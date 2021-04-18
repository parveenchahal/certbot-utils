import uuid
from OpenSSL.crypto import load_pkcs12
from datetime import datetime, timedelta
import signal, os, re, optparse, binascii
from uuid import uuid5

from common.exceptions import KeyvaultSecretNotFoundError
from common import AADToken
from common.key_vault import KeyVaultSecret
from common import Scheduler
from common.utils import decode_base64, encode_base64, string_to_bytes, bytes_to_string
import logging

class UploadCertIfChangedHandler(object):
    def __init__(self, keyvault_secret: KeyVaultSecret, cert_file_path: str) -> None:
        self._keyvault_secret = keyvault_secret
        self._cert_file_path = cert_file_path

    def handle(self):
        try:
            if(not os.path.exists('.tmp')):
                os.mkdir('.tmp')
            k = self._keyvault_secret
            key_vault_cert_digest = None
            key_vault_cert_data = None
            try:
                key_vault_cert_data = k.get()
            except (KeyvaultSecretNotFoundError):
                pass
            try:
                value = string_to_bytes(decode_base64(key_vault_cert_data, encoding='ISO-8859-1'), encoding='ISO-8859-1')
                x = uuid5(uuid.NAMESPACE_DNS, str(datetime.utcnow().timestamp()))
                key_vault_file_path = os.path.join('.tmp', str(x))
                with open(key_vault_file_path, 'wb') as f:
                    f.write(value)
                with open(key_vault_file_path, 'rb') as f:
                    pfx = f.read()
                    p12 = load_pkcs12(pfx)
                    key_vault_cert_digest = p12.get_certificate().digest('sha1')
                os.remove(key_vault_file_path)
            except binascii.Error as e:
                logging.exception(f'Base64 decoding failed for {self._cert_file_path}', exc_info=e)
            local_file_data = None
            local_file_digest = ""
            with open(self._cert_file_path, 'rb') as f:
                local_file_data = f.read()
            p12 = load_pkcs12(local_file_data)
            local_file_digest = p12.get_certificate().digest('sha1')
            if key_vault_cert_digest == local_file_digest:
                logging.info(f'Skipping secret upload for {self._cert_file_path}. Same version already exists.')
                return
            k.set(bytes_to_string(encode_base64(local_file_data, encoding='ISO-8859-1')))
            logging.info(f'Updated secret for {self._cert_file_path}.')
        except Exception as e:
            logging.exception(f'Keyvault operation failed for {self._cert_file_path}', exc_info=e)

def main():
    parser = optparse.OptionParser()
    parser.add_option("-k", "--keyvaultname", default='', help="Keyvault name")
    parser.add_option("-t", "--tenantid", default='', help="Tenant id")
    parser.add_option("-s", "--secret", default='', help="secret")
    parser.add_option("-c", "--clientid", default='', help="secret")
    parser.add_option("-d", "--folder", default='', help="Certs folder")
    parser.add_option("-f", "--frequency", default='', help="Frequency in seconds")
    options = parser.parse_args()[0]
    keyvault_name = options.keyvaultname
    tenant_id = options.tenantid
    secret = options.secret
    client_id = options.clientid
    cert_folder = options.folder
    frequency = int(options.frequency)
    cert_file_names = os.listdir(cert_folder)
    cert_files_path = [os.path.join(cert_folder, f) for f in cert_file_names]
    aad_token = AADToken(client_id, secret, 'https://vault.azure.net', tenant_id)

    handlers_list = []

    for i in range(len(cert_file_names)):
        name = re.sub('[^a-zA-Z0-9-]', '-', cert_file_names[i])
        path = cert_files_path[i]
        k = KeyVaultSecret(keyvault_name, name, aad_token, '7.1')
        h = UploadCertIfChangedHandler(k, path)
        handlers_list.append(h)

    schedulers_list = []
    for h in handlers_list:
        s = Scheduler(callback=h.handle, frequency=timedelta(seconds=frequency))
        schedulers_list.append(s)

    for s in schedulers_list:
        s.start()

    def signal_handler(signum, frame):
        for s in schedulers_list:
            s.stop()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    for s in schedulers_list:
        s.join()
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()