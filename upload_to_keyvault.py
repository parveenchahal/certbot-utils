from datetime import timedelta
import signal, os, re, optparse

from common.exceptions import KeyvaultSecretNotFoundError
from common import AADToken
from common.key_vault import KeyVaultSecret
from common import Scheduler

class UploadCertIfChangedHandler(object):
    def __init__(self, keyvault_secret: KeyVaultSecret, cert_file_path: str) -> None:
        self._keyvault_secret = keyvault_secret
        self._cert_file_path = cert_file_path

    def handle(self):
        try:
            k = self._keyvault_secret
            value = None
            try:
                value = k.get()
            except KeyvaultSecretNotFoundError:
                pass
            file_data = None
            with open(self._cert_file_path, 'r') as f:
                file_data = f.read()
            if value == file_data:
                print(f'Skipping secret upload for {self._cert_file_path}. Same version already exists.')
                return
            k.set(file_data)
            print(f'Updated secret for {self._cert_file_path}.')
        except Exception as e:
            print(f'Keyvault operation failed for {self._cert_file_path}: {e}')

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
    main()