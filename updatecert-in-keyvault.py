from os.path import join
from base64 import b64encode
from requests import get as _http_get, put as _http_put
import signal, os, re, json
import pathlib
import optparse
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver as Observer

keyvault_name = None
tenant_id = None
client_id = None
secret = None

class NotAbleToUpdateKeyVault(Exception): pass

def update_keyvault(name, data):
    res = _http_get(f'https://authonline.net/aadtoken/{tenant_id}?client_id={client_id}&secret={secret}&resource=https://vault.azure.net')
    access_token = json.loads(res.text)["access_token"]
    res = _http_put(f'https://{keyvault_name}.vault.azure.net/secrets/{name}?api-version=7.1', json={'value': data}, headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'})
    if not res.ok:
        raise NotAbleToUpdateKeyVault()


class CertUpdateEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            for _ in range(3):
                try:
                    parent = os.path.dirname(event.src_path)
                    parent_name = pathlib.Path(parent).name
                    parent_name = re.sub('[^a-zA-Z0-9-]', '-', parent_name)
                    cert_path = os.path.join(parent, 'fullchain.pem')
                    key_path = os.path.join(parent, 'privkey.pem')
                    pfx_path = os.path.join(os.getcwd(), f'{parent_name}.pfx')
                    os.system(f'openssl pkcs12 -export -out {pfx_path} -inkey {key_path} -in {cert_path} -passout pass:')
                    data = None
                    with open(pfx_path, 'r') as f:
                        data = f.read()
                        data = b64encode(data.encode('UTF-8', errors='strict'))
                    update_keyvault(parent_name, data)
                    os.remove(pfx_path)
                except Exception as e:
                    print(e)
                    continue
                break


def main():
    parser = optparse.OptionParser()
    parser.add_option("-k", "--keyvaultname", default='', help="Keyvault name")
    parser.add_option("-t", "--tenantid", default='', help="Tenant id")
    parser.add_option("-s", "--secret", default='', help="secret")
    parser.add_option("-c", "--clientid", default='', help="secret")
    parser.add_option("-l", "--certs", default='', help="comma(,) separated certs directory list")
    options = parser.parse_args()[0]
    global keyvault_name, tenant_id, secret, client_id
    keyvault_name = options.keyvaultname
    tenant_id = options.tenantid
    secret = options.secret
    client_id = options.clientid
    cert_list = options.certs.split(',')
    event_handler = CertUpdateEventHandler()
    observer = Observer()
    for cert in cert_list:
        observer.schedule(event_handler, cert)

    def signal_handler(signum, frame):
        observer.stop()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    observer.start()
    observer.join()

if __name__ == '__main__':
    main()