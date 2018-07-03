
import tempfile
from OpenSSL import crypto
import suds
from suds import cache # Gives issue if not imported separately
from suds import client # Gives issue if not imported separately
import requests
import suds_requests


pfx_path = "/home/yogesh/virtual/test/efatura/credentials/TesteWebservices.pfx"
pfx = open(pfx_path, 'rb').read()
password = "TESTEwebservice"
base_url = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
def get_authenticated_client(base_url, cert, key):
    cache_location = '/tmp/suds'
    cache = suds.cache.DocumentCache(location=cache_location)

    session = requests.Session()
    session.cert = (cert, key)
    return suds.client.Client(
        base_url,
        cache=cache,
        transport=suds_requests.RequestsTransport(session)
    )

def save_cert_key(cert, key):
    cert_temp = tempfile.mkstemp()[1]
    key_temp = tempfile.mkstemp()[1]

    arq_temp = open(cert_temp, 'w')
    arq_temp.write(cert)
    arq_temp.close()

    arq_temp = open(key_temp, 'w')
    arq_temp.write(key)
    arq_temp.close()
    print (cert_temp, key_temp)
    return cert_temp, key_temp

#### Extract certificate and private key from PFX
p12 = crypto.load_pkcs12(open(pfx_path, 'rb').read(), password)

# PEM formatted private key
key = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                         p12.get_privatekey())
# PEM formatted certificate
cert = crypto.dump_certificate(crypto.FILETYPE_PEM,
                           p12.get_certificate())
print (cert, key)


cert, key = save_cert_key(cert, key)

#### Get authenticated client

client = get_authenticated_client(base_url, cert, key)

