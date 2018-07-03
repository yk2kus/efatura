
import tempfile
from OpenSSL import crypto

pfx_path = "/home/yogesh/virtual/test/efatura/credentials/TesteWebservices.pfx"
pfx = open(pfx_path, 'rb').read()
password = "TESTEwebservice"
p12 = crypto.load_pkcs12(open(pfx_path, 'rb').read(), password)

# PEM formatted private key
key = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                         p12.get_privatekey())
# PEM formatted certificate
cert = crypto.dump_certificate(crypto.FILETYPE_PEM,
                           p12.get_certificate())
print (cert, key)


