
import tempfile
from OpenSSL import crypto
import suds
from suds import cache # Gives issue if not imported separately
from suds import client # Gives issue if not imported separately
import requests
import suds_requests


pfx_path = "/home/yogesh/virtual/test/efatura/credentials/TesteWebservices.pfx"
cer_path = "/home/yogesh/virtualenv/test/efatura/credentials/ChaveCifraPublicaAT2020.cer"
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
pfx = open(pfx_path, 'rb').read()
password = "TESTEwebservice"
base_url = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"

username = "514223502/1"
user_pass = "u1_webservice"



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




# import logging
# logging.basicConfig(level=logging.INFO)
# from suds.client import Client
# url = 'wsdl url'
# client = Client(url)
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
# from suds.sax.element import Element
# #create an xml element at our namespace
# n = Element('credentials', ns=["cred","namespace.url"])
# import suds.sax.attribute as attribute
# #the username, customerid and pass are atributes so we create them and append them to the node.
# un = attribute.Attribute("username","your username")
# up = attribute.Attribute("password","your password")
# cid = attribute.Attribute("customerID",1111)
# n.append(un).append(up).append(cid)
# client.set_options(soapheaders=n)



# <xs:schema attributeFormDefault="unqualified" elementFormDefault="unqualified" targetNamespace="http://namespace.com">
#   <xs:complexType name="Credentials"><xs:sequence/>
#   <xs:attribute name="username" type="xs:string" use="required"/>
#   <xs:attribute name="password" type="xs:string" use="required"/>
#   <xs:attribute name="customerID" type="xs:int"/>
# </xs:complexType>
# <xs:element name="credentials" nillable="true" type="Credentials"/></xs:schema>


<S:Header>
<wss:Security xmlns:wss="http://schemas.xmlsoap.org/ws/2002/12/secext">
<wss:UsernameToken>
<wss:Username>599999993/37</wss:Username>
<wss:Password>ikCyRV+SWfvZ5c6Q0bhrBQ==</wss:Password>
<wss:Nonce>
fkAHne7cqurxpImCfBC8EEc2vskyUyNofWi0ptIijYg4gYCxir++unzfPVPpusloEtmLkcZjf+E6
T9/76tsCqdupUkxOhWtkRH5IrNwmfEW1ZGFQgYTF21iyKBRzMdsJMhhHrofYYV/YhSPdT4dlgG0t
k9Z736jFuw061mP2TNqHcR/mQR0yW/AEOC6RPumqO8OAfc9/b4KFBSfbpY9HRzbD8bKiTo20n0Pt
amZevCSVHht4yt/Xwgd+KV70WFzyesGVMOgFRTWZyXyXBVaBrkJS8b6PojxADLcpWRnw5+YeOs3c
PU2o1H/YgAam1QuEHioCT2YTdRt+9p6ARNElFg==
</wss:Nonce>
<wss:Created>>YEWoIoqIY5DOD11SeXz+0i4b/AJg1/RgNcOHOYpSxGk</wss:Created>
</wss:UsernameToken>
</wss:Security>
</S:Header>

