# /usr/bin/env

import uuid
import logging
import tempfile
import hashlib
from base64 import b64encode, b64decode
import os
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from datetime import datetime
import pytz
from Crypto.Cipher import AES
from suds.client import Client
from suds.sax.attribute import Attribute
from suds.transport.https import HttpAuthenticated
import suds
import requests
import suds_requests
from suds.sax.element import Element
from zeep import CachingClient as Client
from zeep.wsse.signature import Signature
from zeep.transports import Transport
from requests import Session, Request


############## Variables ###################
SoapAction = "http://servicos.portaldasfinancas.gov.pt/faturas/RegisterInvoice"
Action = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
cert_path = "/home/yogesh/virtual/test/efatura/credentials/ChaveCifraPublicaAT2020.cer"
pfx_path = "/home/yogesh/virtual/test/efatura/credentials/TesteWebservices.pfx"
base_url = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
username = "514223502/1";
password = "u1_webservice";



#### Symmetric key Encryption ############

padding_character = "{"

def generate_secret_key_for_AES_cipher():
	# AES key length must be either 16, 24, or 32 bytes long
	AES_key_length = 16 # use larger value in production
	# generate a random secret key with the decided key length
	# this secret key will be used to create AES cipher for encryption/decryption
	secret_key = os.urandom(AES_key_length)
	# encode this secret key for storing safely in database
	encoded_secret_key = b64encode(secret_key)
	return encoded_secret_key


def encrypt_message(private_msg, encoded_secret_key, padding_character):
	# decode the encoded secret key
	secret_key = b64decode(encoded_secret_key)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# pad the private_msg
	# because AES encryption requires the length of the msg to be a multiple of 16
	padded_private_msg = private_msg + (padding_character * ((16-len(private_msg)) % 16))
	# use the cipher to encrypt the padded message
	encrypted_msg = cipher.encrypt(padded_private_msg)
	# encode the encrypted msg for storing safely in the database
	encoded_encrypted_msg = b64encode(encrypted_msg)
	# return encoded encrypted message
	return encoded_encrypted_msg

#########################################

def get_xml(user, password, nonce, date):
	requeststr  = ""
	requeststr = "<S:Envelope xmlns:S=""http://schemas.xmlsoap.org/soap/envelope/"">"
	requeststr += "<S:Header>"
	requeststr += "<wss:Security xmlns:wss=""http://schemas.xmlsoap.org/ws/2002/12/secext"">"
	requeststr += "<wss:UsernameToken>"
	requeststr += "<wss:Username>" +user+  "</wss:Username>"
	requeststr += "<wss:Password>" +password+ " </wss:Password>"
	requeststr += "<wss:Nonce>" +nonce+ "</wss:Nonce>"
	requeststr += "<wss:Created>"+ date+ "</wss:Created>"
	requeststr += "</wss:UsernameToken>"
	requeststr += "</wss:Security>"
	requeststr += "</S:Header>"
	requeststr += "<S:Body>"
	requeststr += "<ns2:RegisterInvoiceElem xmlns:ns2=""http://servicos.portaldasfinancas.gov.pt/faturas/"">"
	requeststr += "<TaxRegistrationNumber>500555333/0001</TaxRegistrationNumber>"
	requeststr += "<ns2:InvoiceNo>FT/1</ns2:InvoiceNo>"
	requeststr += "<ns2:InvoiceDate>2012-05-05</ns2:InvoiceDate>"
	requeststr += "<ns2:InvoiceType>FT</ns2:InvoiceType>"
	requeststr += "<CustomerTaxID>299999998</CustomerTaxID>"
	requeststr += "<Line>"
	requeststr += "<ns2:DebitAmount>100</ns2:DebitAmount>"
	requeststr += "<ns2:Tax>"
	requeststr += "<ns2:TaxType>IVA</ns2:TaxType>"
	requeststr += "<ns2:TaxCountryRegion>PT</ns2:TaxCountryRegion>"
	requeststr += "<ns2:TaxPercentage>23</ns2:TaxPercentage>"
	requeststr += "</ns2:Tax>"
	requeststr += "</Line>"
	requeststr += "<DocumentTotals>"
	requeststr += "<ns2:TaxPayable>23</ns2:TaxPayable>"
	requeststr += "<ns2:NetTotal>100</ns2:NetTotal>"
	requeststr += "<ns2:GrossTotal>123</ns2:GrossTotal>"
	requeststr += "</DocumentTotals>"
	requeststr += "</ns2:RegisterInvoiceElem>"
	requeststr += "</S:Body>"
	requeststr += "</S:Envelope>"

	return requeststr

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

def get_authenticated_client(base_url, cert, key):
    cache_location = '/tmp/suds'
    cache = suds.cache.DocumentCache(location=cache_location)

    session = requests.Session()
    session.verify = cert
    #session.auth = ('514223502/1', 'u1_webservice')
    #session.auth = ('514223502/1', 'u1_webservice')
    session.headers.update({'SOAPAction': 'http://servicos.portaldasfinancas.gov.pt/faturas/RegisterInvoice'})
	### xml is returned from get_xml()
    xml = "<S:Envelope xmlns:S=http://schemas.xmlsoap.org/soap/envelope/><S:Header><wss:Security xmlns:wss=http://schemas.xmlsoap.org/ws/2002/12/secext><wss:UsernameToken><wss:Username>514223502/1</wss:Username><wss:Password>bN4xoloIs83a2X77tPdg+g== </wss:Password><wss:Nonce>kO0TXhOgQ2rbl5PlkKqOA0Wk4YEPIfW9ncuoBHI3C0YUQS236NYYBCgd2+KzE1WKunI3vveBRLe8DjRLHiQyFeP8pgekwcqayXzA/Ujfv1UmA4gmuTtyQ9flJUELAT7zHfmikAP+hS5QxgHTXhNei247N+LkaBwkN+ABUJ5IhasNl3EwLp1ePkxV72lktMsySvRIf0GoeaG6g+hWPT5PleUVTJH1TnXhDbOzt9BTy6YxlqQ7IGolVrUimS7MtS/46Qq09k2ShrNIx/CUSnzNsNS8M4Zlj1m0JlP3oCnbmIVMLZagZfV95ZRlnagdyDsqPxrAV/09iRqFaBCpGWcICg==</wss:Nonce><wss:Created>OdLJhmrh9jwFG/2Mw+Ac8Bjk6si4gydK5Td/BLPt+ZA=</wss:Created></wss:UsernameToken></wss:Security></S:Header><S:Body><ns2:RegisterInvoiceElem xmlns:ns2=http://servicos.portaldasfinancas.gov.pt/faturas/><TaxRegistrationNumber>500555333/0001</TaxRegistrationNumber><ns2:InvoiceNo>FT/1</ns2:InvoiceNo><ns2:InvoiceDate>2012-05-05</ns2:InvoiceDate><ns2:InvoiceType>FT</ns2:InvoiceType><CustomerTaxID>299999998</CustomerTaxID><Line><ns2:DebitAmount>100</ns2:DebitAmount><ns2:Tax><ns2:TaxType>IVA</ns2:TaxType><ns2:TaxCountryRegion>PT</ns2:TaxCountryRegion><ns2:TaxPercentage>23</ns2:TaxPercentage></ns2:Tax></Line><DocumentTotals><ns2:TaxPayable>23</ns2:TaxPayable><ns2:NetTotal>100</ns2:NetTotal><ns2:GrossTotal>123</ns2:GrossTotal></DocumentTotals></ns2:RegisterInvoiceElem></S:Body></S:Envelope>"

    # print "HEADER===============",soapHeader
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('suds.client').setLevel(logging.DEBUG)
    logging.getLogger('suds.transport').setLevel(logging.DEBUG)
    logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
    logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)
    # t = HttpAuthenticated('514223502/1', 'u1_webservice')
    import base64
    base64string = base64.encodestring('%s:%s' % ('514223502/1', 'u1_webservice')).replace('\n', '')
    authenticationHeader = {
        "SOAPAction": SoapAction,
       # "Authorization": "Basic %s" % base64string
    }

    transport = Transport(session=session)
    c = Client(base_url, transport=transport)
    # return Client(
    #     base_url,
    #     # cache=cache,
    #     headers=authenticationHeader,
    #     soapheaders = soapHeader,
    #     transport=suds_requests.RequestsTransport(session)
    # )

def get_createdate():
    utc = pytz.utc
    tz_lisbon = pytz.timezone('Europe/Lisbon')
    utc_time = datetime.now()
    lisbon_time = tz_lisbon.localize(utc_time)
    # format in php.index "%Y-%m-%dT%H:%M:%S.%zZ" ==>> '2018-07-06T08:57:57.+0100Z'
    # PHP returns ==>>2018-07-06T08:48:53.00Z
    # PDF says ==> e.g.: 2013-01-01T19:20:30.45Z
    lisbon_time = datetime.strftime(lisbon_time, "%Y-%m-%dT%H:%M:%S%zZ")
    return lisbon_time



def extract_public_key_from_crt(cert_path=cert_path):
    ## get public key with openssl
    ## openssl x509 -pubkey -noout -in ChaveCifraPublicaAT2020.cer >public_key.pem
    f = open(cert_path, 'rt')
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    return pubKeyString



def encrypt_text_with_public_key(text):
    """ Encrypt Text with public key
        :return base64 string of crypered text with public key
    """
    pubKeyString = extract_public_key_from_crt(cert_path)
    public_key = RSA.importKey(pubKeyString)
    encrypted_text = public_key.encrypt(text, 32)[0]  # extracting string because it is a tuple of length 1
    return base64_encode(encrypted_text)


def base64_encode(string):
    return b64encode(string)


def gen_sim_key():
    return hashlib.sha256(uuid.uuid4().hex[:16]).hexdigest()


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


def base64_encode_encrypt_aes_ecb_pkcs5pad(data, sim_key):
    iv = Random.new().read(AES.block_size);
    cipher = AES.new(sim_key, AES.MODE_CBC, iv)
    return base64_encode((iv + cipher.encrypt(raw)).encode("hex"))


def base64_encode_rsa_public_encrypt(smkey, publickey):  # certificado 'ChaveCifraPublicaAT2020.cer'
    return base64_encode(bytes(os.urandom(128)))


#### Extract certificate and private key from PFX
cert_pass = "TESTEwebservice"
p12 = crypto.load_pkcs12(open(pfx_path, 'rb').read(), cert_pass)

# PEM formatted private key
key = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                         p12.get_privatekey())
# PEM formatted certificate
cert = crypto.dump_certificate(crypto.FILETYPE_PEM,
                           p12.get_certificate())
## get a temp location for cert and keys
cert, key = save_cert_key(cert, key)
# print (cert, key)

# print cert, key

#date = encrypt_text_with_public_key(get_createdate())
#smkey = gen_sim_key
#passw = encrypt_text_with_public_key(password)

smkey = generate_secret_key_for_AES_cipher()
date = encrypt_message(get_createdate(), smkey, padding_character)
passw = encrypt_message(password, smkey, padding_character)
nonce = encrypt_text_with_public_key(smkey)

#### create xml with suds
def get_soap_header(user= username, passw = passw,nonce= nonce, date=date):
    WssSecurity = Element('wss:Security').setText('xmlns:wss="http://schemas.xmlsoap.org/ws/2002/12/secext"')
    soapheader = Element('S:Header')  # create the parent element
    WssUsernameToken = Element('wss:UsernameToken')
    WssUsername = Element('wss:Username').setText(user)
    WssPassword = Element('wss:Password').setText(passw)
    WssNonce = Element('wss:Nonce').setText(nonce)
    WssCreated = Element('wss:Created').setText(date)
    WssSecurity.children = [WssUsernameToken]
    soapheader.children = [WssSecurity]
    WssUsernameToken.children = [WssUsername, WssPassword, WssNonce, WssCreated]

    return soapheader
#get_soap_header(username, passw, nonce, date)
xml = get_xml(username, passw, nonce, date)
print xml
get_authenticated_client(base_url, cert, key)
