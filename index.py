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

SoapAction = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
Action = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
cert_path = "/home/yogesh/virtual/test/efatura/credentials/ChaveCifraPublicaAT2020.cer"
pfx_path = "/home/yogesh/virtual/test/efatura/credentials/TesteWebservices.pfx"
base_url = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"

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
    session.auth = ('514223502/1', 'u1_webservice')
    session.cert = (cert, key)
    session.headers.update({'x-test': 'true'})
    soapHeader = get_soap_header()
    # print "HEADER===============",soapHeader
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('suds.client').setLevel(logging.DEBUG)
    logging.getLogger('suds.transport').setLevel(logging.DEBUG)
    logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
    logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)
    # t = HttpAuthenticated('514223502/1', 'u1_webservice')
    print(soapHeader)
    import base64
    base64string = base64.encodestring('%s:%s' % ('514223502/1', 'OcEtBl1wNk08Pl+0Pg2RiQ==')).replace('\n', '')
    authenticationHeader = {
        "SOAPAction": SoapAction,
        "Authorization": "Basic %s" % base64string
    }
    return Client(
        base_url,
        # cache=cache,
        headers=authenticationHeader,
        soapheaders = soapHeader,
        transport=suds_requests.RequestsTransport(session)
    )

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
username = "514223502/1";
password = "u1_webservice";
#date = encrypt_text_with_public_key(get_createdate())
#smkey = gen_sim_key
#passw = encrypt_text_with_public_key(password)

smkey = generate_secret_key_for_AES_cipher()
date = encrypt_message(get_createdate(), smkey, padding_character)
passw = encrypt_message(password, smkey, padding_character)
nonce = encrypt_text_with_public_key(smkey)
print "user........", username
print "date.........", date
print "password..........",passw
print "nonce.............", nonce

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
get_soap_header(username, passw, nonce, date)
get_authenticated_client(base_url, cert, key)