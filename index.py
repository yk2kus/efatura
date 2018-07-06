import uuid
import hashlib
from base64 import b64encode
import os
from OpenSSL import crypto
from Crypto.PublicKey import RSA

SoapAction = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas/"
Action = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas"
cert_path = "/home/yogesh/virtualenv/test/efatura/credentials/ChaveCifraPublicaAT2020.cer"

def extract_public_key(cert_path):
	## get public key with openssl
	## openssl x509 -pubkey -noout -in ChaveCifraPublicaAT2020.cer >public_key.pem
	f = open(cert_path, 'rt')
	crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
	pubKeyObject = crtObj.get_pubkey()
	pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM,pubKeyObject)
	print pubKeyString

def encrypt_text_with_public_key(pubKeyString, text):
	public_key = RSA.importKey(pubKeyString)
	encrypted_text = public_key.encrypt(text, 32)
	return base64_encode(encrypted_text)

def base64_encode(string):
	return b64encode(string)

def gen_sim_key():
	return hashlib.sha256(uuid.uuid4().hex[:16]).hexdigest()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def base64_encode_encrypt_aes_ecb_pkcs5pad(data, sim_key):
    iv = Random.new().read(AES.block_size);
    cipher = AES.new( sim_key, AES.MODE_CBC, iv )
    return base64_encode(( iv + cipher.encrypt( raw ) ).encode("hex"))

def base64_encode_rsa_public_encrypt(smkey, publickey) #certificado 'ChaveCifraPublicaAT2020.cer'
	return base64_encode(bytes(os.urandom(128)))



	
	




<?php
	header('Content-Type: text/html; charset=utf-8');
	
        $SoapAction = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas/";
        $Action = "https://servicos.portaldasfinancas.gov.pt:700/fews/faturas";
		
		
		//phpinfo(); //Para ver informacao do servidor
		
		/*
		***************************************************************************************
		* Modulos PHP a instalar/activar: 
		*				CURL (com SSL Version: OpenSSL/1.0.1 )
		*				OPENSSL 
		***************************************************************************************
		*
		*
		*	Extrair TestesWebServices.pfx para .pem (Chave + Certificado)
		*
		*	- Extrair a chave privada para PEM  ( Password: TESTEwebservice )
		*
		*	Código :
		*		openssl pkcs12 -in TestesWebServices.pfx -nocerts -out pfxKey.pem
		*
		*
		*
		*	-Extrair o certificado
		*
		* Código :
		* 		openssl pkcs12 -in TestesWebServices.pfx -clcerts -nokeys -out pfxcert.pem
		*
		***************************************************************************************
		*/
		$cert_pem = 'pfxcert.pem';
        $key_pem  = 'pfxKey.pem';
		
		$pass_cert = 'TESTEwebservice';
		
        $curl = curl_init(trim($Action));   
        
        $xxxml = gerar_xml(); //Gera o XML (ver funcao mais abaixo)
        
        curl_setopt($curl, CURLOPT_FRESH_CONNECT, TRUE);
        curl_setopt($curl, CURLOPT_HTTPHEADER,array(
            'Content-Type:text/xml;Charset=UTF-8',
            'Accept: text/xml',
            'Cache-Control: no-cache',
            'SoapAction='.$SoapAction
        ));
        curl_setopt($curl, CURLOPT_URL, trim($Action));
        curl_setopt($curl, CURLOPT_SSLVERSION, 3);
        curl_setopt($curl, CURLOPT_VERBOSE, TRUE); // para ver o que se passa...
        curl_setopt($curl, CURLOPT_AUTOREFERER, TRUE);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $xxxml);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($curl, CURLOPT_SSLCERT, $cert_pem); // o certificado em formato PEM (.pem)
        curl_setopt($curl, CURLOPT_SSLCERTTYPE, 'PEM');
        curl_setopt($curl, CURLOPT_SSLCERTPASSWD, $pass_cert);
        curl_setopt($curl, CURLOPT_SSLKEY, $key_pem);
        curl_setopt($curl, CURLOPT_SSLKEYPASSWD, $pass_cert);
        curl_setopt($curl, CURLOPT_SSLKEYTYPE, 'PEM');
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);  
           
        $hora_data = date('Y-m-d H:i:s');

        $response = curl_exec($curl);   
        $info = curl_getinfo($curl);
       
            
		preg_match_all("#<ReturnCode>([^<]+)</ReturnCode>#", $response, $r_code); 
		preg_match_all("#<ReturnMessage>([^<]+)</ReturnMessage>#", $response, $r_message); 
		$rr_code = implode("\n", $r_code[1]);
		$rr_message = implode("\n", $r_message[1]);
		
		if($rr_code == 0) {
				
			preg_match_all("#<InvoiceNo>([^<]+)</InvoiceNo>#", $response, $r_doc_number); 
			$rr_doc_number = implode("\n", $r_doc_number[1]);
			
			preg_match_all("#<ATDocCodeID>([^<]+)</ATDocCodeID>#", $response, $r_ATDocCode);
			$rr_ATDocCode = implode("\n", $r_ATDocCode[1]);
			
			echo '<font color=green><font size=3px>['.$hora_data.']</font><b> Documento enviado com successo!</b></font><br> <b>Documento: </b>'. $rr_doc_number .'<br> <b>Codigo AT:</b> '.$rr_ATDocCode;
			
		}
		else {
			echo '<font color=red><b>Ocorreu um erro!!</b></font><br>Codigo: ' . $rr_code . ' - ' . $rr_message; 
		}
		
        curl_close($curl); 
             
    function gerar_xml(){

        $certificado = 'ChaveCifraPublicaAT2020.cer';
        $username = "514223502/1";
		$password = "u1_webservice";	
		
        $TaxRegistrationNumber = '514223502';
        
        $InvoiceNo = 'FT 2018/0004';
        $InvoiceDate = '2018-07-05';
        $InvoiceType = 'FT';
        $InvoiceStatus = 'N';
 
        $CustomerTaxID = '999999990';

 
        $data = array();
        $data['key'] = $smkey = gen_sim_key();
        $data['password'] = $passw = base64_encode_encrypt_aes_ecb_pkcs5pad ( $password, $smkey );
        $data['nonce'] = $nonce = base64_encode_rsa_public_encrypt ( $smkey, $certificado );
        $data['created'] =  $created = base64_encode_encrypt_aes_ecb_pkcs5pad ( gmdate ( 'Y-m-d\TH:i:s\.00\Z' ), $smkey );

        $link = 'http://servicos.portaldasfinancas.gov.pt/faturas/';
        $link_soap ='http://info.portaldasfinancas.gov.pt/NR/rdonlyres/02357996-29FC-4F11-9F1D-6EA2B9210D60/0/factemiws.wsdl';

        $xml = '<?xml version="1.0" encoding="utf-8" standalone="no"?>
        <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
            <S:Header>
                <wss:Security xmlns:wss="http://schemas.xmlsoap.org/ws/2002/12/secext">
                    <wss:UsernameToken>
                        <wss:Username>'.$username.'</wss:Username>
                        <wss:Password>'.$passw.'</wss:Password>
                        <wss:Nonce>'.$nonce.'</wss:Nonce>
                        <wss:Created>'.$created.'</wss:Created>
                    </wss:UsernameToken>
                </wss:Security>
            </S:Header>
            <S:Body>
                <ns2:RegisterInvoiceElem xmlns:ns2="'.$link.'">
                    <TaxRegistrationNumber>'.$TaxRegistrationNumber.'</TaxRegistrationNumber>
                    <ns2:InvoiceNo>'.$DocumentNumber.'</DocumentNumber>
                    <ns2:InvoiceDate>'.$MovementStatus.'</MovementStatus>
                    <ns2:InvoiceType>'.$MovementDate.'</MovementDate>
                    <ns2:InvoiceStatus>'.$MovementType.'</MovementType>
                    <CustomerTaxID>'.$CustomerTaxID.'</CustomerTaxID>
                    <Line>
                        <ns2:DebitAmount>100</ns2:DebitAmount>
                        <ns2:Tax><ns2:TaxType>IVA</ns2:TaxType>
                        <ns2:TaxCountryRegion>PT</ns2:TaxCountryRegion>
                        <ns2:TaxPercentage>23</ns2:TaxPercentage>
                        </ns2:Tax>
                    </Line>  
                    <DocumentTotals>
                        <ns2:TaxPayable>23</ns2:TaxPayable>
                        <ns2:NetTotal>100</ns2:NetTotal>
                        <ns2:GrossTotal>123</ns2:GrossTotal>
                    </DocumentTotals>           
                </ns2:envioDocumentoTransporteRequestElem>
            </S:Body>
        </S:Envelope>';
		
        return $xml;
    }
	
	
		function pkcs5_pad($text, $blocksize)
	{
		$pad = $blocksize - (strlen($text) % $blocksize);
		return $text . str_repeat(chr($pad), $pad);
	}
	function base64_encode_rsa_public_encrypt($data, $pbkey) {
		openssl_public_encrypt ( $data, $crypttext, openssl_pkey_get_public ( file_get_contents ( $pbkey ) ) );
		return base64_encode ( $crypttext );
	}

	function base64_encode_encrypt_aes_ecb_pkcs5pad($data, $sim_key) {
		return trim ( base64_encode ( openssl_encrypt ( pkcs5_pad ( $data, mcrypt_get_block_size ( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB ) ), MCRYPT_RIJNDAEL_128, $sim_key, MCRYPT_MODE_ECB, mcrypt_create_iv ( mcrypt_get_iv_size ( MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB ), MCRYPT_RAND ) ) ) );
	}
	
	
?>substr
