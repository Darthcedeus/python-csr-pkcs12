"""
@author: Humza Ahmad
Generate CSR for SMIME certifactes and convert signed certificate into PKCS12 package
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes

from flask import Flask, request, jsonify, Response, render_template
import zipstream

app = Flask(__name__)

@app.get('/')
def index():
    return render_template('index.html')

@app.get("/makeCSR")
def makeCSR():
    email = request.args.get('email')
    passphrase = request.args.get('passphrase')
    
    if email is None or email == "" or passphrase is None or passphrase == "":
        #return(jsonify({"error":"missing input args \'email\' or \'passphrase'"}))
        return render_template('make_csr.html')

    # Generate key
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )

    encrypted_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(str.encode(passphrase)),
        )

    # Generate CSR for email certificates
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])).add_extension(
        x509.KeyUsage(digital_signature=True, 
                    key_encipherment=True, 
                    content_commitment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False),
        critical=True          
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                            ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        critical=True
    ).sign(key, hashes.SHA256())

    csr_data = csr.public_bytes(serialization.Encoding.PEM)

    zip = zipstream.ZipFile()
    zip.write_iter(arcname='csr.pem', iterable=iter([csr_data]))
    zip.write_iter(arcname='key.pem', iterable=iter([encrypted_key]))

    return Response(zip , mimetype="application/zip")

@app.post("/packagePKCS12")
def pacakgePKCS12():
    return("coming soon")

