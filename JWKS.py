#CSCE 3550 - Alex Trumble

#Import basic flask libraries
from flask import Flask
from flask import jsonify
from flask import request

import rsa
from datetime import datetime
from datetime import timedelta

#Import JWT extension of Flask Library
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

#Import from Cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Import Requests
import requests

app = Flask(__name__)
#Setting up Extended Flask
app.config["JWT_PUBLIC_KEY"] = "mainKey" #Public Key
app.config["JWT_SECRET_KEY"] = "testKey" #Secret Key
jwt = JWTManager(app)

#Make RSA key pair
def generate_rsa_key():
    #Parameters of Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    #Generate public key
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

private_key, public_key = generate_rsa_key()
#Set expiration time of keys
expiry_timestamp = datetime.utcnow() + timedelta(days=30)
expiry = expiry_timestamp.timestamp()

# Store Key and Expiry
keys = {
    "default": {"key": private_key, "expiry": expiry}
}

@app.route("/.well-known/jwks.json", methods=["GET"])
def getJWKS() -> tuple[str, int]:
    #Empties out invalid keys
    keys_to_return = {k: v for k, v in keys.items() if v["expiry"] > datetime.utcnow().timestamp()}

    #Converts keys into object for output
    jwks_keys = [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig"} for kid, key in keys_to_return.items()]
    #jwks_keys = [{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": key.decode('utf-8').split("\n")[1]} for kid, key in keys_to_return.items()]
    ####WIP function, does not properly reflect data

    #Returns all keys
    return jwks_keys

@app.route("/auth", methods=["POST"])
def createJWT() -> tuple[str, int]:
    #Checks if expired, makes expired key if true
    if request.args.get('expired') == 'true':
        key = keys["default"]["key"]
        expiry = keys["default"]["expiry"]
        access_token = create_access_token(identity="userABC")

    #Otherwise, creates standard web key
    else:
        key = private_key
        expiry = expiry_timestamp.timestamp()
        access_token = create_access_token(identity="userABC", fresh = True)

    #Returns Web Token
    return access_token
    #return jsonify(access_token=access_token)

if __name__ == "__main__":
    app.run(port=8080)
