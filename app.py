#!/usr/bin/python

from flask import Flask
from flask import request,Response,redirect
from flask import render_template, url_for, session
from flask_session import Session
from flask_caching import Cache
from flask.json import jsonify
import json
import logging
import sys, os, tempfile, uuid, time, datetime
import configparser
import argparse
import requests
from random import randint
import msal
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from flask import Flask
app = Flask(__name__) # Flask instance named app
cacheConfig = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300
}
app = Flask(__name__,static_url_path='',static_folder='static',template_folder='static')
app.secret_key = '61U7Q~B0qmpNP8~sWHn7_K1t1V1QPeCRiCtBA'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
app.config.from_mapping(cacheConfig)
cache = Cache(app)

app.config.from_object(app.config)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
log = logging.getLogger() 
log.setLevel(logging.INFO)

config = json.load(open("./config.json"))
app.config.update(
    SECRET_KEY=config["CLIENT_SECRET"],
    AUTHORITY=config["AUTHORITY"],
    ENDPOINT=config["ENDPOINT"],
    SCOPE=config["SCOPE"],
    SESSION_TYPE= config["SESSION_TYPE"]
)


msalCca = msal.ConfidentialClientApplication( config["azClientId"], 
    authority="https://login.microsoftonline.com/" + config["azTenantId"],
    client_credential=config["azClientSecret"],
    )

if config["azCertificateName"] != "":
    with open(config["azCertificatePrivateKeyLocation"], "rb") as file:
        private_key = file.read()
    with open(config["azCertificateLocation"]) as file:
        public_certificate = file.read()
    cert = load_pem_x509_certificate(data=bytes(public_certificate, 'UTF-8'), backend=default_backend())
    thumbprint = (cert.fingerprint(hashes.SHA1()).hex())
    print("Cert based auth using thumbprint: " + thumbprint)    
    msalCca = msal.ConfidentialClientApplication( config["azClientId"], 
       authority="https://login.microsoftonline.com/" + config["azTenantId"],
        client_credential={
            "private_key": private_key,
            "thumbprint": thumbprint,
            "public_certificate": public_certificate
        }
    )    

fI = open("./issuance_request_config.json",)
issuanceConfig = json.load(fI)
fI.close()  

apiKey = str(uuid.uuid4())

issuanceConfig["callback"]["headers"]["api-key"] = apiKey
issuanceConfig["authority"] = config["IssuerAuthority"]
issuanceConfig["issuance"]["manifest"] = config["CredentialManifest"]
if "pin" in issuanceConfig["issuance"] is not None:
    if int(issuanceConfig["issuance"]["pin"]["length"]) == 0:
        del issuanceConfig["issuance"]["pin"]

@app.route("/api/issuer/issuance-request", methods = ['GET'])
def issuanceRequest():
    """ This method is called from the UI to initiate the issuance of the verifiable credential """
    id = str(uuid.uuid4())
    accessToken = ""
    result = msalCca.acquire_token_for_client( scopes="bbb94529-53a3-4be5-a069-7eaf2712b826/.default" )
    if "access_token" in result:
        print( result['access_token'] )
        accessToken = result['access_token']
    else:
        print(result.get("error") + result.get("error_description"))

    payload = issuanceConfig.copy()
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "/api/issuer/issuance-request-callback"
    payload["callback"]["state"] = id
    pinCode = 0
    if "pin" in payload["issuance"] is not None:
        pinCode = ''.join(str(randint(0,9)) for _ in range(int(payload["issuance"]["pin"]["length"])))
        payload["issuance"]["pin"]["value"] = pinCode
    payload["issuance"]["claims"]["given_name"] = "Michael"
    payload["issuance"]["claims"]["family_name"] = "Stokes"
    print( json.dumps(payload) )
    post_headers = { "content-type": "application/json", "Authorization": "Bearer " + accessToken }
    client_api_request_endpoint = "https://beta.did.msidentity.com/v1.0/" + config["azTenantId"] + "/verifiablecredentials/request"
    r = requests.post( client_api_request_endpoint
                    , headers=post_headers, data=json.dumps(payload))
    resp = r.json()
    print(resp)
    resp["id"] = id
    if "pin" in payload["issuance"] is not None:
        resp["pin"] = pinCode
    return Response( json.dumps(resp), status=200, mimetype='application/json')

@app.route("/api/issuer/issuance-request-callback", methods = ['POST'])
def issuanceRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    issuanceResponse = request.json
    print(issuanceResponse)
    if request.headers['api-key'] != apiKey:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
    if issuanceResponse["code"] == "request_retrieved":
        cacheData = {
            "status": issuanceResponse["code"],
            "message": "QR Code is scanned. Waiting for issuance to complete..."
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    if issuanceResponse["code"] == "issuance_successful":
        cacheData = {
            "status": issuanceResponse["code"],
            "message": "Credential successfully issued"
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    if issuanceResponse["code"] == "issuance_error":
        cacheData = {
            "status": issuanceResponse["code"],
            "message": issuanceResponse["error"]["message"]
        }
        cache.set( issuanceResponse["state"], json.dumps(cacheData) )
        return ""
    return ""

@app.route("/api/issuer/issuance-response", methods = ['GET'])
def issuanceRequestStatus():
    """ this function is called from the UI polling for a response from the AAD VC Service.
    when a callback is recieved at the presentationCallback service the session will be updated
     """
    id = request.args.get('id')
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        browserData = {
            'status': cacheData["status"],
            'message': cacheData["message"]
        }
        return Response( json.dumps(browserData), status=200, mimetype='application/json')
    else:
        return ""

fP = open("./presentation_request_config.json",)
presentationConfig = json.load(fP)
fP.close()  

apiKey = str(uuid.uuid4())

presentationConfig["callback"]["headers"]["api-key"] = apiKey
presentationConfig["authority"] = config["VerifierAuthority"]
presentationConfig["presentation"]["requestedCredentials"][0]["acceptedIssuers"][0] = config["IssuerAuthority"]
print( presentationConfig )

@app.route("/api/verifier/presentation-request", methods = ['GET'])
def presentationRequest():
    """ This method is called from the UI to initiate the presentation of the verifiable credential """
    id = str(uuid.uuid4())
    accessToken = ""
    result = msalCca.acquire_token_for_client( scopes="bbb94529-53a3-4be5-a069-7eaf2712b826/.default" )
    if "access_token" in result:
        print( result['access_token'] )
        accessToken = result['access_token']
    else:
        print(result.get("error") + result.get("error_description"))
    payload = presentationConfig.copy()
    payload["callback"]["url"] = str(request.url_root).replace("http://", "https://") + "/api/verifier/presentation-request-callback"
    payload["callback"]["state"] = id
    print( json.dumps(payload) )
    post_headers = { "content-type": "application/json", "Authorization": "Bearer " + accessToken }
    client_api_request_endpoint = "https://beta.did.msidentity.com/v1.0/" + config["azTenantId"] + "/verifiablecredentials/request"
    r = requests.post( client_api_request_endpoint
                    , headers=post_headers, data=json.dumps(payload))
    resp = r.json()
    print(resp)
    resp["id"] = id            
    response = Response( json.dumps(resp), status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response


@app.route("/api/verifier/presentation-request-callback", methods = ['POST'])
def presentationRequestApiCallback():
    """ This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service """
    presentationResponse = request.json
    print(presentationResponse)
    if request.headers['api-key'] != apiKey:
        print("api-key wrong or missing")
        return Response( jsonify({'error':'api-key wrong or missing'}), status=401, mimetype='application/json')
    if presentationResponse["code"] == "request_retrieved":
        cacheData = {
            "status": presentationResponse["code"],
            "message": "QR Code is scanned. Waiting for validation..."
        }
        cache.set( presentationResponse["state"], json.dumps(cacheData) )
        return ""
    if presentationResponse["code"] == "presentation_verified":
        cacheData = {
            "status": presentationResponse["code"],
            "message": "Presentation received",
            "payload": presentationResponse["issuers"],
            "subject": presentationResponse["subject"],
            "firstName": presentationResponse["issuers"][0]["claims"]["firstName"],
            "lastName": presentationResponse["issuers"][0]["claims"]["lastName"],
            "presentationResponse": presentationResponse
        }
        cache.set( presentationResponse["state"], json.dumps(cacheData) )
        return ""
    return ""

@app.route("/api/verifier/presentation-response", methods = ['GET'])
def presentationRequestStatus():
    """ this function is called from the UI polling for a response from the AAD VC Service.
     when a callback is recieved at the presentationCallback service the session will be updated
     this method will respond with the status so the UI can reflect if the QR code was scanned and with the result of the presentation
     """
    id = request.args.get('id')
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        response = Response( json.dumps(cacheData), status=200, mimetype='application/json')
    else:
        response = Response( "", status=200, mimetype='application/json')
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route("/api/verifier/presentation-response-b2c", methods = ['POST'])
def presentationResponseB2C():
    presentationResponse = request.json
    id = presentationResponse["id"]
    print(id)
    data = cache.get(id)
    print(data)
    if data is not None:
        cacheData = json.loads(data)
        if cacheData["status"] == "presentation_verified":
            claims = cacheData["presentationResponse"]["issuers"][0]["claims"]
            claimsExtra = {
               'vcType': presentationConfig["presentation"]["requestedCredentials"][0]["type"],
               'vcIss': cacheData["presentationResponse"]["issuers"][0]["authority"],
               'vcSub': cacheData["presentationResponse"]["subject"],
               'vcKey': cacheData["presentationResponse"]["subject"].replace("did:ion:", "did.ion.").split(":")[0].replace("did.ion.", "did:ion:")
            }
            responseBody = {**claimsExtra, **claims} # merge
            return Response( json.dumps(responseBody), status=200, mimetype='application/json')

    errmsg = {
        'version': '1.0.0', 
        'status': 400,
        'userMessage': 'Verifiable Credentials not presented'
        }
    return Response( json.dumps(errmsg), status=409, mimetype='application/json')


@app.route('/')
def root():
    varvalue="testing"
    return render_template('index.html')
    #return app.send_static_file('index.html')

def index():

    #if not session.get("user"):
    #    return redirect(url_for("login"))
    return render_template('index.html', user=session["user"])

@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())
    auth_url = _build_msal_app().get_authorization_request_url(
        app.config["SCOPE"],  # Technically we can use empty list [] to just sign in,
                           # here we choose to also collect end user consent upfront
        state=session["state"],
        redirect_uri=url_for("authorized", _external=True, _scheme='https'))
    return "<a href='%s'>Login with Microsoft Identity</a>" % auth_url

@app.route("/getAToken")  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args['state'] != session.get("state"):
        return redirect(url_for("login", _scheme='https'))
    cache = _load_cache()
    result = _build_msal_app(cache).acquire_token_by_authorization_code(
        request.args['code'],
        scopes=app.config["SCOPE"],  # Misspelled scope would cause an HTTP 400 error here
        redirect_uri=url_for("authorized", _external=True, _scheme='https'))
    if "error" in result:
        return "Login failure: %s, %s" % (
            result["error"], result.get("error_description"))
    session["user"] = result.get("id_token_claims")
    _save_cache(cache)
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session["user"] = None  # Log out from this app from its session
    # session.clear()  # If you prefer, this would nuke the user's token cache too
    return redirect(  # Also need to logout from Microsoft Identity platform
        "https://login.microsoftonline.com/common/oauth2/v2.0/logout"
        "?post_logout_redirect_uri=" + url_for("index"))

@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app.configSCOPE)
    if not token:
        return redirect(url_for("login"))
    graph_data = requests.get(  # Use token to call downstream service
        app.config["ENPOINT"],
        headers={'Authorization': 'Bearer ' + token['access_token']},
        ).json()
    return render_template('display.html', result=graph_data)


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        config["azClientId"], authority=app.config["AUTHORITY"],
        client_credential=config["azClientSecret"], token_cache=cache)

def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result

@app.route("/echo", methods = ['GET'])
def echoApi():
    result = {
        'date': datetime.datetime.utcnow().isoformat(),
        'api': request.url,
        'Host': request.headers.get('host'),
        'x-forwarded-for': request.headers.get('x-forwarded-for'),
        'x-original-host': request.headers.get('x-original-host')
    }
    return Response( json.dumps(result), status=200, mimetype='application/json')

if __name__ == "__main__":
    app.run(host="localhost", port=5000)