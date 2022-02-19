#!/usr/bin/python

from contextlib import nullcontext
from flask import Flask, render_template
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

app = Flask(__name__, static_url_path='',static_folder='static') # Flask instance named app
cacheConfig = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 300,
    "SESSION_TYPE": "filesystem"
}
app.config.from_mapping(cacheConfig)

cache = Cache(app)

app.secret_key = os.urandom(24).hex() #'61U7Q~B0qmpNP8~sWHn7_K1t1V1QPeCRiCtBA'

config = json.load(open("./config.json"))

Session(app)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
log = logging.getLogger() 
log.setLevel(logging.INFO)



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
    if not session.get("user"):
        return redirect(url_for("login"))
    user = session["user"]
    payload["issuance"]["claims"]["given_name"] = user["given_name"]
    payload["issuance"]["claims"]["family_name"] = user["family_name"]
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
#def root():
#    varvalue="testing"
#    return render_template('index.html')
    #return app.send_static_file('index.html')

def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    user = session["user"]

    return render_template('index.html', given_name=user["given_name"], family_name=user["family_name"])

@app.route("/login")
def login():
    # Technically we could use empty list [] as scopes to do just sign in,
    # here we choose to also collect end user consent upfront
    session["flow"] = _build_auth_code_flow(scopes=config["azScope"])
    return render_template("login.html", auth_url=session["flow"]["auth_uri"], version=msal.__version__)

@app.route(config["azRedirectPath"])  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session["user"] = None  # Log out from this app from its session
    # session.clear()  # If you prefer, this would nuke the user's token cache too
    return redirect(  # Also need to logout from Microsoft Identity platform
        "https://login.microsoftonline.com/"
        + config["azTenantId"] + "/oauth2/v2.0/logout")
#        "?post_logout_redirect_uri=" + url_for("index"))

@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app.config["SCOPE"])
    if not token:
        return redirect(url_for("login"))
    graph_data = requests.get(  # Use token to call downstream service
        app.config["azEndpoint"],
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
        config["azClientId"], authority=config["azAuthority"],
        client_credential=config["azClientSecret"], token_cache=cache)

def _build_auth_code_flow(scopes=None):
    return _build_msal_app(cache=_load_cache()).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))

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