#!/usr/bin/env python
import os
import requests
import uuid
from getpass import getuser, getpass
from urllib.parse import urlparse, parse_qs

session = requests.Session()

# https://condi.uk.auth0.com/.well-known/openid-configuration
# https://auth0.com/docs/api/authentication#social
AUTHORIZATION_ENDPOINT = "https://condi.uk.auth0.com/authorize"
# https://auth0.com/docs/api/authentication#get-token
TOKEN_ENDPOINT = "https://condi.uk.auth0.com/oauth/token"
# https://auth0.com/docs/api/authentication#user-profile
USERINFO_ENDPOINT = "https://condi.uk.auth0.com/userinfo"

# Auth0 Specific Web pages
LOGIN_ENDPOINT = "https://condi.uk.auth0.com/u/login"
RESUME_ENDPOINT = "https://condi.uk.auth0.com/authorize/resume"

# GET /authorize
print("GET /authorize")
state = uuid.uuid4().hex
query = {
    "client_id": os.getenv("AUTH0_CLIENT_ID"),
    "redirect_uri": "http://localhost:3000/callback",
    "response_type": "code",
    "scope": "openid profile",
    "state": state
}
print(query)
response = session.get(AUTHORIZATION_ENDPOINT, params=query, allow_redirects=False)
assert 302, response.status_code
authorization_state = parse_qs(urlparse(response.headers['location']).query)['state'][0]
print(f"authorization state: {authorization_state}")

# POST /login
print("POST /login")
form = {
    "state": authorization_state,
    "username": getuser(),
    "password": getpass(),
    "action": "default",
}
response = session.post(LOGIN_ENDPOINT, data=form, allow_redirects=False)
assert 302, response.status_code
resume_state = parse_qs(urlparse(response.headers['location']).query)['state'][0]
print(f"resume state: {resume_state}")

# GET /authorize/resume
print("GET /authorize/resume")
query = {
    "state": resume_state,
}
print(query)
response = session.get(RESUME_ENDPOINT, params=query, allow_redirects=False)
assert 302, response.status_code
code = parse_qs(urlparse(response.headers['location']).query)['code'][0]
print(f"code: {code}")

exchange_state = parse_qs(urlparse(response.headers['location']).query)['state'][0]
assert state == exchange_state

# POST /oauth/token
print("POST /oauth/token")
query = {
    "grant_type": "authorization_code",
    "client_id": os.getenv("AUTH0_CLIENT_ID"),
    "client_secret": os.getenv("AUTH0_CLIENT_SECRET"),
    "code": code,
    "redirect_uri": "http://localhost:3000/callback",
}
print(query)
response = requests.post(TOKEN_ENDPOINT, data=query, allow_redirects=False)
assert 200, response.status_code
token = response.json()

# Verify ID Token
# XXX: Do it properly, cryptographically chech the sig
raw_id_token = token['id_token']
from base64 import urlsafe_b64decode as decode
import json
header, payload, sig = raw_id_token.split('.')
id_token = decode(payload + '=' * (-len(payload) % 4))
identity = json.loads(id_token)
print(f"identity: {identity['nickname']}")
access_token = token['access_token']

# GET /userinfo
# https://auth0.com/docs/secure/tokens/access-tokens/validate-access-tokens
# The access token is "alg":"dir" symetrically encrypted. The only way to verify
# it is to use it to access the userinfo endpoint.
print("GET /userinfo")
response = requests.get(USERINFO_ENDPOINT, headers={"Authorization": f"Bearer {access_token}"})
print(response.status_code)
assert 200, response.status_code
print(response.json())
