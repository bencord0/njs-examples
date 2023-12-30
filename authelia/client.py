import sys
import requests
from argparse import ArgumentParser
from getpass import getuser, getpass

parser = ArgumentParser()
parser.add_argument("--otp", required=False)


def main():
    args = parser.parse_args()
    session = requests.Session()

    #baseurl = "https://local.condi.me" # Example real URL that is in the same cookie domain
    baseurl = "https://localhost"

    response = session.get(f"{baseurl}/api", allow_redirects=False, verify = "./server.pem")
    if response.status_code == 200:
        print("Already authenticated")
        sys.exit(0)

    # Oh no! we're not authenticated!
    assert response.status_code in (302, 401), response.status_code

    # Login with username and password
    response = session.post("https://auth.condi.me/api/firstfactor", json={
        "username": getuser(),
        "password": getpass(),
        "keepMeLoggedIn": True,
    })

    assert response.status_code == 200, {
        "code": response.status_code,
        "reqHeaders": response.request.headers,
        "headers": response.headers,
        "body": response.text,
    }

    otp = args.otp
    if otp is None:
        otp = getpass("OTP: ")

    # Login with second factor
    response = session.post("https://auth.condi.me/api/secondfactor/totp", json={
        "token": otp,
    })
    assert response.status_code == 200, {
        "code": response.status_code,
        "reqHeaders": response.request.headers,
        "headers": response.headers,
        "body": response.text,
    }

    if 'localhost' in baseurl:
        # only needed to hack around the cookie's trusted domains
        session.cookies.set('authelia_session', response.cookies.get('authelia_session'))

    # Attempt to request the resource again, this time with cookies
    response = session.get(f"{baseurl}/api", verify = "./server.pem")
    assert response.status_code == 200, {
        "code": response.status_code,
        "reqHeaders": response.request.headers,
        "headers": response.headers,
        "body": response.text,
    }
    print("Request Successful")


if __name__ == '__main__':
    main()
