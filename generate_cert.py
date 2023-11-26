#!/usr/bin/env python

from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


parser = ArgumentParser()
parser.add_argument("--cert", required=True)
keygroup = parser.add_mutually_exclusive_group(required=True)
keygroup.add_argument("--key")
keygroup.add_argument("--fromkey")


def main():
    args = parser.parse_args()

    private_key = None

    # Attempt to read private key from file
    if args.fromkey:
        with open(args.fromkey, 'rb') as keyfile:
            private_bytes = keyfile.read()

        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None,
        )

    # Otherwise, generate a new private key
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        serialized_privatekey = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(args.key, 'wb') as keyfile:
            keyfile.write(serialized_privatekey)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder(
    ).subject_name(subject
    ).issuer_name(issuer
    ).public_key(private_key.public_key()
    ).serial_number(x509.random_serial_number()
    ).not_valid_before(datetime.now(timezone.utc)
    ).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1000)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    with open(args.cert, 'wb') as certfile:
        certfile.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == '__main__':
    main()
