import argparse
import json

from . import SSHCertificate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path_to_certificate', type=argparse.FileType('r'))
    args = parser.parse_args()

    cert = SSHCertificate.from_bytes(args.path_to_certificate.read())
    print(json.dumps(cert.asdict()))


main()
