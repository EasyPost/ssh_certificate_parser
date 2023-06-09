`ssh_certificate_parser` is a small library for interacting with [OpenSSH host/user certificates](https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.15&content-type=text/plain). Specifically, it supports RSA, DSA, and Ed25519 keys signed by an RSA certificate authority. It does not currently validate the CA signature, but merely parses out some fields.

![CI](https://github.com/EasyPost/ssh_certificate_parser/workflows/CI/badge.svg)
[![Documentation Status](https://readthedocs.org/projects/ssh-certificate-parser/badge/?version=latest)](https://ssh-certificate-parser.readthedocs.io/en/latest/?badge=latest)

This work is licensed under the ISC license, a copy of which can be found at [LICENSE.txt](LICENSE.txt)

## Usage

This module contains a single class, `SSHCertificate`. You can construct it with the `.from_bytes` or `.from_file` classmethods.

```python
from ssh_certificate_parser import SSHCertificate

cert = SSHCertificate.from_file('/etc/ssh/ssh_host_rsa_key-cert.pub')

remaining_seconds_of_validity = cert.remaining_validity
```

Full documentation is at <https://ssh-certificate-parser.readthedocs.io/en/latest/>.

## Development

```sh
# Install dependencies
make install

# Lint project
make lint

# Test project
make test
make coverage
```
