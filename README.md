`ssh_certificate_parser` is a small library for interacting with [OpenSSH host/user certificates](https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.15&content-type=text/plain). Specifically, it supports RSA, DSA, and Ed25519 keys signed by an RSA certificate authority. It does not currently validate the CA signature, but merely parses out some fields.

[![Build Status](https://travis-ci.com/EasyPost/ssh_certificate_parser.svg?branch=master)](https://travis-ci.com/EasyPost/ssh_certificate_parser)

This work is licensed under the ISC license, a copy of which can be found at [LICENSE.txt](LICENSE.txt)
