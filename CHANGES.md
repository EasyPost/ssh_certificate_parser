# CHANGELOG

## v1.6.0

- Adds support for certs that last forever
- Adds support for `ed25519` certs

## v1.5.0

- Adds proper support for `ecdsa-sha2-nistp256`

## v1.4.0

- Adds proper support for `ecdsa-sha2-nistp384`

## v1.3.3

- Fix RtD link issue

## v1.3.2

- Fix PyPI project URLs

## v1.3.1

- Fix `setup.py` issues

## v1.3.0

- Can now parse ECDSA keys (if they're signed with an RSA CA)
- Add `.from_file` constructor on `SSHCertificate`
- Add a bunch of type hints
- Improve documentation a bit

## v1.2.0

- Can now parse DSA and Ed25519 keys (although they still have to have been signed by an RSA CA)
- Unit tests
- `key_type` is now in the `SSHCertificate` object
- `pubkey_parts` is a dictionary containing the appropriate parts for that key (e.g., `n` and `e` for RSA)
- Now raises subclasses of `ssh_certificate_parser.errors.SSHCertificateParserError` instead of just `ValueError` with a string description

## v1.1.0

- CA certificate fingerprint (equivalent to `ssh-keygen -l -f /path/to/key.pub`) is now parsed for ssh-rsa CAs. I don't have any ECDSA/Ed25519 CAs so I haven't tested them!

## v1.0.0

- Initial release
