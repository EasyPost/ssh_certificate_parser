ChangeLog
=========

1.5.0
-----

- Adds proper support for `ecdsa-sha2-nistp256`

1.4.0
-----

- Adds proper support for `ecdsa-sha2-nistp384`

1.3.3
-----

- Fix RtD link issue

1.3.2
-----

- Fix PyPI project URLs

1.3.1
-----

- Fix `setup.py` issues

1.3.0
-----

- Can now parse ECDSA keys (if they're signed with an RSA CA)
- Add `.from_file` constructor on `SSHCertificate`
- Add a bunch of type hints
- Improve documentation a bit

1.2.0
-----

- Can now parse DSA and Ed25519 keys (although they still have to have been signed by an RSA CA)
- Unit tests
- `key_type` is now in the `SSHCertificate` object
- `pubkey_parts` is a dictionary containing the appropriate parts for that key (e.g., `n` and `e` for RSA)
- Now raises subclasses of `ssh_certificate_parser.errors.SSHCertificateParserError` instead of just `ValueError` with a string description

1.1.0
-----

- CA certificate fingerprint (equivalent to `ssh-keygen -l -f /path/to/key.pub`) is now parsed for ssh-rsa CAs. I don't have any ECDSA/Ed25519 CAs so I haven't tested them!
