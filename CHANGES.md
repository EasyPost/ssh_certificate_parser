1.2.0
=====
- Can now parse DSA and Ed25519 keys (although they still have to have been signed by an RSA CA)
- Unit tests
- `key_type` is now in the `SSHCertificate` object
- `pubkey_parts` is a dictionary containing the appropriate parts for that key (e.g., `n` and `e` for RSA)
- Now raises subclasses of `ssh_certificate_parser.errors.SSHCertificateParserError` instead of just `ValueError` with a string description

1.1.0
=====
- CA certificate fingerprint (equivalent to `ssh-keygen -l -f /path/to/key.pub`) is now parsed for ssh-rsa CAs. I don't have any ECDSA/Ed25519 CAs so I haven't tested them!
