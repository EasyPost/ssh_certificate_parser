import attr


class SSHCertificateParserError(Exception):
    pass


@attr.s(frozen=True, hash=True, eq=True, order=True)
class UnsupportedKeyTypeError(SSHCertificateParserError):
    """This key has a type which we do not know how to parse"""
    key_type = attr.ib()


@attr.s(frozen=True, hash=True, eq=True, order=True)
class UnsupportedCertificateTypeError(SSHCertificateParserError):
    """This key was signed with an unknown certificate algorithm"""
    cert_type = attr.ib()


class InputTooShortError(SSHCertificateParserError):
    pass
