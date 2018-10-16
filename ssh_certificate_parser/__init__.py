import base64
import hashlib
import enum
import datetime

import attr

from .errors import UnsupportedKeyTypeError
from .errors import UnsupportedCertificateTypeError
from .parser_helpers import take_u32
from .parser_helpers import take_u64
from .parser_helpers import take_pascal_bytestring
from .parser_helpers import take_pascal_string
from .parser_helpers import take_list


__author__ = 'EasyPost <oss@easypost.com>'
version_info = (1, 2, 0)
__version__ = '.'.join(str(s) for s in version_info)


class CertType(enum.Enum):
    SSH2_CERT_TYPE_USER = 1
    SSH2_CERT_TYPE_HOST = 2


@attr.s
class PublicKey(object):
    raw = attr.ib()

    @property
    def fingerprint(self):
        dgt = hashlib.sha256(self.raw).digest()
        b64 = base64.standard_b64encode(dgt).decode('ascii')
        return 'SHA256:{0}'.format(b64.rstrip('='))


@attr.s
class RSAPublicKey(PublicKey):
    modulus = attr.ib()
    exponent = attr.ib()


def take_rsa_cert(raw_pubkey, byte_array):
    modulus_len, byte_array = take_u32(byte_array)
    modulus = byte_array[:modulus_len]
    byte_array = byte_array[modulus_len:]
    exponent_len, byte_array = take_u32(byte_array)
    exponent = byte_array[:exponent_len]
    return RSAPublicKey(modulus=modulus, exponent=exponent, raw=raw_pubkey)


def utcnow():
    return datetime.datetime.utcnow()  # pragma: no cover


@attr.s
class SSHCertificate(object):
    serial = attr.ib()
    cert_type = attr.ib()
    key_id = attr.ib()
    principals = attr.ib()
    valid_after = attr.ib()
    valid_before = attr.ib()
    crits = attr.ib()
    exts = attr.ib()
    ca = attr.ib()
    signature = attr.ib()
    key_type = attr.ib()
    pubkey_parts = attr.ib()

    def asdict(self):
        dct = attr.asdict(self)
        del dct['ca']
        dct['valid_after'] = dct['valid_after'].isoformat()
        dct['valid_before'] = dct['valid_before'].isoformat()
        dct['cert_type'] = dct['cert_type'].name
        dct['signature'] = base64.b64encode(dct['signature']).decode('ascii')
        dct['ca_fingerprint'] = self.ca.fingerprint
        dct['pubkey_parts'] = dict(
            (k, base64.b64encode(v).decode('ascii'))
            for k, v in
            dct['pubkey_parts'].items()
        )
        return dct

    @classmethod
    def from_bytes(cls, byte_array):
        if b' ' in byte_array:
            blob = byte_array.split(b' ')[1]
        else:
            blob = byte_array
        blob = base64.b64decode(blob)
        key_type, blob = take_pascal_string(blob)
        pubkey_parts = {}
        if key_type == 'ssh-rsa-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['n'], blob = take_pascal_bytestring(blob)
            pubkey_parts['e'], blob = take_pascal_bytestring(blob)
        elif key_type == 'ssh-ed25519-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['pubkey'], blob = take_pascal_bytestring(blob)
        elif key_type == 'ssh-dss-cert-v01@openssh.com':
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['p'], blob = take_pascal_bytestring(blob)
            pubkey_parts['q'], blob = take_pascal_bytestring(blob)
            pubkey_parts['g'], blob = take_pascal_bytestring(blob)
            pubkey_parts['pubkey'], blob = take_pascal_bytestring(blob)
        else:
            raise UnsupportedKeyTypeError(key_type)
        serial, blob = take_u64(blob)
        cert_type, blob = take_u32(blob)
        cert_type = CertType(cert_type)
        key_id, blob = take_pascal_string(blob)
        principals, blob = take_list(blob, take_pascal_string)
        valid_after, blob = take_u64(blob)
        valid_after = datetime.datetime.utcfromtimestamp(valid_after)
        valid_before, blob = take_u64(blob)
        valid_before = datetime.datetime.utcfromtimestamp(valid_before)
        crits, blob = take_list(blob, take_pascal_string)
        exts, blob = take_list(blob, take_pascal_string)
        unknown, blob = take_pascal_bytestring(blob)
        raw_ca, blob = take_pascal_bytestring(blob)
        ca_cert_type, raw_ca_rest = take_pascal_string(raw_ca)
        if ca_cert_type == 'ssh-rsa':
            ca_cert = take_rsa_cert(raw_ca, raw_ca_rest)
        else:
            raise UnsupportedCertificateTypeError(ca_cert_type)
        signature = blob
        return SSHCertificate(
            serial, cert_type, key_id, principals, valid_after, valid_before,
            crits, exts, ca_cert, signature, key_type, pubkey_parts
        )

    @property
    def remaining_validity(self):
        now = utcnow()
        if now > self.valid_before or now < self.valid_after:
            return 0
        else:
            return (self.valid_before - now).total_seconds()


__all__ = ['SSHCertificate']
