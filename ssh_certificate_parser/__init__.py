import base64
import datetime
import enum
import hashlib
from pathlib import Path
from typing import List

import attr

from .errors import UnsupportedCertificateTypeError, UnsupportedKeyTypeError
from .parser_helpers import (take_list, take_pascal_bytestring,
                             take_pascal_string, take_u32, take_u64)

__author__ = 'EasyPost <oss@easypost.com>'
version_info = (1, 4, 0)
__version__ = '.'.join(str(s) for s in version_info)


class CertType(enum.Enum):
    SSH2_CERT_TYPE_USER = 1
    SSH2_CERT_TYPE_HOST = 2


@attr.s
class PublicKey(object):
    """The public key of a CA"""
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


def take_ed25519_cert(raw_pubkey):
    return PublicKey(raw=raw_pubkey)


def utcnow():
    return datetime.datetime.utcnow()  # pragma: no cover


@attr.s
class SSHCertificate(object):
    """Representation of a signed SSH certificate"""
    serial: int = attr.ib()
    cert_type: CertType = attr.ib()
    key_id: str = attr.ib()
    principals: List[str] = attr.ib()
    valid_after: datetime.date = attr.ib()
    valid_before: datetime.date = attr.ib()
    crits: List[str] = attr.ib()
    exts: List[str] = attr.ib()
    ca: PublicKey = attr.ib()
    signature: bytes = attr.ib()
    key_type: str = attr.ib()
    pubkey_parts: dict = attr.ib()

    def asdict(self):
        """Return a dictionary with the important properties of this certificate"""
        dct = attr.asdict(self)
        del dct['ca']
        dct['valid_after'] = dct['valid_after'].isoformat()
        dct['valid_before'] = dct['valid_before'].isoformat()
        dct['cert_type'] = dct['cert_type'].name
        dct['signature'] = base64.b64encode(dct['signature']).decode('ascii')
        dct['ca_fingerprint'] = self.ca.fingerprint
        dct['pubkey_parts'] = dict(
            (
                k,
                base64.b64encode(v).decode('ascii')
                if isinstance(v, bytes)
                else v
            )
            for k, v in
            dct['pubkey_parts'].items()
        )
        return dct

    @classmethod
    def from_file(cls, path_or_file_object):
        """Construct a new SSHCertificate from a path or open file descriptor

        :path_or_file_object: A path or open file object pointing to a valid certifcate
        """
        if isinstance(path_or_file_object, (str, Path)):
            with open(path_or_file_object, 'rb') as f:
                return cls.from_file(f)
        return cls.from_bytes(path_or_file_object.read())

    @classmethod
    def from_bytes(cls, byte_array):
        """Construct a new SSHCertificate from a byte array

        :param byte_array: bytestring or equivalent object
        """
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
        elif key_type in (
            'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521-cert-v01@openssh.com'
        ):
            pubkey_parts['nonce'], blob = take_pascal_bytestring(blob)
            pubkey_parts['curve'], blob = take_pascal_string(blob)
            pubkey_parts['point'], blob = take_pascal_bytestring(blob)
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
        # Forever certificate may be large, change to a value that can be handled by CPython
        max_python_datetime = datetime.datetime(year=9999, month=12, day=31)
        if valid_before > max_python_datetime.timestamp():
            valid_before = max_python_datetime
        else:
            valid_before = datetime.datetime.utcfromtimestamp(valid_before)
        crits, blob = take_list(blob, take_pascal_string)
        exts, blob = take_list(blob, take_pascal_string)
        unknown, blob = take_pascal_bytestring(blob)
        raw_ca, blob = take_pascal_bytestring(blob)
        ca_cert_type, raw_ca_rest = take_pascal_string(raw_ca)
        if ca_cert_type in ('ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384'):
            ca_cert = take_rsa_cert(raw_ca, raw_ca_rest)
        elif ca_cert_type == 'ssh-ed25519':
            ca_cert = take_ed25519_cert(raw_ca)
        else:
            raise UnsupportedCertificateTypeError(ca_cert_type)
        signature = blob
        return SSHCertificate(
            serial, cert_type, key_id, principals, valid_after, valid_before,
            crits, exts, ca_cert, signature, key_type, pubkey_parts
        )

    @property
    def remaining_validity(self):
        """Number of seconds of remaining validity on this certificate"""
        now = utcnow()
        if now > self.valid_before or now < self.valid_after:
            return 0
        else:
            return (self.valid_before - now).total_seconds()


__all__ = ['SSHCertificate', 'CertType']
