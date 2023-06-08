import datetime
from pathlib import Path

from ssh_certificate_parser import SSHCertificate, RSAPublicKey

import pytest


def test_rsa_cert(mocker):
    with open('tests/data/web1_rsa_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-rsa-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 2, 41)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 2, 41)
    assert cert.key_id == 'web1'
    assert cert.principals == ['web1.example.com']
    assert cert.serial == 1
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(2018, 10, 9, 0, 2, 39))
    assert cert.remaining_validity == 0
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(2018, 10, 9, 0, 2, 41))
    assert cert.remaining_validity == 32054400.0
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(2019, 10, 16, 0, 2, 41))
    assert cert.remaining_validity == 0
    d = cert.asdict()
    assert d['ca_fingerprint'] == 'SHA256:dHmZ5LUyoGNqkH8zzg7hndOJp9rqKRgq21OVMW7JhPk'
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['crits'] == []
    assert d['exts'] == []

    assert isinstance(cert.ca, RSAPublicKey)


def test_forever_cert(mocker):
    with open('tests/data/web4_rsa_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.valid_after == datetime.datetime(1970, 1, 1, 0, 0, 0)
    assert cert.valid_before == datetime.datetime(9999, 12, 31, 0, 0, 0)
    assert cert.key_id == 'web4'
    assert cert.principals == ['web4.example.com']
    assert cert.serial == 0
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(1970, 1, 2, 0, 0, 0))
    assert cert.remaining_validity > 0
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(2018, 2, 5, 0, 0, 0))
    assert cert.remaining_validity > 0
    mocker.patch('ssh_certificate_parser.utcnow', return_value=datetime.datetime(2099, 3, 8, 0, 0, 0))
    assert cert.remaining_validity > 0
    d = cert.asdict()
    assert d['ca_fingerprint'] == 'SHA256:sZ8QWMpND0GZa8pm3MFNV8nHB2+ssdukl/FyZ49JBgU'
    assert d['cert_type'] == 'SSH2_CERT_TYPE_USER'
    assert d['crits'] == []
    assert d['exts'] == []


def test_ed25519_cert():
    with open('tests/data/web1_ed25519_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-ed25519-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 8, 1)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 8, 1)
    assert cert.key_id == 'web1'
    assert cert.principals == ['web1.example.com']
    assert cert.serial == 1
    d = cert.asdict()
    assert d['ca_fingerprint'] == 'SHA256:dHmZ5LUyoGNqkH8zzg7hndOJp9rqKRgq21OVMW7JhPk'
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['crits'] == []
    assert d['exts'] == []


def test_dsa_cert():
    with open('tests/data/web2_dsa_key-cert.pub', 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ssh-dss-cert-v01@openssh.com'
    assert cert.valid_after == datetime.datetime(2018, 10, 9, 0, 11, 55)
    assert cert.valid_before == datetime.datetime(2019, 10, 15, 0, 11, 55)
    assert cert.key_id == 'web2'
    assert cert.principals == ['web2.example.com']
    assert cert.serial == 2
    d = cert.asdict()
    assert d['ca_fingerprint'] == 'SHA256:dHmZ5LUyoGNqkH8zzg7hndOJp9rqKRgq21OVMW7JhPk'
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['crits'] == []
    assert d['exts'] == []


@pytest.mark.parametrize('key_size', ['256', '384', '521'])
def test_ecdsa_cert(key_size):
    with open('tests/data/web3_{0}_ecdsa_key-cert.pub'.format(key_size), 'rb') as f:
        cert = SSHCertificate.from_bytes(f.read())
    assert cert.key_type == 'ecdsa-sha2-nistp{0}-cert-v01@openssh.com'.format(key_size)
    assert cert.valid_after == datetime.datetime(2021, 8, 12, 9, 2, 3)
    assert cert.valid_before == datetime.datetime(2022, 8, 14, 7, 59, 59)
    assert cert.key_id == 'CN=web3,CA=new_ca'
    assert cert.principals == ['web3', 'web3.example']
    assert cert.serial == 0
    d = cert.asdict()
    assert d['ca_fingerprint'] == 'SHA256:DEGzMMIkpgHKD7EdQr8p9BemrKdzhmTbhFZch4Scx1w'
    assert d['cert_type'] == 'SSH2_CERT_TYPE_HOST'
    assert d['crits'] == []
    assert d['exts'] == []
    assert d['pubkey_parts']['curve'] == 'nistp{0}'.format(key_size)


def test_from_file():
    path = 'tests/data/web1_ed25519_key-cert.pub'
    cert = SSHCertificate.from_file(path)
    assert cert.key_type == 'ssh-ed25519-cert-v01@openssh.com'

    with open(path, 'rb') as f:
        cert = SSHCertificate.from_file(f)
        assert cert.key_type == 'ssh-ed25519-cert-v01@openssh.com'

    cert = SSHCertificate.from_file(Path(path))
    assert cert.key_type == 'ssh-ed25519-cert-v01@openssh.com'
