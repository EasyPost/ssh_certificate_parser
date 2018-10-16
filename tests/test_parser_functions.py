from ssh_certificate_parser import parser_helpers
from ssh_certificate_parser.errors import InputTooShortError

import pytest


def test_take_u32():
    assert (0, b'') == parser_helpers.take_u32(b'\x00\x00\x00\x00')
    assert (1, b'\x00\x00\x00\x00') == parser_helpers.take_u32(b'\x00\x00\x00\x01\x00\x00\x00\x00')
    with pytest.raises(InputTooShortError):
        parser_helpers.take_u32(b'\x00')


def test_take_u64():
    assert (0, b'') == parser_helpers.take_u64(b'\x00\x00\x00\x00\x00\x00\x00\x00')
    assert (1, b'\x00') == parser_helpers.take_u64(b'\x00\x00\x00\x00\x00\x00\x00\x01\x00')
    with pytest.raises(InputTooShortError):
        parser_helpers.take_u64(b'\x00')


def test_take_pascal_bytestring():
    assert (b'foo', b'') == parser_helpers.take_pascal_bytestring(b'\x00\x00\x00\x03foo')
    assert (b'foo', b'\x01') == parser_helpers.take_pascal_bytestring(b'\x00\x00\x00\x03foo\x01')
    assert (b'fo\x00', b'\x01') == parser_helpers.take_pascal_bytestring(b'\x00\x00\x00\x03fo\x00\x01')
    with pytest.raises(InputTooShortError):
        parser_helpers.take_pascal_bytestring(b'\x00\x00\x00\x03fo')


def test_take_pascal_string():
    assert ('foo', b'') == parser_helpers.take_pascal_string(b'\x00\x00\x00\x03foo')
    assert ('fπø', b'\x00') == parser_helpers.take_pascal_string(b'\x00\x00\x00\x05f\xcf\x80\xc3\xb8\x00')


def test_take_list():
    assert ([1, 2], b'\x01') == parser_helpers.take_list(
        b'\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x02\x01',
        parser_helpers.take_u32
    )
