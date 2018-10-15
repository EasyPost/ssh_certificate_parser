import struct

from .errors import InputTooShortError


def take_u32(byte_array):
    if len(byte_array) < 4:
        raise InputTooShortError()
    return struct.unpack('!L', byte_array[:4])[0], byte_array[4:]


def take_u64(byte_array):
    if len(byte_array) < 8:
        raise InputTooShortError()
    return struct.unpack('!Q', byte_array[:8])[0], byte_array[8:]


def take_pascal_bytestring(byte_array):
    string_len, rest = take_u32(byte_array)
    if len(rest) < string_len:
        raise InputTooShortError()
    return rest[:string_len], rest[string_len:]


def take_pascal_string(byte_array):
    string_len, rest = take_u32(byte_array)
    return rest[:string_len].decode('utf-8'), rest[string_len:]


def take_list(byte_array, per_item_callback):
    overall, rest = take_pascal_bytestring(byte_array)
    lst = []
    while overall:
        item, overall = per_item_callback(overall)
        lst.append(item)
    return lst, rest
