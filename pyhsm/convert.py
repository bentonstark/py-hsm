#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# convert.py
# author: Benton Stark (bestark@cisco.com)
# date: 11-22-2014

import binascii


def bytes_to_hex(b):
    """
    Convert bytes or bytearray to hexadecimal str.

    Args:
        b:    python bytes string or bytearray to convert

    Returns:
        hex-encoded representation of a binary string

    """
    if not isinstance(b, bytes) and not isinstance(b, bytearray):
        raise Exception("bytes_to_hex: b must be of type bytes or bytearray")
    if len(b) <= 0:
        raise Exception("bytes_to_hex: b must contain a value")
    return str(binascii.hexlify(b))[2:-1]


def hex_to_bytes(hex_str):
    """
    Convert hexadecimal string to a bytes binary string

    Args:
        hex_str:     hexadecimal representation of a binary string

    Returns:
        immutable python byte string

    """
    if not isinstance(hex_str, str):
        raise Exception("hex_to_bytes: hex must be of type str")
    elif len(hex_str) == 0:
        return ""
    elif len(hex_str) <= 0:
        raise Exception("hex_to_bytes: hex must contain a value")
    return binascii.a2b_hex(hex_str)


def str_to_bytes(s):
    """
    Convert str to bytes string if needed.

    Args:
        s:  string to convert

    Returns: python byte string if input a str otherwise s

    """
    if isinstance(s, str):
        s = s.encode('ascii')
    return s


def bytes_to_str(b):
    """
    Convert bytes or bytearray to an ascii str.

    Args:
        b:  byte string or byte array to convert

    Returns: python string if input is bytes or bytearray

    """
    if not isinstance(b, bytes) and not isinstance(b, bytearray):
        raise Exception("bytes_to_str: b must be of type bytes or bytearray")
    if len(b) == 0:
        return ""
    b = b.decode('ascii')
    return b
