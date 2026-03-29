# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file

"""Miscellaneous utility functions for Python 3.13+."""

import binascii
import re
import time


def compat26Str(x):
    """Identity function for compatibility."""
    return x


def compatHMAC(x):
    """Convert bytes-like input to format acceptable for HMAC."""
    return x


def compatAscii2Bytes(val):
    """Convert ASCII string to bytes."""
    if isinstance(val, str):
        return bytes(val, "ascii")
    return val


def compat_b2a(val):
    """Convert an ASCII bytes string to string."""
    return str(val, "ascii")


def a2b_hex(s):
    """Convert hex string to bytearray."""
    try:
        b = bytearray(binascii.a2b_hex(bytearray(s, "ascii")))
    except Exception as e:
        raise SyntaxError(f"base16 error: {e}") from e
    return b


def a2b_base64(s):
    """Convert base64 string to bytearray."""
    try:
        if isinstance(s, str):
            s = bytearray(s, "ascii")
        b = bytearray(binascii.a2b_base64(s))
    except Exception as e:
        raise SyntaxError(f"base64 error: {e}") from e
    return b


def b2a_hex(b):
    """Convert bytes to hex string."""
    return binascii.b2a_hex(b).decode("ascii")


def b2a_base64(b):
    """Convert bytes to base64 string."""
    return binascii.b2a_base64(b).decode("ascii")


def readStdinBinary():
    """Read binary data from stdin."""
    import sys

    return sys.stdin.buffer.read()


def compatLong(num):
    """Convert to int (compatibility function)."""
    return int(num)


int_types = (int,)


def formatExceptionTrace(e):
    """Return exception information formatted as string."""
    return str(e)


def time_stamp():
    """Returns system time as a float."""
    return time.perf_counter()


def remove_whitespace(text):
    """Removes all whitespace from passed in string."""
    return re.sub(r"\s+", "", text, flags=re.UNICODE)


bytes_to_int = int.from_bytes


def bit_length(val):
    """Return number of bits necessary to represent an integer."""
    return val.bit_length()


def int_to_bytes(val, length=None, byteorder="big"):
    """Return number converted to bytes."""
    if length is None:
        if val:
            length = byte_length(val)
        else:
            length = 1
    # for gmpy we need to convert back to native int
    if not isinstance(val, int):
        val = int(val)
    return bytearray(val.to_bytes(length=length, byteorder=byteorder))


def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    length = bit_length(val)
    return (length + 7) // 8


ecdsaAllCurves = False
ML_KEM_AVAILABLE = False
ML_DSA_AVAILABLE = False
