# Author: Hubert Kario (c) 2015
# see LICENCE file for legal information regarding use of this file

"""hashlib that handles FIPS mode."""

import hashlib

# Re-export commonly used hash constructors
sha1 = hashlib.sha1
sha224 = hashlib.sha224
sha256 = hashlib.sha256
sha384 = hashlib.sha384
sha512 = hashlib.sha512
sha3_224 = hashlib.sha3_224
sha3_256 = hashlib.sha3_256
sha3_384 = hashlib.sha3_384
sha3_512 = hashlib.sha3_512
blake2b = hashlib.blake2b
blake2s = hashlib.blake2s


def _fipsFunction(func, *args, **kwargs):
    """Make hash function support FIPS mode."""
    try:
        return func(*args, **kwargs)
    except ValueError:
        return func(*args, usedforsecurity=False, **kwargs)


def md5(*args, **kwargs):
    """MD5 constructor that works in FIPS mode."""
    return _fipsFunction(hashlib.md5, *args, **kwargs)


def new(*args, **kwargs):
    """General constructor that works in FIPS mode."""
    return _fipsFunction(hashlib.new, *args, **kwargs)
