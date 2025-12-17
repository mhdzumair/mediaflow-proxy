# mediaflow_proxy/utils/python_aesgcm.py

from .aesgcm import AESGCM
from .rijndael import Rijndael


def new(key: bytes) -> AESGCM:
    """
    Mirror ResolveURL's python_aesgcm.new(key) API:
    returns an AESGCM instance with pure-Python Rijndael backend.
    """
    return AESGCM(key, "python", Rijndael(key, 16).encrypt)
