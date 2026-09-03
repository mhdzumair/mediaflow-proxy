"""
Tests for the SSRF guard in mediaflow_proxy.routes.proxy.

_check_forward_destination used to only reject numeric private/loopback IP
literals, so a hostname that resolves to one (a DNS rebinding-style host, or
a service like nip.io that maps a hostname straight to an IP) sailed
through. /proxy/stream had no guard at all. Both are fixed by resolving the
hostname and checking every address it resolves to.
"""

import pytest
from fastapi import HTTPException

from mediaflow_proxy.routes.proxy import _check_forward_destination, _check_not_internal_address


async def test_rejects_private_ip_literal():
    with pytest.raises(HTTPException) as exc_info:
        await _check_not_internal_address("169.254.169.254")
    assert exc_info.value.status_code == 403


async def test_rejects_hostname_that_resolves_to_loopback():
    # "localhost" is a hostname, not a numeric literal, and it resolves to
    # 127.0.0.1. This is exactly the class of bypass reported: a name whose
    # own resolution lands on a private/loopback address.
    with pytest.raises(HTTPException) as exc_info:
        await _check_not_internal_address("localhost")
    assert exc_info.value.status_code == 403


async def test_allows_a_public_hostname():
    # Should resolve normally and not raise.
    await _check_not_internal_address("example.com")


async def test_forward_destination_rejects_hostname_bypass():
    with pytest.raises(HTTPException) as exc_info:
        await _check_forward_destination("http://localhost/latest/meta-data/")
    assert exc_info.value.status_code == 403
