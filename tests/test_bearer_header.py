"""Exercise header parsing through real, offline RSA JWT authentication."""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clerk_backend_api import authenticate_request
from clerk_backend_api.security import authenticate_request_async
from clerk_backend_api.security.types import AuthenticateRequestOptions, AuthStatus


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private, public


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("header", ["Bearer {}", "bearer {}", "BEARER {}", "bEaReR {}", "Bearer  {}"])
@pytest.mark.parametrize("condition", ["valid", "expired", "wrong_party", "wrong_signature"])
def test_real_jwt_header(keys, asynchronous, header, condition):
    private, public = keys
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "user_example",
        "iat": now - timedelta(minutes=5),
        "exp": now + timedelta(minutes=5),
        "azp": "https://example.com",
    }
    if condition == "expired":
        claims["exp"] = now - timedelta(minutes=2)
    if condition == "wrong_party":
        claims["azp"] = "https://other.example"
    if condition == "wrong_signature":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, private, algorithm="RS256")
    request = httpx.Request("GET", "https://example.com", headers={"Authorization": header.format(token)})
    options = AuthenticateRequestOptions(jwt_key=public, authorized_parties=["https://example.com"])
    state = (asyncio.run(authenticate_request_async(request, options)) if asynchronous
             else authenticate_request(request, options))
    assert state.status == (AuthStatus.SIGNED_IN if condition == "valid" else AuthStatus.SIGNED_OUT)
    if condition == "valid":
        assert state.token == token
        assert state.payload["sub"] == "user_example"


@pytest.mark.parametrize("authorization,expected", [
    ("Bearer aBearer b", "aBearer b"),
    ("Bearer ", ""),
    ("Basic credentials", "Basic credentials"),
    ("raw-token", "raw-token"),
])
def test_preserve_credentials_and_existing_non_bearer_behavior(authorization, expected):
    from clerk_backend_api.security.authenticaterequest import _get_session_token

    request = httpx.Request("GET", "https://example.com", headers={
        "Authorization": authorization, "cookie": "__session=cookie-token",
    })
    assert _get_session_token(request) == expected


def test_cookie_only_still_works():
    from clerk_backend_api.security.authenticaterequest import _get_session_token

    request = httpx.Request("GET", "https://example.com", headers={"cookie": "__session=cookie-token"})
    assert _get_session_token(request) == "cookie-token"
