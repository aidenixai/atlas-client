"""Ephemeral test roots; tests exercise the installed wheel without source-path injection."""

import base64
import copy
import hashlib
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aidenix_atlas import _recipe_runtime as rt


@pytest.fixture
def recipe_signer(monkeypatch):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    kid = hashlib.sha256(public).hexdigest()[:16]
    monkeypatch.setattr(rt, "RECIPE_PUBLIC_KEYS", {kid: base64.b64encode(public).decode()})
    monkeypatch.delenv("ATLAS_RECIPE_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("ATLAS_ALLOW_UNTRUSTED_CODE", raising=False)
    monkeypatch.setenv("ATLAS_TELEMETRY", "0")

    def sign(document):
        document = copy.deepcopy(document)
        issued = int(time.time())
        meta = {
            "version": 1,
            "algorithm": "Ed25519",
            "key_id": kid,
            "issued_at": issued,
            "expires_at": issued + 86400,
        }
        value = base64.b64encode(key.sign(rt.recipe_signature_message(document, meta))).decode()
        return {**document, "signature": {**meta, "value": value}}

    return sign


@pytest.fixture
def endpoint_signer(recipe_signer):
    def sign(ep, auth):
        clean = {k: v for k, v in ep.items() if k != "signature"}
        document = recipe_signer({"type": "http_step", "ep": clean, "auth": auth})
        return {**document["ep"], "signature": document["signature"]}

    return sign
