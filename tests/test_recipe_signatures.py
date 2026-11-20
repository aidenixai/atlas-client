"""Offline signature checks. The key below is ephemeral and never trusted in production."""

import base64
import hashlib
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aidenix_atlas import _recipe_runtime as rt
from aidenix_atlas import fetch


def recipe():
    return {
        "id": "fixture",
        "runnable": True,
        "kind": "legacy",
        "code_trust": "verified",
        "code_revision": 4,
        "returns_outputs": ["rows"],
        "steps": [
            {
                "step": 1,
                "ep": {},
                "in": ["q"],
                "out_map": {"rows": "[]"},
                "connector_code": "def lookup(q):\n return [{'value': q}]",
            }
        ],
        "edges": [],
    }


@pytest.fixture
def signer(monkeypatch):
    monkeypatch.setenv("ATLAS_TELEMETRY", "0")
    monkeypatch.delenv("ATLAS_RECIPE_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("ATLAS_ALLOW_UNTRUSTED_CODE", raising=False)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    kid = hashlib.sha256(public).hexdigest()[:16]
    monkeypatch.setattr(rt, "RECIPE_PUBLIC_KEYS", {kid: base64.b64encode(public).decode()})

    def sign(doc):
        issued = int(time.time())
        meta = {
            "version": 1,
            "algorithm": "Ed25519",
            "key_id": kid,
            "issued_at": issued,
            "expires_at": issued + 86400,
        }
        value = base64.b64encode(key.sign(rt.recipe_signature_message(doc, meta))).decode()
        return {**doc, "signature": {**meta, "value": value}}

    return sign


@pytest.fixture
def signed(signer):
    return signer(recipe())


def test_forged_verified_metadata_is_not_permission(monkeypatch):
    monkeypatch.delenv("ATLAS_ALLOW_UNTRUSTED_CODE", raising=False)
    result = rt.run_chain_recipe(recipe(), {"q": "value"}, allow_untrusted_code=False)
    assert result["steps"]["step1"]["code_blocked"] is True


def test_valid_signature_runs_after_json_roundtrip(signed):
    wire = json.loads(json.dumps(signed, sort_keys=True))
    assert rt.run_chain_recipe(wire, {"q": "value"})["bundle"]["rows"] == [{"value": "value"}]


@pytest.mark.parametrize(
    "field", ["code", "edges", "ep", "auth", "trust", "revision", "signature", "gates", "report"]
)
def test_tampering_is_rejected_even_with_explicit_allow(signed, monkeypatch, field):
    if field == "code":
        signed["steps"][0]["connector_code"] += "\n# tampered"
    elif field == "edges":
        signed["edges"].append({"to_step": 1, "code": "pass"})
    elif field in ("ep", "auth"):
        signed["steps"][0][field] = {"url": "https://changed.invalid/"}
    elif field == "trust":
        signed["code_trust"] = "draft"
    elif field == "revision":
        signed["code_revision"] += 1
    elif field == "signature":
        signed["signature"]["value"] = base64.b64encode(b"x" * 64).decode()
    elif field == "gates":
        signed["step_gates"] = []
    else:
        signed["report"] = {"url": "https://changed.invalid/"}
    monkeypatch.setattr(rt, "run_recipe", lambda *a, **k: pytest.fail("HTTP reached"))
    monkeypatch.setattr(rt, "_run_connector_step", lambda *a: pytest.fail("exec reached"))
    with pytest.raises(ValueError, match="recipe signature"):
        rt.run_chain_recipe(signed, {}, allow_untrusted_code=True)


def test_unknown_key_and_expired_signature(signed, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: signed["signature"]["expires_at"] + 1)
    with pytest.raises(ValueError, match="expired"):
        rt.run_chain_recipe(signed, {})
    monkeypatch.setattr(rt, "RECIPE_PUBLIC_KEYS", {})
    with pytest.raises(ValueError, match="signature key"):
        rt.run_chain_recipe(signed, {})


def test_fetch_verifies_recipe_from_api(signed, monkeypatch):
    def get(url, **kwargs):
        return httpx.Response(200, json=signed, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", get)
    assert fetch("fixture", {"q": "api"}, api_key="fake")["data"]["bundle"]["rows"] == [
        {"value": "api"}
    ]
    signed["steps"][0]["connector_code"] += "\n# tampered"
    with pytest.raises(ValueError, match="recipe signature"):
        fetch("fixture", {}, api_key="fake")


def test_unsigned_local_recipe_can_be_explicitly_allowed():
    assert rt.run_chain_recipe(recipe(), {"q": "local"}, allow_untrusted_code=True)["bundle"][
        "rows"
    ] == [{"value": "local"}]


@pytest.mark.parametrize("entrypoint", ["attempt", "fallback"])
@pytest.mark.parametrize("delivery", ["embedded", "resolve"])
@pytest.mark.parametrize(
    "endpoints",
    [
        [{"url": "https://changed.invalid/"}],
        {"url": "https://changed.invalid/"},
    ],
)
def test_signed_recipe_cannot_switch_to_endpoint_dispatch(
    signer,
    monkeypatch,
    entrypoint,
    delivery,
    endpoints,
):
    signed = signer(recipe())
    signed["endpoints"] = endpoints
    calls = []

    def execute(*args, **kwargs):
        calls.append(args)
        return {"records": [{"value": "must not run"}]}

    monkeypatch.setattr(rt, "run_recipe", execute)
    payload = {
        "plan": {"steps": [{"source_id": "fixture", "kind": "chain"}]},
        "recipes": {"fixture": signed} if delivery == "embedded" else {},
    }
    attempts = rt.attempts_from_payload(payload, resolve=lambda ref: signed)
    if entrypoint == "attempt":
        with pytest.raises(ValueError, match="recipe signature"):
            rt.execute_attempt(attempts[0], allow_untrusted_code=True)
    else:
        result = rt.run_with_fallback(attempts, allow_untrusted_code=True)
        assert result["chosen"] is None
        assert result["attempts"][0]["code"] == "ValueError"
    assert not calls


@pytest.mark.parametrize("entrypoint", ["attempt", "fallback"])
def test_endpoint_dispatch_executes_verified_snapshot(signer, monkeypatch, entrypoint):
    signed = signer(
        {
            "code_trust": "verified",
            "code_revision": 1,
            "endpoints": [{"url": "https://original.invalid/"}],
        }
    )
    original_verify = rt.verify_recipe_signature
    checked = []

    def verify_then_mutate_caller(snapshot):
        original_verify(snapshot)
        checked.append(True)
        signed["endpoints"][0]["url"] = "https://changed.invalid/"

    monkeypatch.setattr(rt, "verify_recipe_signature", verify_then_mutate_caller)
    monkeypatch.setattr(rt, "run_recipe", lambda ep, *a, **k: {"raw": {"url": ep["url"]}})
    attempt = {"recipe": signed}
    if entrypoint == "attempt":
        result = rt.execute_attempt(attempt)
    else:
        result = rt.run_with_fallback([attempt])["result"]
    assert result["raw"]["url"] == "https://original.invalid/"
    assert checked
