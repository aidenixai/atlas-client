"""Credential authorization uses signed endpoint+auth snapshots, never recipe flags."""

import asyncio
import json
import os
import socket
from types import SimpleNamespace

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt

AUTH = {"type": "header", "name": "X-API-Key", "env": "ATLAS_TEST_SOURCE_KEY"}
EP = {"url": "https://api.example/records/{id}"}


@pytest.fixture
def wire(monkeypatch):
    state = SimpleNamespace(seen=[], respond=None)
    monkeypatch.setenv("ATLAS_TEST_SOURCE_KEY", "synthetic-source-key")
    monkeypatch.setenv("ATLAS_TEST_PASSWORD", "synthetic-password")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ],
    )
    rt._LOGIN_CACHE.clear()

    def handle(request):
        state.seen.append(request)
        if state.respond:
            return state.respond(request)
        if request.url.path == "/login":
            return httpx.Response(200, headers={"Authorization": "Bearer synthetic-token"}, json={})
        return httpx.Response(200, json=[{"id": "123"}])

    sync, async_ = httpx.Client, httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: sync(transport=httpx.MockTransport(handle), **kwargs)
    )
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: async_(transport=httpx.MockTransport(handle), **kwargs),
    )
    yield state
    rt._LOGIN_CACHE.clear()


@pytest.mark.parametrize("explicit", [False, True])
def test_unsigned_request_cannot_use_credentials(wire, explicit):
    auth = {"type": "header", "name": "X-API-Key"} if explicit else AUTH
    with pytest.raises(ValueError, match="(?i)signature|credential"):
        rt.run_recipe(EP, auth, {"id": "123"}, api_key="synthetic-explicit" if explicit else None)
    assert not wire.seen


def test_unsigned_request_is_rejected_before_reading_environment(wire, monkeypatch):
    original = os.environ.get

    def read(name, *args):
        if name == AUTH["env"]:
            pytest.fail("Secret read before authorization")
        return original(name, *args)

    monkeypatch.setattr(os.environ, "get", read)
    with pytest.raises(ValueError, match="(?i)signature|credential"):
        rt.run_recipe(EP, AUTH, {"id": "123"})
    assert not wire.seen


@pytest.mark.parametrize("mode", ["header", "query", "path"])
def test_signed_step_sends_key_only_to_fixed_origin(endpoint_signer, wire, mode):
    auth = {**AUTH, "type": mode, "name": "key"}
    endpoint = {"url": "https://api.example/records/{id}" + ("/{key}" if mode == "path" else "")}
    result = rt.run_recipe(endpoint_signer(endpoint, auth), auth, {"id": "123"})
    assert result["count"] == 1
    request = wire.seen[0]
    assert request.url.host == "api.example"
    if mode == "header":
        assert request.headers["key"] == "synthetic-source-key"
    elif mode == "query":
        assert request.url.params["key"] == "synthetic-source-key"
    else:
        assert request.url.path.endswith("/synthetic-source-key")


@pytest.mark.parametrize("field", ["url", "env", "header", "missing", "expired", "flags"])
def test_altered_endpoint_or_auth_cannot_release_key(endpoint_signer, wire, field):
    auth = dict(AUTH)
    ep = endpoint_signer(EP, auth)
    if field == "url":
        ep["url"] = "https://collector.example/records/{id}"
    elif field == "env":
        auth["env"] = "ATLAS_TEST_PASSWORD"
    elif field == "header":
        auth["name"] = "X-Different-Key"
    elif field == "missing":
        ep.pop("signature")
    elif field == "expired":
        ep["signature"]["expires_at"] = 1
    else:
        ep.pop("signature")
        ep.update(verified=True, _credential_origin="https://api.example", code_trust="verified")
    with pytest.raises(ValueError, match="(?i)signature|credential"):
        rt.run_recipe(ep, auth, {"id": "123"})
    assert not wire.seen


@pytest.mark.parametrize(
    "url",
    [
        "https://{host}/records",
        "https://api.example:{port}/records",
        "http://api.example/records",
        "https://user@api.example/records",
    ],
)
def test_credentials_require_literal_https_recipient(endpoint_signer, wire, url):
    ep = endpoint_signer({"url": url}, AUTH)
    with pytest.raises(ValueError, match="(?i)origin|HTTPS|recipient"):
        rt.run_recipe(ep, AUTH, {"host": "collector.example", "port": "8443"})
    assert not wire.seen


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_cannot_forward_key_to_another_origin(endpoint_signer, wire, status):
    wire.respond = lambda request: (
        httpx.Response(status, headers={"Location": "https://collector.example/receive"})
        if request.url.host == "api.example"
        else httpx.Response(200, json=[{}])
    )
    with pytest.raises(ValueError, match="(?i)origin|recipient"):
        rt.run_recipe(endpoint_signer(EP, AUTH), AUTH, {"id": "123"})
    assert [request.url.host for request in wire.seen] == ["api.example"]


def test_same_origin_redirect_and_anonymous_unsigned_still_work(endpoint_signer, wire):
    wire.respond = lambda request: (
        httpx.Response(302, headers={"Location": "/final"})
        if request.url.path != "/final"
        else httpx.Response(200, json=[{}])
    )
    assert rt.run_recipe(endpoint_signer(EP, AUTH), AUTH, {"id": "123"})["count"] == 1
    assert all(request.headers["X-API-Key"] == "synthetic-source-key" for request in wire.seen)
    assert (
        rt.run_recipe({"url": "https://anonymous.example/final"}, {"type": "none"}, {})["count"]
        == 1
    )


def test_unsigned_chain_cannot_reuse_individually_signed_credential_step(endpoint_signer, wire):
    recipe = {
        "kind": "legacy",
        "steps": [{"step": 1, "ep": endpoint_signer(EP, AUTH), "auth": AUTH}],
    }
    with pytest.raises(ValueError, match="(?i)signature|credential"):
        rt.run_chain_recipe(recipe, {"id": "123"}, allow_untrusted_code=True)
    assert not wire.seen


def test_signed_chain_preserves_independent_step_signature(recipe_signer, endpoint_signer, wire):
    ep = endpoint_signer({**EP, "stop_on_http_error": True}, AUTH)
    recipe = recipe_signer(
        {
            "kind": "legacy",
            "code_trust": "verified",
            "code_revision": 1,
            "steps": [{"step": 1, "ep": ep, "auth": AUTH}],
            "edges": [],
        }
    )
    assert rt.run_chain_recipe(recipe, {"id": "123"})["steps"]["step1"]["count"] == 1
    assert len(wire.seen) == 1


def test_signed_login_pins_password_and_token_to_separate_origins(endpoint_signer, wire):
    auth = {
        "type": "header",
        "name": "Authorization",
        "login_url": "https://login.example/login",
        "user": "tester",
        "env": "ATLAS_TEST_PASSWORD",
    }
    ep = endpoint_signer(EP, auth)
    assert rt.run_recipe(ep, auth, {"id": "123"})["count"] == 1
    assert [request.url.host for request in wire.seen] == ["login.example", "api.example"]
    assert json.loads(wire.seen[0].content)["password"] == "synthetic-password"
    assert wire.seen[1].headers["Authorization"] == "Bearer synthetic-token"


def test_login_redirect_cannot_forward_password(endpoint_signer, wire):
    auth = {
        "login_url": "https://login.example/login",
        "user": "tester",
        "env": "ATLAS_TEST_PASSWORD",
    }
    wire.respond = lambda request: (
        httpx.Response(307, headers={"Location": "https://collector.example/receive"})
        if request.url.host == "login.example"
        else httpx.Response(200, json={})
    )
    with pytest.raises(ValueError, match="(?i)origin|recipient"):
        rt.run_recipe(endpoint_signer(EP, auth), auth, {"id": "123"})
    assert [request.url.host for request in wire.seen] == ["login.example"]


def test_async_unsigned_request_cannot_use_key(wire):
    with pytest.raises(ValueError, match="(?i)signature|credential"):
        asyncio.run(rt.arun_recipe(EP, AUTH, {"id": "123"}))
    assert not wire.seen


def test_async_signed_request_rejects_cross_origin_redirect(endpoint_signer, wire):
    wire.respond = lambda request: (
        httpx.Response(307, headers={"Location": "https://collector.example/receive"})
        if request.url.host == "api.example"
        else httpx.Response(200, json=[{}])
    )
    with pytest.raises(ValueError, match="(?i)origin|recipient"):
        asyncio.run(rt.arun_recipe(endpoint_signer(EP, AUTH), AUTH, {"id": "123"}))
    assert len(wire.seen) == 1


@pytest.mark.parametrize("foreign", [False, True])
def test_signed_resource_alternatives_keep_credential_origin(endpoint_signer, wire, foreign):
    target = "https://collector.example/final" if foreign else "https://api.example/final"
    ep = endpoint_signer(
        {"url": "https://api.example/empty", "alternatives": [{"url": target}]}, AUTH
    )
    wire.respond = lambda request: httpx.Response(
        200, json=[] if request.url.path == "/empty" else [{}]
    )
    if foreign:
        with pytest.raises(ValueError, match="(?i)origin|recipient"):
            rt.run_recipe(ep, AUTH, {})
        assert len(wire.seen) == 1
    else:
        assert rt.run_recipe(ep, AUTH, {})["count"] == 1
        assert len(wire.seen) == 2
    assert all(request.url.host == "api.example" for request in wire.seen)


@pytest.mark.parametrize("login", [False, True])
def test_signed_fanout_retains_approved_auth(endpoint_signer, wire, login):
    auth = (
        {"login_url": "https://login.example/login", "env": "ATLAS_TEST_PASSWORD"}
        if login
        else AUTH
    )
    ep = endpoint_signer(
        {
            "url": "https://api.example/records/{item}",
            "fanout": {"url": "https://api.example/records/{item}", "items": ["a", "b"]},
        },
        auth,
    )
    result = rt.run_recipe(ep, auth, {})
    assert result["count"] == 2
    requests = [request for request in wire.seen if request.url.host == "api.example"]
    assert len(requests) == 2
    header = "Authorization" if login else "X-API-Key"
    assert all(
        request.headers[header] == ("Bearer synthetic-token" if login else "synthetic-source-key")
        for request in requests
    )


def test_http_execution_uses_the_verified_copy(endpoint_signer, wire, monkeypatch):
    auth = dict(AUTH)
    ep = endpoint_signer(EP, auth)
    original = rt.verify_recipe_signature

    def verify_then_mutate_caller(document):
        original(document)
        ep["url"] = "https://collector.example/receive"
        auth["env"] = "ATLAS_TEST_PASSWORD"

    monkeypatch.setattr(rt, "verify_recipe_signature", verify_then_mutate_caller)
    rt.run_recipe(ep, auth, {"id": "123"})
    assert wire.seen[0].url.host == "api.example"
    assert wire.seen[0].headers["X-API-Key"] == "synthetic-source-key"


@pytest.mark.parametrize("async_", [False, True])
def test_nested_resource_cannot_disable_tls_with_credentials(endpoint_signer, wire, async_):
    auth = {"type": "none"}
    ep = endpoint_signer(
        {
            "url": "https://api.example/empty",
            "alternatives": [
                {
                    "url": "https://api.example/private",
                    "tls_insecure": True,
                    "static_headers": {"Cookie": "synthetic-session"},
                },
            ],
        },
        auth,
    )
    wire.respond = lambda request: httpx.Response(
        200, json=[] if request.url.path == "/empty" else [{}]
    )
    with pytest.raises(ValueError, match="(?i)HTTPS|TLS"):
        if async_:
            asyncio.run(rt.arun_recipe(ep, auth, {}))
        else:
            rt.run_recipe(ep, auth, {})
    assert len(wire.seen) == 1


def test_unsigned_url_credentials_are_not_anonymous(wire):
    with pytest.raises(ValueError, match="(?i)credential|signature"):
        rt.run_recipe({"url": "https://user:synthetic@api.example/private"}, {"type": "none"}, {})
    assert not wire.seen


def test_login_cache_is_scoped_to_auth_and_recipient(endpoint_signer, wire):
    def respond(request):
        if request.url.host == "login.example":
            password = json.loads(request.content)["password"]
            return httpx.Response(
                200, headers={"Authorization": "Bearer token-" + password}, json={}
            )
        return httpx.Response(200, json=[{}])

    wire.respond = respond
    for host, password in [("first.example", "account-A"), ("second.example", "account-B")]:
        auth = {
            "login_url": "https://login.example/login",
            "user": "same-user",
            "password": password,
        }
        ep = endpoint_signer({"url": "https://" + host + "/data"}, auth)
        rt.run_recipe(ep, auth, {})
    requests = [request for request in wire.seen if request.url.host != "login.example"]
    assert requests[0].headers["Authorization"] == "Bearer token-account-A"
    assert requests[1].headers["Authorization"] == "Bearer token-account-B"
    assert len(wire.seen) == 4


def test_rotated_environment_password_invalidates_cached_token(endpoint_signer, wire, monkeypatch):
    auth = {
        "login_url": "https://login.example/login",
        "user": "same-user",
        "env": "ATLAS_TEST_PASSWORD",
    }
    wire.respond = lambda request: (
        httpx.Response(
            200,
            headers={"Authorization": "Bearer token-" + json.loads(request.content)["password"]},
            json={},
        )
        if request.url.host == "login.example"
        else httpx.Response(200, json=[{}])
    )
    ep = endpoint_signer(EP, auth)
    rt.run_recipe(ep, auth, {"id": "123"})
    monkeypatch.setenv("ATLAS_TEST_PASSWORD", "rotated-synthetic")
    rt.run_recipe(ep, auth, {"id": "123"})
    requests = [request for request in wire.seen if request.url.host == "api.example"]
    assert requests[1].headers["Authorization"] == "Bearer token-rotated-synthetic"
    assert len(wire.seen) == 4
