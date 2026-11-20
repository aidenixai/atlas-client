"""A recipe runs on the client side: the runner never calls addresses inside its network."""
import asyncio
import socket

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt


@pytest.fixture(autouse=True)
def strict(monkeypatch):
    monkeypatch.delenv("ATLAS_ALLOW_PRIVATE_ADDRESSES", raising=False)
    monkeypatch.delenv("ATLAS_PROXY_URL", raising=False)


def dns(monkeypatch, mapping):
    def fake(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], port or 443))]
    monkeypatch.setattr(socket, "getaddrinfo", fake)


def no_network(monkeypatch, seen):
    real = httpx.HTTPTransport.handle_request

    def handle(self, request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"items": [{"a": 1}]}, request=request)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    return real


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin", "http://localhost:8090/x", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "http://192.168.1.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "http://0.0.0.0/", "http://db.internal/", "http://printer.local/",
])
def test_private_literal_and_local_names_are_refused(url):
    assert rt.address_refusal(url)


def test_public_address_passes(monkeypatch):
    dns(monkeypatch, {"api.example.org": "93.184.216.34"})
    assert rt.address_refusal("https://api.example.org/v1") is None
    assert rt.address_refusal("https://8.8.8.8/") is None


def test_name_resolving_to_private_is_refused(monkeypatch):
    dns(monkeypatch, {"evil.example.org": "10.1.2.3"})
    assert "non-public" in rt.address_refusal("https://evil.example.org/")


def test_behind_proxy_names_are_not_resolved_locally(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("resolved locally"))
    assert rt.address_refusal("https://api.example.org/", resolve=False) is None
    assert rt.address_refusal("http://127.0.0.1/", resolve=False)


def test_run_recipe_never_sends_request_to_private_address(monkeypatch):
    seen = []
    no_network(monkeypatch, seen)
    with pytest.raises(httpx.RequestError, match="refused"):
        rt.run_recipe({"url": "http://169.254.169.254/latest/meta-data/"}, {}, {})
    assert seen == []


def test_redirect_to_private_address_is_refused(monkeypatch):
    dns(monkeypatch, {"api.example.org": "93.184.216.34"})
    seen = []

    def handle(self, request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:6379/"}, request=request)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    with pytest.raises(httpx.RequestError, match="refused"):
        rt.run_recipe({"url": "https://api.example.org/v1"}, {}, {})
    assert seen == ["https://api.example.org/v1"]


def test_async_runner_refuses_private_address(monkeypatch):
    async def handle(self, request):
        pytest.fail("request was sent")
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", handle)
    with pytest.raises(httpx.RequestError, match="refused"):
        asyncio.run(rt.arun_recipe({"url": "http://10.0.0.7/"}, {}, {}))


def test_public_recipe_still_runs(monkeypatch):
    dns(monkeypatch, {"api.example.org": "93.184.216.34"})
    seen = []
    no_network(monkeypatch, seen)
    out = rt.run_recipe({"url": "https://api.example.org/v1", "response_path": "items"}, {}, {})
    assert out["count"] == 1 and seen == ["https://api.example.org/v1"]


def test_ftp_to_private_address_is_refused(monkeypatch):
    dns(monkeypatch, {"files.example.org": "192.168.0.10"})
    with pytest.raises(httpx.RequestError, match="refused"):
        rt.run_recipe({"url": "ftp://files.example.org/pub/a.csv"}, {}, {})


def test_explicit_opt_in_allows_private(monkeypatch):
    monkeypatch.setenv("ATLAS_ALLOW_PRIVATE_ADDRESSES", "1")
    assert rt.address_refusal("http://127.0.0.1/") is None
