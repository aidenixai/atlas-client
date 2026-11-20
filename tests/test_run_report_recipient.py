"""Untrusted recipes cannot choose the telemetry recipient or redirect it elsewhere."""
from types import SimpleNamespace

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt


TOKEN = "aB0_-" + "t" * 27
REPORT_URL = "https://atlas.aidenix.com/v1/runs/" + TOKEN


@pytest.fixture
def report_wire(monkeypatch):
    state = SimpleNamespace(requests=[], options=[], status=204, location=None)
    monkeypatch.setenv("ATLAS_TELEMETRY", "1")

    def handle(request):
        state.requests.append(request)
        headers = {"Location": state.location} if state.location else {}
        return httpx.Response(state.status, headers=headers)

    def post(url, **kwargs):
        state.options.append(kwargs)
        with httpx.Client(transport=httpx.MockTransport(handle), trust_env=False) as client:
            return client.post(url, **kwargs)

    monkeypatch.setattr(httpx, "post", post)
    return state


@pytest.mark.parametrize("url", [
    REPORT_URL,
    REPORT_URL.replace("atlas.aidenix.com", "ATLAS.AIDENIX.COM"),
    REPORT_URL.replace("atlas.aidenix.com", "atlas.aidenix.com:443"),
])
def test_only_atlas_report_endpoint_receives_summary(report_wire, url):
    assert rt.send_run_report({"report": {"url": url}}, {"steps": {}}, 12)
    assert [str(request.url) for request in report_wire.requests] == [REPORT_URL]
    assert report_wire.requests[0].method == "POST"
    assert report_wire.options[0]["follow_redirects"] is False


@pytest.mark.parametrize("url", [
    "https://collector.example/v1/runs/" + TOKEN,
    "https://atlas.aidenix.com.collector.example/v1/runs/" + TOKEN,
    "https://sub.atlas.aidenix.com/v1/runs/" + TOKEN,
    "https://127.0.0.1:9443/internal",
    "https://[::1]/v1/runs/" + TOKEN,
    "https://169.254.169.254/v1/runs/" + TOKEN,
    REPORT_URL.replace("https:", "http:"),
    REPORT_URL.replace("atlas.aidenix.com", "atlas.aidenix.com:8443"),
    REPORT_URL.replace("atlas.aidenix.com", "atlas.aidenix.com."),
    REPORT_URL.replace("atlas.aidenix.com", "user:password@atlas.aidenix.com"),
    "https://atlas.aidenix.com@collector.example/v1/runs/" + TOKEN,
    "https://collector.example/https://atlas.aidenix.com/v1/runs/" + TOKEN,
    REPORT_URL.replace("/v1/runs/", "/account/"),
    REPORT_URL.replace("/v1/runs/", "/v1/runs/../runs/"),
    REPORT_URL + "?recipient=collector.example",
    REPORT_URL + "#fragment",
    REPORT_URL + "/extra",
    REPORT_URL[:-1],
    REPORT_URL + "t",
    REPORT_URL.replace(TOKEN, "%61" + TOKEN[1:]),
    "https://atlas.aidenix.com:invalid/v1/runs/" + TOKEN,
    "https://[invalid/v1/runs/" + TOKEN,
    None,
    123,
])
def test_invalid_report_recipient_never_reaches_http(report_wire, url):
    assert rt.send_run_report({"report": {"url": url}}, {}) is False
    assert report_wire.options == []
    assert report_wire.requests == []


@pytest.mark.parametrize("report", [None, {}, "https://collector.example", [REPORT_URL]])
def test_malformed_report_is_ignored(report_wire, report):
    assert rt.send_run_report({"report": report}, {}) is False
    assert report_wire.requests == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_report_redirect_is_never_followed(report_wire, status):
    report_wire.status = status
    report_wire.location = "https://collector.example/receive"
    assert rt.send_run_report({"report": {"url": REPORT_URL}}, {}) is False
    assert [str(request.url) for request in report_wire.requests] == [REPORT_URL]
    assert report_wire.options[0]["follow_redirects"] is False


@pytest.mark.parametrize("url,expected_requests", [(REPORT_URL, 1),
                                                   ("https://collector.example/report", 0)])
def test_unsigned_chain_keeps_result_when_report_is_refused(
    report_wire, monkeypatch, url, expected_requests,
):
    result = {"bundle": {"answer": 42}, "steps": {}}
    monkeypatch.setattr(rt, "_run_chain_legacy", lambda *args: result)
    recipe = {"id": "demo", "kind": "legacy", "steps": [], "report": {"url": url}}
    assert rt.run_chain_recipe(recipe, {})["bundle"]["answer"] == 42
    assert len(report_wire.requests) == expected_requests
