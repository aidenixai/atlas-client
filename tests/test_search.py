"""search() asks the hosted index which chain answers a task; fetch() runs it."""
import httpx

import aidenix_atlas


def _post(body, status=200):
    def post(url, json=None, headers=None, timeout=None):
        assert url.endswith("/v1/search") and headers["Authorization"] == "Bearer k" and json["query"]
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))
    return post


ROUTE = {"results": [{"id": "example-company-group", "kind": "chain", "score": 1.05},
                     {"id": "example-company-profile", "kind": "chain", "score": 0.6}],
         "route": {"abstain": False, "abstain_reason": "", "confidence": 0.83,
                   "steps": [{"step": 1, "kind": "chain", "id": "example-company-group",
                              "params": {"company_name": "Siemens Aktiengesellschaft"}}]}}


def test_search_returns_the_route_and_its_inputs(monkeypatch):
    monkeypatch.setattr(httpx, "post", _post(ROUTE))
    out = aidenix_atlas.search("LEI and subsidiaries of Siemens Aktiengesellschaft", api_key="k")
    assert (out["id"], out["inputs"], out["abstain"]) == (
        "example-company-group", {"company_name": "Siemens Aktiengesellschaft"}, False)
    assert [c["id"] for c in out["candidates"]] == ["example-company-group", "example-company-profile"]


def test_abstain_gives_no_route_even_with_candidates(monkeypatch):
    body = {"results": [{"id": "example-regulation-chain", "kind": "chain"}],
            "route": {"abstain": True, "abstain_reason": "no chain with valid inputs", "steps": []}}
    monkeypatch.setattr(httpx, "post", _post(body))
    out = aidenix_atlas.search("FDA 510(k) clearances for glucose monitors", api_key="k")
    assert out["id"] is None and out["inputs"] == {} and out["reason"] == "no chain with valid inputs"
    assert out["candidates"][0]["id"] == "example-regulation-chain"


def test_missing_and_rejected_key(monkeypatch):
    monkeypatch.delenv("ATLAS_API_KEY", raising=False)
    assert "API key required" in aidenix_atlas.search("x")["reason"]
    monkeypatch.setattr(httpx, "post", _post({}, 401))
    assert aidenix_atlas.search("x", api_key="k")["reason"] == "API key rejected (401)"
