"""fetch() returns per-step provenance and freshness, not empty placeholders."""
import httpx

import aidenix_atlas

RECIPE = {"id": "demo", "runnable": True, "code_trust": "verified", "code_revision": 3,
          "steps": [{"step": 1, "source_id": "a.example", "slug": "a-1"},
                    {"step": 2, "source_id": "b.example", "slug": "b-1", "optional": True}],
          "step_gates": [{"step": 1, "proven": True, "last_verified_at": "2026-11-03T05:53:51+01:00",
                          "verified_until": "2026-12-03T05:53:51+01:00"},
                         {"step": 2, "proven": True, "last_verified_at": "2026-11-06T15:36:01+01:00",
                          "verified_until": "2026-12-06T15:36:01+01:00"}]}
RUN = {"bundle": {"x": 1}, "fetched_at": "2026-11-15T09:00:00Z",
       "steps": {"step1": {"count": 20, "truncated": True, "fetched_at": "2026-11-15T08:59:58Z"},
                 "step2": {"count": None, "error": "HTTP 503"}}}


def _fetch(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json=RECIPE, request=httpx.Request("GET", "https://x")))
    monkeypatch.setattr(aidenix_atlas, "run_chain_recipe", lambda *a, **k: RUN)
    return aidenix_atlas.fetch("demo", {"q": 1}, api_key="k")


def test_provenance_lists_each_step_with_its_source_and_run(monkeypatch):
    out = _fetch(monkeypatch)
    first, second = out["provenance"]
    assert (first["source_id"], first["records"], first["truncated"], first["proven"]) == ("a.example", 20, True, True)
    assert first["fetched_at"] == "2026-11-15T08:59:58Z" and first["verified_until"].startswith("2026-12-03")
    assert second["optional"] is True and second["error"] == "HTTP 503"


def test_freshness_summarises_verification_and_failures(monkeypatch):
    fresh = _fetch(monkeypatch)["freshness"]
    assert fresh["fetched_at"] == "2026-11-15T09:00:00Z"
    assert fresh["oldest_verification"].startswith("2026-11-03") and fresh["newest_verification"].startswith("2026-11-06")
    assert fresh["all_steps_proven"] is True
    assert fresh["failed_steps"] == []  # the failed step is optional


def test_record_count_reads_a_connector_object():
    assert aidenix_atlas._record_count({"count": None, "raw": {"records": [1, 2, 3]}}) == 3
    assert aidenix_atlas._record_count({"count": 0}) == 0
    assert aidenix_atlas._record_count({"raw": {"total": 5}}) is None
