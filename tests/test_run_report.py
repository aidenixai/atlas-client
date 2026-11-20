"""Client runner reports whether an issued chain recipe worked — outcome only, never data."""


import httpx


from aidenix_atlas import _recipe_runtime as rt

RECIPE = {"id": "demo", "kind": "legacy", "returns_outputs": ["registration", "filings"],
          "steps": [{"step": 1, "source_id": "a.example"},
                    {"step": 2, "source_id": "b.example", "optional": True}],
          "report": {"url": "https://atlas.aidenix.com/v1/runs/" + "t" * 32}}


def run(step1, step2=None, bundle=None):
    return {"bundle": bundle or {}, "steps": {"step1": step1, **({"step2": step2} if step2 else {})}}


def test_full_answer_is_ok_and_carries_no_inputs_or_data():
    result = run({"records": [{"name": "Secret Co"}], "count": 1, "http": 200},
                 {"records": [], "count": 0},
                 {"registration": {"name": "Secret Co"}, "filings": [1]})
    report = rt.run_report(RECIPE, result, 120)
    assert report["outcome"] == "ok" and report["outputs_filled"] == ["registration", "filings"]
    assert [s["status"] for s in report["steps"]] == ["ok", "empty"]
    assert "Secret Co" not in repr(report)


def test_outcomes_partial_failed_blocked_empty():
    assert rt.run_report(RECIPE, run({"count": 3, "records": [1, 2, 3]}, None, {"registration": 1}))["outcome"] == "partial"
    failed = rt.run_report(RECIPE, run({"error": "HTTP 503: https://a.example/x?q=Secret", "http": 503}))
    assert failed["outcome"] == "failed" and failed["steps"][0]["http"] == 503
    assert "error" not in failed["steps"][0]
    blocked = rt.run_report(RECIPE, run({"code_blocked": True, "error": "x"}, None, {"code_blocked": {"edges": 1}}))
    assert blocked["outcome"] == "blocked"
    assert rt.run_report(RECIPE, run({"count": 0, "records": []}, {"skipped": True}))["outcome"] == "empty"


def test_send_posts_to_recipe_address_and_respects_opt_out(monkeypatch):
    sent = []
    monkeypatch.setattr(httpx, "post", lambda url, **kwargs: sent.append((url, kwargs["json"])) or httpx.Response(204))
    result = run({"count": 1, "records": [1]})
    assert rt.send_run_report(RECIPE, result, 5) is True and sent[0][0] == RECIPE["report"]["url"]
    monkeypatch.setenv("ATLAS_TELEMETRY", "0")
    assert rt.send_run_report(RECIPE, result) is False and len(sent) == 1
    monkeypatch.delenv("ATLAS_TELEMETRY")
    assert rt.send_run_report({**RECIPE, "report": None}, result) is False
    assert rt.send_run_report({**RECIPE, "report": {"url": "http://plain"}}, result) is False


def test_send_failure_is_silent(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(httpx, "post", boom)
    assert rt.send_run_report(RECIPE, run({"count": 1, "records": [1]})) is False


def test_chain_runner_sends_report_once(monkeypatch):
    calls = []
    monkeypatch.setattr(rt, "_run_chain_legacy", lambda recipe, seed, allow: run({"count": 1, "records": [1]}))
    monkeypatch.setattr(rt, "send_run_report", lambda recipe, result, ms: calls.append(recipe["id"]))
    rt.run_chain_recipe(RECIPE, {})
    assert calls == ["demo"]
