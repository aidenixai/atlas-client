"""Free-form diagnostics stay local, including errors from valid signed recipes."""
import json

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt


SECRET = "SYNTHETIC_PRIVATE_INPUT"
RECIPE = {"id": "privacy-fixture", "steps": [{"step": 1, "source_id": "fixture.example"}]}


@pytest.mark.parametrize("field", ["error", "reason"])
@pytest.mark.parametrize("diagnostic", [
    "invalid input: " + SECRET,
    {"detail": SECRET},
    [SECRET],
])
def test_report_omits_free_form_diagnostics(field, diagnostic):
    result = {"steps": {"step1": {field: diagnostic, "http": 503, "count": 0}}}
    report = rt.run_report(RECIPE, result, 12)
    step = report["steps"][0]
    assert SECRET not in json.dumps(report)
    assert "error" not in step and "reason" not in step
    assert (step["status"], step["http"], step["records"]) == ("error", 503, 0)
    assert result["steps"]["step1"][field] == diagnostic


def test_signed_connector_error_is_local_but_not_posted(recipe_signer, monkeypatch):
    recipe = recipe_signer({
        "id": "privacy-fixture", "kind": "legacy", "code_trust": "verified", "code_revision": 1,
        "steps": [{"step": 1, "source_id": "fixture.example", "ep": {}, "in": ["value"],
                   "connector_code": "def marker(value):\n raise ValueError('invalid input: ' + value)"}],
        "report": {"url": "https://atlas.aidenix.com/v1/runs/" + "t" * 32},
    })
    posted = []
    monkeypatch.setenv("ATLAS_TELEMETRY", "1")
    monkeypatch.setattr(httpx, "post", lambda url, **kwargs:
                        posted.append(kwargs["json"]) or httpx.Response(204))
    result = rt.run_chain_recipe(recipe, {"value": SECRET})
    assert SECRET in result["steps"]["step1"]["error"]
    assert len(posted) == 1
    assert SECRET not in json.dumps(posted)
    assert "error" not in posted[0]["steps"][0]
    assert posted[0]["steps"][0]["status"] == "error"


def test_blocked_and_skipped_diagnostics_are_not_reported():
    recipe = {"steps": [{"step": 1}, {"step": 2}]}
    result = {"bundle": {"code_blocked": {"reason": SECRET}}, "steps": {
        "step1": {"code_blocked": True, "error": SECRET},
        "step2": {"skipped": True, "reason": SECRET},
    }}
    report = rt.run_report(recipe, result)
    assert report["outcome"] == "blocked"
    assert [step["status"] for step in report["steps"]] == ["blocked", "skipped"]
    assert SECRET not in json.dumps(report)
