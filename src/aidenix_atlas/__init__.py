"""Aidenix Atlas client runtime.

Atlas returns recipes — where a data source lives and how to call it. This package runs those
recipes on your machine, with your own credentials. Data goes from the source straight to you.

``run_recipe(ep, auth, params)``     — run one source endpoint.
``run_chain_recipe(recipe, seed)``   — run a multi-step chain recipe (no LLM, deterministic).
``run_with_fallback(attempts, ...)`` — try a route step and its alternates until one returns data.
``search(task)``                    — ask atlas.aidenix.com which chain answers a task (your API key).
``fetch(id, seed)``                  — get a chain recipe from atlas.aidenix.com with your API key
                                       and run it here.
"""
from __future__ import annotations

from . import _recipe_runtime  # noqa: F401 — chain bootstraps import the runtime under this name
from ._recipe_runtime import (attempt_outcome, attempts_from_payload, run_chain_recipe, run_recipe,
                              run_with_fallback, seed_seen, seed_values_of)

__version__ = "0.9.5"

DEFAULT_PUBLIC_URL = "https://atlas.aidenix.com"


def _key_and_base(api_url, api_key):
    import os

    base = (api_url or os.environ.get("ATLAS_PUBLIC_URL") or DEFAULT_PUBLIC_URL).rstrip("/")
    return base, api_key or os.environ.get("ATLAS_API_KEY")


def search(task: str, *, top: int = 3, api_url: str | None = None, api_key: str | None = None,
           timeout: float = 90.0) -> dict:
    """Ask Atlas which chain answers a task: ``POST {api_url}/v1/search`` with your personal key.

    Returns ``{id, inputs, abstain, reason, confidence, candidates}``. ``id`` and ``inputs`` are the
    selected route — pass them to ``fetch(id, inputs)``. When Atlas abstains, ``id`` is None and
    ``reason`` says why; ``candidates`` are only nearby chains, not an answer. Uses one request
    from your monthly allowance."""
    import httpx

    base, key = _key_and_base(api_url, api_key)
    empty = {"id": None, "inputs": {}, "abstain": True, "reason": None, "confidence": None, "candidates": []}
    if not key:
        return {**empty, "reason": "personal API key required: pass api_key= or set ATLAS_API_KEY"}
    r = httpx.post(f"{base}/v1/search", json={"query": task, "top": top},
                   headers={"Authorization": f"Bearer {key}"}, timeout=timeout)
    if r.status_code in (401, 403):
        return {**empty, "reason": f"API key rejected ({r.status_code})"}
    if r.status_code == 429:
        return {**empty, "reason": "request allowance or rate limit reached (429)"}
    r.raise_for_status()
    body = r.json()
    route = body.get("route") or {}
    chosen = next((s for s in route.get("steps") or [] if s.get("kind") == "chain" and s.get("id")), None)
    candidates = [{"id": c.get("id"), "kind": c.get("kind"), "score": c.get("score")}
                  for c in body.get("results") or [] if c.get("id")]
    abstain = bool(route.get("abstain")) or chosen is None
    return {"id": None if abstain else chosen["id"],
            "inputs": {} if abstain else dict(chosen.get("params") or {}),
            "abstain": abstain, "reason": route.get("abstain_reason") or None,
            "confidence": route.get("confidence"), "candidates": candidates}


def _record_count(run: dict):
    """Records in a step result: the runner's count, or the `records` list a connector object carries."""
    if type(run.get("count")) is int:
        return run["count"]
    if isinstance(run.get("records"), list):
        return len(run["records"])
    raw = run.get("raw")
    return len(raw["records"]) if isinstance(raw, dict) and isinstance(raw.get("records"), list) else None


def _provenance(recipe: dict, data: dict) -> tuple[list, dict]:
    """Per-step provenance and freshness from the recipe's step gates and this run.

    The recipe says which source each step uses and when Atlas last verified it; the run says
    when each response arrived, how many records it held and whether the step failed."""
    gates = {g.get("step"): g for g in recipe.get("step_gates") or [] if isinstance(g, dict)}
    steps = (data or {}).get("steps") or {}
    provenance, verified = [], []
    for cfg in recipe.get("steps") or []:
        n = cfg.get("step")
        gate, run = gates.get(n) or {}, steps.get(f"step{n}") or {}
        if gate.get("last_verified_at"):
            verified.append(str(gate["last_verified_at"]))
        provenance.append({
            "step": n, "source_id": cfg.get("source_id"), "slug": cfg.get("slug"),
            "optional": bool(cfg.get("optional")), "proven": gate.get("proven"),
            "last_verified_at": gate.get("last_verified_at"), "verified_until": gate.get("verified_until"),
            "fetched_at": run.get("fetched_at"), "records": _record_count(run),
            "truncated": bool(run.get("truncated")), "error": run.get("error") or run.get("reason"),
        })
    freshness = {
        "fetched_at": (data or {}).get("fetched_at"),
        "oldest_verification": min(verified) if verified else None,
        "newest_verification": max(verified) if verified else None,
        "all_steps_proven": bool(provenance) and all(p["proven"] is True for p in provenance),
        "failed_steps": [p["step"] for p in provenance if p["error"] and not p["optional"]],
    }
    return provenance, freshness


def fetch(id_: str, seed: dict | None = None, api_url: str | None = None, *,
          api_key: str | None = None, allow_untrusted_code: bool | None = None, timeout: float = 30.0) -> dict:
    """Chain id + seed → {id, data, provenance, freshness}.

    The recipe comes from ``GET {api_url}/v1/recipes/{id}?runnable=true`` with your personal key
    (``api_key`` or env ``ATLAS_API_KEY``; base URL ``api_url`` or env ``ATLAS_PUBLIC_URL``, default
    https://atlas.aidenix.com) and runs locally with ``run_chain_recipe``."""
    from urllib.parse import quote

    import httpx

    base, key = _key_and_base(api_url, api_key)
    empty = {"id": id_, "data": None, "provenance": [], "freshness": {}}
    if not key:
        return {**empty, "error": "personal API key required: pass api_key= or set ATLAS_API_KEY"}
    r = httpx.get(f"{base}/v1/recipes/{quote(id_, safe='')}", params={"runnable": "true"},
                  headers={"Authorization": f"Bearer {key}"}, timeout=timeout)
    if r.status_code == 404:
        return {**empty, "error": f"{id_}: recipe not found"}
    if r.status_code in (401, 403):
        return {**empty, "error": f"{id_}: API key rejected ({r.status_code})"}
    r.raise_for_status()
    recipe = r.json()
    if not recipe.get("runnable") or not recipe.get("steps"):
        return {**empty, "error": f"{id_}: not a runnable chain (single sources: use run_recipe with the recipe endpoint)"}
    data = run_chain_recipe(recipe, dict(seed or {}), allow_untrusted_code=allow_untrusted_code)
    provenance, freshness = _provenance(recipe, data)
    out = {"id": recipe.get("id") or id_, "data": data, "provenance": provenance, "freshness": freshness,
           "code_revision": recipe.get("code_revision"), "code_trust": recipe.get("code_trust")}
    if recipe.get("executable") is False:
        out["warnings"] = [{"type": "not_executable", "detail": recipe.get("executable_reason")}]
    return out


__all__ = ["run_recipe", "run_chain_recipe", "run_with_fallback", "attempts_from_payload", "attempt_outcome",
           "seed_values_of", "seed_seen", "search", "fetch"]
