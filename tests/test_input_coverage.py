"""Unit: input_coverage preflight (canonical input contract).

Guards against a planner parameter silently getting lost: an unknown input must land
in `unbound`, not vanish inside `_build_args`. Pure unit test, no database or network.
"""
from aidenix_atlas._recipe_runtime import input_coverage


def test_socrata_company_name_unbound_by_default():
    """A Socrata endpoint accepts $q/$where; the planner gave company_name, so it is UNBOUND."""
    ep = {"url": "https://data.delaware.gov/resource/5zy2-grhr.json",
          "params_passthrough": ["$where", "$q", "$select", "$limit"]}
    cov = input_coverage(ep, {"company_name": "Acme"})
    assert cov["unbound"] == ["company_name"]
    assert cov["consumed"] == []
    assert cov["coverage"] == 0.0


def test_socrata_company_name_bound_via_alias():
    """Same endpoint plus param_aliases company_name→$q: the parameter is CONSUMED, unbound is empty."""
    ep = {"url": "https://data.delaware.gov/resource/5zy2-grhr.json",
          "params_passthrough": ["$where", "$q", "$select", "$limit"],
          "param_aliases": {"company_name": "$q"}}
    cov = input_coverage(ep, {"company_name": "Acme"})
    assert cov["consumed"] == ["company_name"]
    assert cov["unbound"] == []
    assert cov["coverage"] == 1.0


def test_path_param_consumed():
    """Path token {cik} is filled from params: consumed, not unbound."""
    ep = {"url": "https://data.sec.gov/submissions/CIK{cik}.json", "params_passthrough": []}
    cov = input_coverage(ep, {"cik": "0000320193"})
    assert cov["consumed"] == ["cik"]
    assert cov["unbound"] == []


def test_direct_passthrough_consumed():
    ep = {"url": "https://company.clearbit.com/v1/domains/find", "params_passthrough": ["query"]}
    cov = input_coverage(ep, {"query": "acme"})
    assert cov["consumed"] == ["query"]
    assert cov["unbound"] == []


def test_partial_coverage_flags_only_unbound():
    """$q is bound, date_range is not: coverage is partial, unbound lists just that one."""
    ep = {"url": "https://data.ny.gov/resource/n9v6-gdp6.json", "params_passthrough": ["$q", "$limit"]}
    cov = input_coverage(ep, {"$q": "acme", "date_range": "2020..2024"})
    assert cov["consumed"] == ["$q"]
    assert cov["unbound"] == ["date_range"]
    assert 0.0 < cov["coverage"] < 1.0


def test_empty_and_underscore_keys_ignored():
    """Service `_` keys and empty values are not user input: coverage 1.0."""
    ep = {"url": "https://x.example/api", "params_passthrough": ["q"]}
    cov = input_coverage(ep, {"_hint": "x", "company_name": "", "q": None})
    assert cov == {"consumed": [], "unbound": [], "coverage": 1.0}
