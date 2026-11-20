"""Chain executors stay local across parallel, nested and failed runs."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from aidenix_atlas import _recipe_runtime as rt

INSTALL = """
from aidenix_atlas import _recipe_runtime as rt
original = rt.run_recipe
def run_recipe(ep, auth, params, api_key=None, proxy_url=None):
    raise ValueError("bounded stream timeout must be positive and at most 60 seconds")
rt.run_recipe = run_recipe
rt._curated_helper = lambda: None
ctx["installed"] = rt.run_recipe is not original
"""


def recipe(code):
    return {"id": "curated", "kind": "legacy", "steps": [],
            "edges": [{"from_step": 0, "to_step": 1, "to_field": "installed", "code": code}]}


def test_wire_patch_is_undone_after_the_chain(monkeypatch):
    monkeypatch.setattr(rt, "send_run_report", lambda *a, **k: False)
    original, step = rt.run_recipe, rt._run_step
    rt.run_chain_recipe(recipe(INSTALL), {}, allow_untrusted_code=True)
    assert rt.run_recipe is original and rt._run_step is step
    assert not hasattr(rt, "_curated_helper")


@pytest.mark.parametrize('runtime_import', [
    'from aidenix_atlas import _recipe_runtime as rt',
    'import aidenix_atlas._recipe_runtime as rt',
])
def test_parallel_chains_keep_their_own_executors(monkeypatch, runtime_import):
    monkeypatch.setattr(rt, "send_run_report", lambda *a, **k: False)
    monkeypatch.setattr(rt, '_test_barrier', threading.Barrier(2), raising=False)
    code = runtime_import + '''
rt._test_marker = ctx['marker']
exec("def run_recipe(*args, **kwargs): return {'records': [_test_marker]}", rt.__dict__)
rt._test_barrier.wait(5)
'''
    doc = recipe(code)
    doc['steps'] = [
        {'step': n, 'ep': {'url': 'https://example.org/data'}} for n in (1, 2, 3)
    ]
    # Steps 2 and 3 run in the chain's internal thread pool.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(rt.run_chain_recipe, doc, {'marker': marker},
                               allow_untrusted_code=True) for marker in ('A', 'B')]
        for marker, future in zip(('A', 'B'), futures):
            out = future.result(timeout=10)
            assert not out['bundle'].get('edge_errors')
            assert [out['steps'][f'step{n}']['records'] for n in (1, 2, 3)] == [[marker]] * 3
    assert not hasattr(rt, '_test_marker')


def test_patch_does_not_affect_plain_chain_or_direct_calls(monkeypatch):
    monkeypatch.setattr(rt, 'send_run_report', lambda *a, **k: False)
    monkeypatch.setattr(rt, 'run_recipe', lambda *a, **k: {'records': ['ordinary']})
    installed, release = threading.Event(), threading.Event()
    monkeypatch.setattr(rt, '_test_installed', installed, raising=False)
    monkeypatch.setattr(rt, '_test_release', release, raising=False)
    code = INSTALL + '\nrt._test_installed.set()\nassert rt._test_release.wait(5)\n'
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(rt.run_chain_recipe, recipe(code), {}, allow_untrusted_code=True)
        try:
            assert installed.wait(5)
            second = rt.run_chain_recipe({'steps': [{'step': 1, 'ep': {'url': 'https://example.org'}}]}, {})
            assert second['steps']['step1']['records'] == ['ordinary']
            assert rt.run_recipe({}, {}, {})['records'] == ['ordinary']
        finally:
            release.set()
            first.result(timeout=10)


def test_failed_wire_does_not_leave_its_executor(monkeypatch):
    monkeypatch.setattr(rt, 'send_run_report', lambda *a, **k: False)
    original = rt.run_recipe
    out = rt.run_chain_recipe(recipe(INSTALL + '\nraise ValueError("wire failed")'), {},
                              allow_untrusted_code=True)
    assert out['bundle']['edge_errors']
    assert rt.run_recipe is original
    assert not hasattr(rt, '_curated_helper')


def test_nested_chain_starts_with_ordinary_executor(monkeypatch):
    monkeypatch.setattr(rt, 'send_run_report', lambda *a, **k: False)
    monkeypatch.setattr(rt, 'run_recipe', lambda *a, **k: {'records': ['ordinary']})
    code = INSTALL + '''
child = rt.run_chain_recipe({'steps': [{'step': 1, 'ep': {'url': 'https://example.org'}}]}, {})
ctx['child'] = child['steps']['step1']['records']
ctx['parent_kept_executor'] = rt.run_recipe is not original
'''
    doc = recipe(code)
    doc['returns_outputs'] = ['child', 'parent_kept_executor']
    out = rt.run_chain_recipe(doc, {}, allow_untrusted_code=True)
    assert not out['bundle'].get('edge_errors')
    assert out['bundle']['child'] == ['ordinary']
    assert out['bundle']['parent_kept_executor'] is True


def test_connector_imports_see_its_chains_executor(monkeypatch):
    monkeypatch.setattr(rt, 'send_run_report', lambda *a, **k: False)
    code = '''
from aidenix_atlas import _recipe_runtime as rt
exec("def run_recipe(*args, **kwargs): return {'records': ['local']}", rt.__dict__)
'''
    doc = recipe(code)
    doc['steps'] = [{'step': 1, 'in': ['value'], 'connector_code': '''
def go(value):
    from aidenix_atlas import run_recipe
    from aidenix_atlas._recipe_runtime import run_recipe as other
    from aidenix_atlas import dataset
    assert callable(dataset.open)
    assert other({}, {}, {}) == run_recipe({}, {}, {})
    return run_recipe({}, {}, {})['records']
'''}]
    out = rt.run_chain_recipe(doc, {'value': 'x'}, allow_untrusted_code=True)
    assert out['steps']['step1']['records'] == ['local'], out
