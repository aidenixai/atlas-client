"""Trusted local ceilings; recipes cannot raise resource consumption."""
import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt


@pytest.fixture(autouse=True)
def clean_limits(monkeypatch):
    for name in ("ATLAS_BODY_CAP_MB", "ATLAS_FETCH_DEADLINE_S", "ATLAS_MAX_CONCURRENCY"):
        monkeypatch.delenv(name, raising=False)


def test_recipe_cannot_raise_local_limits(monkeypatch):
    monkeypatch.setenv("ATLAS_BODY_CAP_MB", "1")
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", "2")
    assert rt._limits_of({"body_cap_mb": 8192, "deadline_s": 86400}) == (1024**2, 2)


def test_user_can_raise_defaults_and_recipe_can_narrow(monkeypatch):
    monkeypatch.setenv("ATLAS_BODY_CAP_MB", "1024")
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", "600")
    assert rt._limits_of({}) == (1024**3, 600)
    assert rt._limits_of({"body_cap_mb": 500, "deadline_s": 400}) == (500 * 1024**2, 400)


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "-3", "0", "bad"])
def test_invalid_limits_keep_safe_defaults(monkeypatch, value):
    monkeypatch.setenv("ATLAS_BODY_CAP_MB", value)
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", value)
    assert rt._limits_of({"body_cap_mb": value, "deadline_s": value}) == (256 * 1024**2, 300)


def test_recipe_cannot_raise_default_concurrency():
    assert rt._fanout_plan({}, {"items": list(range(1000)), "concurrency": 1000}, {}, None)["concurrency"] == 6


def test_user_can_raise_concurrency_and_parent_limits_reach_legs(monkeypatch):
    monkeypatch.setenv("ATLAS_MAX_CONCURRENCY", "12")
    ep = {"body_cap_mb": 1, "deadline_s": 2}
    plan = rt._fanout_plan(ep, {"items": list(range(20)), "concurrency": 1000}, {}, None)
    assert plan["concurrency"] == 12
    assert rt._limits_of(plan["leg"](1)) == (1024**2, 2)


def test_async_fanout_schedules_only_one_width_at_a_time(monkeypatch):
    original = asyncio.gather
    submitted = []

    async def gather(*jobs):
        submitted.append(len(jobs))
        return await original(*jobs)

    async def run(*args, **kwargs):
        return {"records": [{"ok": True}]}

    monkeypatch.setattr(asyncio, "gather", gather)
    monkeypatch.setattr(rt, "_arun_recipe", run)
    result = asyncio.run(rt._run_fanout_async({}, {"items": list(range(15)), "concurrency": 3}, {}, {}))
    assert result["count"] == 15
    assert max(submitted) <= 3


@pytest.mark.parametrize("asynchronous", [False, True])
def test_concurrent_calls_share_the_local_network_ceiling(monkeypatch, asynchronous):
    monkeypatch.setenv("ATLAS_MAX_CONCURRENCY", "2")
    active = peak = 0
    lock = threading.Lock()

    def enter():
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)

    def leave(request):
        nonlocal active
        with lock:
            active -= 1
        return httpx.Response(200, stream=httpx.ByteStream(b"[]"))

    def handler(request):
        enter()
        time.sleep(0.01)
        return leave(request)

    async def ahandler(request):
        enter()
        await asyncio.sleep(0.01)
        return leave(request)

    if asynchronous:
        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(ahandler)) as client:
                await asyncio.gather(*(rt._afetch(client, {}, {}, "https://source.test/data") for _ in range(12)))
        asyncio.run(run())
    else:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            with ThreadPoolExecutor(max_workers=12) as pool:
                list(pool.map(lambda _: rt._fetch(client, {}, {}, "https://source.test/data"), range(12)))
    assert 0 < peak <= 2


def test_cancelled_waiter_does_not_leak_a_network_slot(monkeypatch):
    monkeypatch.setenv("ATLAS_MAX_CONCURRENCY", "1")

    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        async def handler(request):
            entered.set()
            await release.wait()
            return httpx.Response(200, stream=httpx.ByteStream(b"[]"))

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            first = asyncio.create_task(rt._afetch(client, {}, {}, "https://source.test/data"))
            await entered.wait()
            waiter = asyncio.create_task(rt._afetch(client, {}, {}, "https://source.test/data"))
            await asyncio.sleep(0.02)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            release.set()
            await asyncio.wait_for(rt._afetch(client, {}, {}, "https://source.test/data"), 1)

    asyncio.run(run())
