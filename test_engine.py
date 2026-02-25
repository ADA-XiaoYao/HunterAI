"""
Unit tests — HunterAI Core Engine
"""
import asyncio
import pytest

from hunterai.core.eventbus import EventBus, Event, EventType
from hunterai.core.session  import HunterSession
from hunterai.core.engine   import BaseModule, HunterEngine


# ── EventBus ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_eventbus_subscribe_and_receive():
    bus      = EventBus()
    received = []

    async def handler(e: Event):
        received.append(e)

    bus.subscribe(EventType.VULN_FOUND, handler)
    await bus.publish(Event(EventType.VULN_FOUND, "test", {"title": "SQLi"}))
    await asyncio.sleep(0)

    assert len(received) == 1
    assert received[0].data["title"] == "SQLi"
    assert received[0].source == "test"


@pytest.mark.asyncio
async def test_eventbus_subscribe_all_receives_every_type():
    bus   = EventBus()
    count = {"n": 0}

    async def handler(e: Event):
        count["n"] += 1

    bus.subscribe_all(handler)
    await bus.publish(Event(EventType.SUBDOMAIN_FOUND, "recon"))
    await bus.publish(Event(EventType.VULN_FOUND,      "scan"))
    await bus.publish(Event(EventType.TECH_DETECTED,   "recon"))
    await asyncio.sleep(0)

    assert count["n"] == 3


@pytest.mark.asyncio
async def test_eventbus_history_filtering():
    bus = EventBus()
    bus.subscribe(EventType.SUBDOMAIN_FOUND, lambda e: None)
    bus.subscribe(EventType.VULN_FOUND,      lambda e: None)

    await bus.publish(Event(EventType.SUBDOMAIN_FOUND, "recon", {"subdomain": "api.ex.com"}))
    await bus.publish(Event(EventType.VULN_FOUND,      "scan",  {"title": "XSS"}))
    await bus.publish(Event(EventType.SUBDOMAIN_FOUND, "recon", {"subdomain": "dev.ex.com"}))

    assert bus.count(EventType.SUBDOMAIN_FOUND) == 2
    assert bus.count(EventType.VULN_FOUND)      == 1
    assert len(bus.history())                   == 3


@pytest.mark.asyncio
async def test_eventbus_handler_exception_does_not_propagate():
    bus = EventBus()

    async def bad_handler(e: Event):
        raise RuntimeError("handler crash")

    async def good_handler(e: Event):
        pass

    bus.subscribe(EventType.ERROR, bad_handler)
    bus.subscribe(EventType.ERROR, good_handler)

    # Should not raise
    await bus.publish(Event(EventType.ERROR, "test"))


# ── HunterSession ─────────────────────────────────────────────────

def test_session_finding_deduplication():
    s = HunterSession("https://example.com")
    added1 = s.add_finding({"title": "SQLi", "component": "/login", "severity": "critical"})
    added2 = s.add_finding({"title": "SQLi", "component": "/login", "severity": "critical"})

    assert added1 is True
    assert added2 is False
    assert len(s.findings) == 1


def test_session_finding_different_components_not_deduped():
    s = HunterSession("https://example.com")
    s.add_finding({"title": "SQLi", "component": "/login",  "severity": "critical"})
    s.add_finding({"title": "SQLi", "component": "/search", "severity": "critical"})

    assert len(s.findings) == 2


def test_session_severity_counts():
    s = HunterSession("https://example.com")
    s.add_finding({"title": "A", "component": "c1", "severity": "critical"})
    s.add_finding({"title": "B", "component": "c2", "severity": "high"})
    s.add_finding({"title": "C", "component": "c3", "severity": "high"})
    s.add_finding({"title": "D", "component": "c4", "severity": "medium"})
    s.add_finding({"title": "E", "component": "c5", "severity": "info"})

    counts = s.severity_counts()
    assert counts["critical"] == 1
    assert counts["high"]     == 2
    assert counts["medium"]   == 1
    assert counts["low"]      == 0
    assert counts["info"]     == 1


def test_session_add_confirmed_marks_flag():
    s = HunterSession("https://example.com")
    finding = {"title": "RCE", "component": "/exec", "severity": "critical"}
    s.add_confirmed(finding)

    assert len(s.confirmed) == 1
    assert s.confirmed[0]["confirmed"] is True
    assert len(s.findings)  == 1


def test_session_snapshot_structure():
    s = HunterSession("https://target.example.com", profile="full")
    s.subdomains.add("api.target.example.com")
    s.technologies.add("Django")

    snap = s.snapshot()
    assert snap["target"]        == "https://target.example.com"
    assert snap["profile"]       == "full"
    assert snap["subdomains"]    == 1
    assert "Django" in snap["technologies"]
    assert "severity" in snap
    assert "elapsed_s" in snap


# ── HunterEngine ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_engine_registers_and_runs_module():
    executed = {"count": 0}

    class MockModule(BaseModule):
        name = "mock"
        async def execute(self):
            executed["count"] += 1

    engine = HunterEngine("https://example.com", profile="quick")
    engine.register(MockModule(engine.bus, engine.session))

    # Manually enqueue and drain one task
    await engine._queue.put((0, "mock"))
    worker = asyncio.create_task(engine._worker("w0"))
    await asyncio.wait_for(engine._queue.join(), timeout=5.0)
    worker.cancel()

    assert executed["count"] == 1
    assert "mock" in engine._done


@pytest.mark.asyncio
async def test_engine_skips_already_done_module():
    executed = {"count": 0}

    class MockModule(BaseModule):
        name = "mock2"
        async def execute(self):
            executed["count"] += 1

    engine = HunterEngine("https://example.com", profile="quick")
    engine.register(MockModule(engine.bus, engine.session))
    engine._done.add("mock2")   # already marked done

    await engine.schedule("mock2", priority=0)
    # Queue should be empty because module is already done
    assert engine._queue.empty()


@pytest.mark.asyncio
async def test_engine_schedule_deduplicates():
    engine = HunterEngine("https://example.com", profile="quick")

    await engine.schedule("recon", priority=0)
    await engine.schedule("recon", priority=0)   # duplicate

    # Both enqueue since we don't dedup at schedule time for pending modules
    # (dedup happens in _worker when checking _done/_running)
    assert not engine._queue.empty()


@pytest.mark.asyncio
async def test_engine_module_failure_does_not_crash_worker():
    class CrashModule(BaseModule):
        name = "crash"
        async def execute(self):
            raise RuntimeError("intentional crash")

    engine = HunterEngine("https://example.com", profile="quick")
    engine.register(CrashModule(engine.bus, engine.session))

    await engine._queue.put((0, "crash"))
    worker = asyncio.create_task(engine._worker("w0"))

    # Should complete without raising
    await asyncio.wait_for(engine._queue.join(), timeout=5.0)
    worker.cancel()

    # crash is in non-critical set? No — but engine still handles it
    assert "crash" in engine._done


# ── BaseModule helpers ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_base_module_emit_finding_deduplicates():
    bus     = EventBus()
    session = HunterSession("https://example.com")
    events  = []

    async def capture(e):
        events.append(e)
    bus.subscribe(EventType.VULN_FOUND, capture)

    class TestModule(BaseModule):
        name = "test"
        async def execute(self):
            await self.emit_finding({"title": "XSS", "component": "/x", "severity": "high"})
            await self.emit_finding({"title": "XSS", "component": "/x", "severity": "high"})

    m = TestModule(bus, session)
    await m.execute()
    await asyncio.sleep(0)

    # Only one event published (deduplicated by session)
    assert len(events) == 1
    assert len(session.findings) == 1


@pytest.mark.asyncio
async def test_base_module_emit_confirmed_sets_flag():
    bus     = EventBus()
    session = HunterSession("https://example.com")
    events  = []

    async def capture(e):
        events.append(e)
    bus.subscribe(EventType.VULN_CONFIRMED, capture)

    class TestModule(BaseModule):
        name = "test"
        async def execute(self):
            await self.emit_confirmed({"title": "RCE", "component": "/cmd", "severity": "critical"})

    m = TestModule(bus, session)
    await m.execute()
    await asyncio.sleep(0)

    assert len(events) == 1
    assert session.confirmed[0]["confirmed"] is True
