"""
HunterAI — Core Scheduling Engine
===================================
Event-driven dynamic module scheduler.

Design:
  - NOT a fixed pipeline. Uses a priority queue + real-time insertion.
  - The Orchestrator Agent can inject high-priority modules at any time.
  - 3 concurrent workers maximise parallelism.
  - Non-critical module failures are isolated; the scan continues.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

from hunterai.core.eventbus import EventBus, Event, EventType
from hunterai.core.session  import HunterSession

logger = logging.getLogger(__name__)

# Profile → initial module sequence
PROFILES: dict[str, list[str]] = {
    "quick":    ["recon", "vulnscan"],
    "standard": ["recon", "vulnscan", "apifuzz", "auth"],
    "full":     ["recon", "vulnscan", "apifuzz", "auth",
                 "cloud", "exploit_chain", "post_exploit"],
    "cloud":    ["recon", "cloud"],
    "api":      ["recon", "apifuzz", "auth"],
}

# Failures in these modules don't abort the scan
NON_CRITICAL = {"post_exploit", "cloud", "exploit_chain"}


class BaseModule:
    """Base class for all HunterAI modules."""
    name:     str = "base"
    category: str = "misc"

    def __init__(self, bus: EventBus, session: HunterSession) -> None:
        self.bus     = bus
        self.session = session
        self.log     = logging.getLogger(f"hunterai.module.{self.name}")

    async def run(self) -> None:
        await self.bus.publish(Event(EventType.MODULE_STARTED, self.name))
        t0 = time.time()
        try:
            await self.execute()
        except Exception as e:
            self.log.error("Unhandled error: %s", e, exc_info=True)
            await self.bus.publish(Event(EventType.ERROR, self.name, {"error": str(e)}))
        finally:
            elapsed = round(time.time() - t0, 1)
            self.session.modules_done.add(self.name)
            await self.bus.publish(Event(EventType.MODULE_DONE, self.name,
                                          {"elapsed_s": elapsed}))
            self.log.info("Done in %.1fs", elapsed)

    async def execute(self) -> None:
        raise NotImplementedError

    async def emit_finding(self, finding: dict) -> None:
        if self.session.add_finding(finding):
            await self.bus.publish(Event(EventType.VULN_FOUND, self.name, finding))

    async def emit_confirmed(self, finding: dict) -> None:
        self.session.add_confirmed(finding)
        await self.bus.publish(Event(EventType.VULN_CONFIRMED, self.name, finding))


class HunterEngine:
    """
    HunterAI core engine.

    Usage:
        engine = HunterEngine("https://example.com", profile="full")
        engine.register(ReconModule(engine.bus, engine.session))
        engine.register(VulnScanModule(engine.bus, engine.session))
        engine.set_orchestrator(OrchestratorAgent(engine, llm))
        session = await engine.run()
    """

    def __init__(self, target: str, profile: str = "standard") -> None:
        self.bus      = EventBus()
        self.session  = HunterSession(target=target, profile=profile)
        self._modules: dict[str, BaseModule]  = {}
        self._queue:   asyncio.PriorityQueue  = asyncio.PriorityQueue()
        self._running: set[str]               = set()
        self._done:    set[str]               = set()
        self._orchestrator                    = None

    def register(self, module: BaseModule) -> None:
        self._modules[module.name] = module
        logger.debug("Registered module: %s", module.name)

    def set_orchestrator(self, agent) -> None:
        self._orchestrator = agent
        self.bus.subscribe_all(agent.on_event)

    async def schedule(self, module_name: str, priority: int = 5) -> None:
        """
        Add a module to the execution queue.
        Lower priority value = runs sooner (min-heap).
        Safe to call from any coroutine, including agent handlers.
        """
        if module_name in self._done or module_name in self._running:
            return
        # Avoid duplicate queue entries
        await self._queue.put((priority, module_name))
        logger.debug("Scheduled: %s (priority=%d)", module_name, priority)

    async def run(self) -> HunterSession:
        logger.info("=== HunterAI SCAN START | target=%s profile=%s session=%s ===",
                    self.session.target, self.session.profile, self.session.session_id)

        # Seed the queue from the selected profile
        for i, mod in enumerate(PROFILES.get(self.session.profile, PROFILES["standard"])):
            await self.schedule(mod, priority=i)

        # Always finish with report
        await self.schedule("report", priority=99)

        # Start orchestrator background loop
        if self._orchestrator:
            await self._orchestrator.start()

        # Run workers
        workers = [asyncio.create_task(self._worker(f"worker-{i}"))
                   for i in range(3)]
        await self._queue.join()

        for w in workers:
            w.cancel()
        if self._orchestrator:
            await self._orchestrator.stop()

        await self.bus.publish(Event(EventType.SCAN_COMPLETE, "engine",
                                      self.session.snapshot()))
        logger.info("=== SCAN COMPLETE | findings=%d confirmed=%d ===",
                    len(self.session.findings), len(self.session.confirmed))
        return self.session

    async def _worker(self, name: str) -> None:
        while True:
            try:
                priority, module_name = await asyncio.wait_for(
                    self._queue.get(), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            if module_name in self._done:
                self._queue.task_done()
                continue

            module = self._modules.get(module_name)
            if not module:
                logger.warning("[%s] Unknown module: %s — skipping", name, module_name)
                self._queue.task_done()
                continue

            self._running.add(module_name)
            logger.info("[%s] Running: %s", name, module_name)
            try:
                await module.run()
                self._done.add(module_name)
            except Exception as e:
                if module_name not in NON_CRITICAL:
                    logger.error("[%s] Critical module failed: %s — %s", name, module_name, e)
                else:
                    logger.warning("[%s] Non-critical module failed: %s — continuing", name, module_name)
            finally:
                self._running.discard(module_name)
                self._queue.task_done()
