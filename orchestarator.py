"""
HunterAI — Orchestrator Agent
===============================
The AI command center. Listens to every event on the bus and dynamically
re-evaluates attack priorities in real time.

Two-tier decision architecture:
  Tier 1 — Rule-based fast response (no LLM call, sub-millisecond)
            Handles well-known high-value triggers immediately.
  Tier 2 — LLM deep analysis (batched, async)
            Identifies non-obvious opportunities and exploit chain seeds.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hunterai.core.engine import HunterEngine

from hunterai.core.eventbus import Event, EventType
from hunterai.llm.router    import LLMRouter, TaskType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Opportunity matrix — technology detected → modules to prioritise
# ---------------------------------------------------------------------------
OPPORTUNITY_MATRIX: dict[str, dict[str, int]] = {
    "GraphQL":       {"apifuzz": 10, "auth": 8},
    "Spring Boot":   {"vulnscan": 10, "apifuzz": 8},
    "WordPress":     {"vulnscan": 10},
    "JWT":           {"auth": 10},
    "AWS":           {"cloud": 10},
    "GCP":           {"cloud": 10},
    "Azure":         {"cloud": 10},
    "Kubernetes":    {"cloud": 9, "post_exploit": 7},
    "Django":        {"vulnscan": 8, "apifuzz": 7},
    "Laravel":       {"vulnscan": 8},
    "Elasticsearch": {"vulnscan": 10},
    "Redis":         {"post_exploit": 9},
    "MongoDB":       {"vulnscan": 9},
    "Next.js":       {"apifuzz": 7},
    "Express.js":    {"apifuzz": 8, "auth": 7},
}


@dataclass
class Decision:
    action:   str
    reason:   str
    priority: int
    module:   str
    trigger:  str


class OrchestratorAgent:
    """
    Real-time AI decision engine for HunterAI.

    Registered as an EventBus subscriber; every event fires on_event().
    High-value events trigger immediate module scheduling.
    A background loop batches events for LLM deep analysis.
    """

    def __init__(self, engine: "HunterEngine", llm: LLMRouter) -> None:
        self.engine    = engine
        self.session   = engine.session
        self.llm       = llm
        self.decisions: list[Decision] = []
        self._pending:  asyncio.Queue  = asyncio.Queue()
        self._task:     asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._analysis_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    # ------------------------------------------------------------------
    # Event handler — called for EVERY event published on the bus
    # ------------------------------------------------------------------

    async def on_event(self, event: Event) -> None:
        await self._fast_response(event)

        if event.type in (EventType.VULN_CONFIRMED, EventType.CRED_FOUND,
                           EventType.SESSION_OBTAINED, EventType.TECH_DETECTED):
            await self._pending.put(event)

    # ------------------------------------------------------------------
    # Tier 1 — Rule-based fast response
    # ------------------------------------------------------------------

    async def _fast_response(self, event: Event) -> None:
        if event.type == EventType.TECH_DETECTED:
            tech   = event.data.get("tech", "")
            boosts = OPPORTUNITY_MATRIX.get(tech, {})
            for module, score in boosts.items():
                if score >= 9:
                    logger.info("[Orchestrator] %s detected → urgent schedule: %s", tech, module)
                    await self.engine.schedule(module, priority=1)
                    self._record(f"schedule:{module}",
                                 f"High-value technology: {tech}", score, module, event.id)

        elif event.type == EventType.ENDPOINT_FOUND:
            url = event.data.get("url", "")
            if any(k in url.lower() for k in ["graphql", "/api/", "/rest/", "/v1/", "/v2/"]):
                await self.engine.schedule("apifuzz", priority=1)

        elif event.type == EventType.CRED_FOUND:
            logger.info("[Orchestrator] Credentials found → scheduling post_exploit")
            await self.engine.schedule("post_exploit", priority=0)

        elif event.type == EventType.SESSION_OBTAINED:
            logger.info("[Orchestrator] Shell obtained → urgent post_exploit + exploit_chain")
            await self.engine.schedule("post_exploit",   priority=0)
            await self.engine.schedule("exploit_chain",  priority=1)

        elif event.type == EventType.VULN_CONFIRMED:
            # When 2+ confirmed vulns exist, try chaining them
            if len(self.session.confirmed) >= 2:
                await self.engine.schedule("exploit_chain", priority=2)

    # ------------------------------------------------------------------
    # Tier 2 — LLM deep analysis (batched)
    # ------------------------------------------------------------------

    async def _analysis_loop(self) -> None:
        batch: list[Event] = []
        while True:
            try:
                event = await asyncio.wait_for(self._pending.get(), timeout=8.0)
                batch.append(event)
                if len(batch) >= 5:
                    await self._llm_analyze(batch)
                    batch = []
            except asyncio.TimeoutError:
                if batch:
                    await self._llm_analyze(batch)
                    batch = []
            except asyncio.CancelledError:
                break

    async def _llm_analyze(self, events: list[Event]) -> None:
        state   = self.session.snapshot()
        summary = [{"type": e.type, "source": e.source, "data": e.data} for e in events]

        prompt = f"""You are an expert penetration tester acting as the AI command center for HunterAI.

Current scan state:
{json.dumps(state, indent=2)}

Recent events ({len(events)}):
{json.dumps(summary, indent=2)}

Available modules: recon, vulnscan, apifuzz, auth, cloud, exploit_chain, post_exploit

Analyze the current state and recommend the best next actions.
Respond ONLY with valid JSON:
{{
  "analysis": "One sentence situational assessment.",
  "next_actions": [
    {{"module": "<name>", "priority": 1-10, "reason": "<why>"}}
  ],
  "chain_opportunity": "<describe exploit chain potential, or null>"
}}"""

        try:
            resp   = await self.llm.complete(
                task_type=TaskType.ORCHESTRATION,
                messages=[{"role": "user", "content": prompt}],
                system="You are HunterAI's Orchestrator Agent. Respond only with JSON.",
                max_tokens=1024,
            )
            result = json.loads(resp["content"])
            logger.info("[Orchestrator] LLM analysis: %s", result.get("analysis", ""))

            for action in result.get("next_actions", []):
                module   = action.get("module", "")
                priority = 10 - action.get("priority", 5)
                if module and module not in self.engine._done:
                    await self.engine.schedule(module, priority=priority)
                    self._record(f"schedule:{module}", action.get("reason", "LLM decision"),
                                 action.get("priority", 5), module, events[0].id)

            if result.get("chain_opportunity"):
                logger.info("[Orchestrator] Chain opportunity: %s", result["chain_opportunity"])
                await self.engine.schedule("exploit_chain", priority=2)

        except Exception as e:
            logger.warning("[Orchestrator] LLM analysis error (non-fatal): %s", e)

    def _record(self, action: str, reason: str, priority: int,
                module: str, trigger: str) -> None:
        self.decisions.append(Decision(action, reason, priority, module, trigger))

    def decision_log(self) -> list[dict]:
        return [{"action": d.action, "reason": d.reason,
                 "priority": d.priority, "trigger": d.trigger}
                for d in self.decisions]
