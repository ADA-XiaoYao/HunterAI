"""
Unit tests — LLM Router
"""
import os
import pytest

from hunterai.llm.router import LLMRouter, Provider, TaskType, ProviderHealth, PREFERENCE


# ── ProviderHealth ────────────────────────────────────────────────

def test_provider_health_success_resets_errors():
    h = ProviderHealth(available=False, error_count=5)
    h.record_success(100.0)
    assert h.available     is True
    assert h.error_count   == 0
    assert h.avg_latency   > 0


def test_provider_health_failure_increments_count():
    h = ProviderHealth()
    h.record_failure()
    h.record_failure()
    assert h.error_count   == 2
    assert h.available     is True   # Still available after 2


def test_provider_health_marks_unavailable_after_three_failures():
    h = ProviderHealth()
    h.record_failure()
    h.record_failure()
    h.record_failure()
    assert h.available     is False
    assert h.error_count   == 3


def test_provider_health_latency_ema():
    h = ProviderHealth()
    h.record_success(100.0)
    h.record_success(200.0)
    # EMA: 0.8 * (0.8*0 + 0.2*100) + 0.2*200 = 0.8*20 + 40 = 56
    assert h.avg_latency > 0


# ── Provider detection ────────────────────────────────────────────

def test_llm_router_detects_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.delenv("OPENAI_API_KEY",   raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY",   raising=False)
    monkeypatch.delenv("OLLAMA_URL",       raising=False)

    router = LLMRouter()
    assert Provider.ANTHROPIC in router._available
    assert Provider.OPENAI    not in router._available


def test_llm_router_detects_multiple_providers(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY",    "sk-openai-test")

    router = LLMRouter()
    assert Provider.ANTHROPIC in router._available
    assert Provider.OPENAI    in router._available


def test_llm_router_raises_with_no_providers(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY",    raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY",    raising=False)
    monkeypatch.delenv("OLLAMA_URL",        raising=False)

    with pytest.raises(RuntimeError, match="No LLM providers configured"):
        LLMRouter()


# ── Provider selection ────────────────────────────────────────────

def test_llm_router_selects_anthropic_for_code_analysis(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY",    "sk-openai-test")

    router   = LLMRouter()
    provider = router.select(TaskType.CODE_ANALYSIS)
    assert provider == Provider.ANTHROPIC


def test_llm_router_selects_openai_for_exploit_gen(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY",    "sk-openai-test")

    router   = LLMRouter()
    provider = router.select(TaskType.EXPLOIT_GEN)
    assert provider == Provider.OPENAI


def test_llm_router_falls_back_when_preferred_unhealthy(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY",    "sk-openai-test")

    router = LLMRouter()
    # Mark Anthropic as unhealthy
    router._health[Provider.ANTHROPIC].available = False

    provider = router.select(TaskType.CODE_ANALYSIS)
    # Should fall back to OpenAI
    assert provider == Provider.OPENAI


def test_llm_router_raises_when_all_providers_unhealthy(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    router = LLMRouter()
    router._health[Provider.ANTHROPIC].available = False

    with pytest.raises(RuntimeError, match="unavailable"):
        router.select(TaskType.ORCHESTRATION)


# ── Health report ─────────────────────────────────────────────────

def test_llm_router_health_report(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY",    "sk-openai-test")

    router = LLMRouter()
    report = router.health_report()

    assert "anthropic" in report
    assert "openai"    in report
    assert report["anthropic"]["available"] is True
    assert "avg_latency_ms" in report["anthropic"]


# ── Preference coverage ───────────────────────────────────────────

def test_preference_covers_all_task_types():
    for task_type in TaskType:
        assert task_type in PREFERENCE, f"TaskType.{task_type} missing from PREFERENCE"
        assert len(PREFERENCE[task_type]) > 0
