"""
HunterAI — Exploit Chain Builder
===================================
Combines multiple individual findings into high-impact attack chains.

Original design: most pentest tools report findings in isolation.
HunterAI models vulnerability capabilities as a directed graph.
Each vulnerability "provides" certain capabilities (e.g. SSRF → internal_reach).
Those capabilities can "unlock" further vulnerabilities.

Two analysis tiers:
  1. Rule-based graph matching (fast, covers known chains)
  2. LLM analysis (discovers novel combinations the rules miss)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from hunterai.core.engine import BaseModule
from hunterai.llm.router  import LLMRouter, TaskType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Capability model
# Vulnerability type → capabilities it grants to an attacker
# ---------------------------------------------------------------------------
VULN_CAPABILITIES: dict[str, list[str]] = {
    "ssrf":              ["internal_reach", "cloud_metadata"],
    "open_redirect":     ["phishing", "oauth_redirect_abuse"],
    "xxe":               ["file_read", "internal_reach"],
    "sql_injection":     ["cred_dump", "file_read", "rce"],
    "rce":               ["rce", "file_read", "cred_dump", "pivot"],
    "lfi":               ["file_read", "config_leak"],
    "file_read":         ["config_leak", "cred_read"],
    "idor":              ["data_access", "priv_esc"],
    "auth_bypass":       ["priv_esc", "data_access"],
    "jwt_weak":          ["priv_esc", "token_forge"],
    "xss_stored":        ["session_hijack", "cred_phish"],
    "cors_misconfig":    ["session_hijack", "data_access"],
    "redis_unauth":      ["rce", "cred_dump"],
    "elasticsearch_unauth": ["data_access", "cred_dump"],
    "k8s_dashboard":     ["rce", "pivot", "secret_access"],
    "cloud_metadata":    ["cloud_cred", "priv_esc"],
    "cloud_cred":        ["full_account_takeover"],
    "config_leak":       ["cred_read", "internal_info"],
    "cred_read":         ["auth_bypass", "priv_esc"],
    "internal_reach":    ["redis_unauth", "elasticsearch_unauth", "k8s_dashboard"],
    "ssti":              ["rce"],
    "default_creds":     ["auth_bypass", "priv_esc"],
    "sensitive_path":    ["config_leak"],
}

# Known chain templates — pattern of capabilities required
CHAIN_TEMPLATES = [
    {
        "name":     "SSRF → Internal Service → RCE",
        "pattern":  ["internal_reach", "redis_unauth"],
        "impact":   "Use SSRF to reach internal Redis with no authentication → write SSH public key → RCE",
        "severity": "critical",
    },
    {
        "name":     "Info Disclosure → Credential Reuse → Privilege Escalation",
        "pattern":  ["config_leak", "cred_read", "priv_esc"],
        "impact":   "Leaked config exposes credentials → reused credentials grant admin access",
        "severity": "critical",
    },
    {
        "name":     "JWT Weak Secret → Token Forgery → Full Account Takeover",
        "pattern":  ["jwt_weak", "token_forge", "priv_esc"],
        "impact":   "Brute-force JWT secret → forge admin token → access all accounts",
        "severity": "critical",
    },
    {
        "name":     "Stored XSS → Session Hijack → Account Takeover",
        "pattern":  ["xss_stored", "session_hijack"],
        "impact":   "Stored XSS exfiltrates admin session cookie → full account takeover",
        "severity": "critical",
    },
    {
        "name":     "XXE → File Read → Credential Theft",
        "pattern":  ["xxe", "file_read", "cred_read"],
        "impact":   "XXE reads /etc/passwd, private keys, and application config files",
        "severity": "critical",
    },
    {
        "name":     "SSRF → Cloud Metadata → Cloud Account Takeover",
        "pattern":  ["cloud_metadata", "cloud_cred", "full_account_takeover"],
        "impact":   "SSRF reaches instance metadata service → IAM credentials → full cloud account compromise",
        "severity": "critical",
    },
    {
        "name":     "SSTI → RCE → Full Server Compromise",
        "pattern":  ["ssti", "rce"],
        "impact":   "Template injection evaluated → server-side code execution → OS command execution",
        "severity": "critical",
    },
    {
        "name":     "Default Credentials → Admin Access → Data Exfiltration",
        "pattern":  ["default_creds", "auth_bypass", "data_access"],
        "impact":   "Default credentials grant admin panel access → full database dump",
        "severity": "critical",
    },
]


@dataclass
class ChainNode:
    title:      str
    capability: str
    severity:   str
    component:  str


@dataclass
class ExploitChain:
    name:      str
    nodes:     list[ChainNode]
    severity:  str
    impact:    str
    steps:     list[str]
    is_llm:    bool = False


class ExploitChainModule(BaseModule):
    name     = "exploit_chain"
    category = "exploit"

    def __init__(self, bus, session, llm: LLMRouter) -> None:
        super().__init__(bus, session)
        self.llm = llm

    async def execute(self) -> None:
        candidates = (self.session.confirmed +
                      [f for f in self.session.findings
                       if f.get("severity") in ("critical", "high")])

        if len(candidates) < 2:
            self.log.info("Need ≥2 findings for chain analysis, skipping")
            return

        self.log.info("Analyzing %d findings for exploit chains", len(candidates))

        rule_chains = self._rule_chains(candidates)
        llm_chains  = await self._llm_chains(candidates)

        all_chains = rule_chains + llm_chains
        self.log.info("Chains discovered: %d (rule=%d llm=%d)",
                      len(all_chains), len(rule_chains), len(llm_chains))

        for chain in all_chains:
            await self.emit_confirmed({
                "title":       f"Exploit Chain: {chain.name}",
                "severity":    chain.severity,
                "source":      "exploit_chain",
                "component":   " → ".join(n.component for n in chain.nodes if n.component),
                "description": chain.impact,
                "evidence":    chain.steps,
                "fix":         "Remediate any node in the chain to break it. Prioritize the first node.",
                "refs":        [],
                "chain":       True,
                "llm_assisted": chain.is_llm,
            })

    # ------------------------------------------------------------------
    # Tier 1 — rule-based graph matching
    # ------------------------------------------------------------------

    def _rule_chains(self, findings: list[dict]) -> list[ExploitChain]:
        chains  = []
        titles  = [f.get("title", "").lower() for f in findings]

        for template in CHAIN_TEMPLATES:
            matched: list[ChainNode] = []
            for capability in template["pattern"]:
                node = self._find_node_for_capability(capability, findings, titles)
                if node:
                    matched.append(node)

            if len(matched) >= 2:
                chains.append(ExploitChain(
                    name     = template["name"],
                    nodes    = matched,
                    severity = template["severity"],
                    impact   = template["impact"],
                    steps    = [
                        f"Step {i+1}: Exploit '{n.title}' → gain capability: {n.capability}"
                        for i, n in enumerate(matched)
                    ],
                ))
        return chains

    def _find_node_for_capability(
            self, capability: str,
            findings: list[dict], titles: list[str]) -> ChainNode | None:
        for vuln_type, caps in VULN_CAPABILITIES.items():
            if capability not in caps:
                continue
            for i, title in enumerate(titles):
                if vuln_type.replace("_", " ") in title or vuln_type in title:
                    f = findings[i]
                    return ChainNode(
                        title=f.get("title", ""),
                        capability=capability,
                        severity=f.get("severity", "medium"),
                        component=f.get("component", ""),
                    )
        return None

    # ------------------------------------------------------------------
    # Tier 2 — LLM analysis for novel chains
    # ------------------------------------------------------------------

    async def _llm_chains(self, findings: list[dict]) -> list[ExploitChain]:
        summary = [
            {"title": f.get("title", ""), "severity": f.get("severity", ""),
             "component": f.get("component", ""), "description": f.get("description", "")}
            for f in findings[:20]
        ]
        prompt = f"""You are an expert penetration tester analyzing findings for attack chain potential.

Target: {self.session.target}
Findings:
{json.dumps(summary, indent=2)}

Identify multi-step exploit chains that combine 2+ of these findings.
Focus on: SSRF → internal services, info disclosure → auth bypass, injection → privilege escalation.

Respond ONLY with valid JSON:
{{
  "chains": [
    {{
      "name": "Chain name",
      "steps": ["Step 1: ...", "Step 2: ...", "Final: ..."],
      "impact": "What attacker achieves",
      "severity": "critical",
      "involved": ["finding title 1", "finding title 2"]
    }}
  ]
}}

If no viable chains exist, return {{"chains": []}}"""

        try:
            resp   = await self.llm.complete(
                task_type=TaskType.ORCHESTRATION,
                messages=[{"role": "user", "content": prompt}],
                system="You are HunterAI's exploit chain analysis agent. Respond only with JSON.",
                max_tokens=2048,
            )
            data   = json.loads(resp["content"])
            chains = []
            for c in data.get("chains", []):
                nodes = [ChainNode(title=v, capability="llm", severity="high", component="")
                         for v in c.get("involved", [])]
                if len(nodes) >= 2:
                    chains.append(ExploitChain(
                        name     = c.get("name", "LLM-identified chain"),
                        nodes    = nodes,
                        severity = c.get("severity", "critical"),
                        impact   = c.get("impact", ""),
                        steps    = c.get("steps", []),
                        is_llm   = True,
                    ))
            return chains
        except Exception as e:
            self.log.warning("LLM chain analysis error (non-fatal): %s", e)
            return []
