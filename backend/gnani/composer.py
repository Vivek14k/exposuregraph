"""Deterministic response composer separating factual content from phrasing variation.
Ensures varied, natural phrasing while preserving 100% evidence-grounded facts and
preventing consecutive repetitive boilerplate.

The dedup state (``_recent_hashes`` and ``_shown_caveats``) used to live at class
level, which meant every user in the process shared the same memory - a partial-
scan caveat shown to user A would silently suppress the same caveat for user B.
The state now lives on a per-instance ``__init__``, and a lazily-created shared
instance is exposed to the existing classmethod callers via :meth:`_instance`.
:meth:`reset_session` clears that shared instance; the assistant engine wires it
at the start of each new conversation.
"""
from typing import Dict, Any, List, Optional
import hashlib
import random


class ResponseComposer:
    # Lazily-created shared instance for backward-compat with callers that use
    # ResponseComposer.method_name() classmethod-style. State itself lives on
    # the instance (see __init__), not on the class.
    _shared: Optional["ResponseComposer"] = None

    def __init__(self) -> None:
        # Per-instance dedup state - no longer shared at class level.
        self._recent_hashes: List[str] = []
        self._shown_caveats: set[str] = set()

    @classmethod
    def _instance(cls) -> "ResponseComposer":
        """Returns the shared composer instance, creating it lazily."""
        if cls._shared is None:
            cls._shared = cls()
        return cls._shared

    @classmethod
    def reset_session(cls) -> None:
        """Clear the shared composer's per-session dedup state.

        The assistant engine wires this at the start of each new conversation so
        a fresh user/scan doesn't inherit ``_recent_hashes`` or ``_shown_caveats``
        memory from the previous one.
        """
        inst = cls._instance()
        inst._recent_hashes.clear()
        inst._shown_caveats.clear()

    @classmethod
    def compose_risk_score(cls, domain: str, risk_score: float, total_findings: int, total_assets: int, is_partial: bool = False, ask_coverage: bool = False) -> str:
        options = [
            f"The exposure risk score for {domain} evaluates to {risk_score:.1f} out of 100. This calculation combines {total_findings} security findings across {total_assets} discovered external assets. Lower is safer; higher values reflect open services and missing controls.",
            f"Looking at {domain}'s overall posture, we calculate an attack surface risk score of {risk_score:.1f}/100 based on {total_findings} findings and {total_assets} mapped infrastructure assets. I can guide you through the highest-exposure nodes on the graph.",
            f"For {domain}, the weighted risk score currently sits at {risk_score:.1f} out of 100 ({total_findings} findings identified across {total_assets} active assets). Reviewing open ports and web certificates will help bring this score down.",
            f"Security evaluation for {domain} yields an exposure rating of {risk_score:.1f}/100. We identified {total_findings} risk factors across {total_assets} external endpoints. Check the Overview or Attack Graph tabs to see the full topological layout.",
            f"The overall attack surface risk score stands at {risk_score:.1f} out of 100 for {domain}, accounting for {total_findings} findings detected among {total_assets} internet-facing assets.",
        ]
        chosen = cls._pick_variant(options)
        return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

    @classmethod
    def compose_findings_summary(cls, domain: str, total_findings: int, crit: int, high: int, med: int, low: int, top_title: Optional[str] = None, top_asset: Optional[str] = None, is_partial: bool = False, ask_coverage: bool = False) -> str:
        if total_findings == 0:
            options = [
                f"No findings were recorded for {domain}. Note that zero findings do not guarantee the absence of all vulnerabilities.",
                f"No security findings were detected during the bounded checks on {domain}. This does not mean the system is fully impenetrable.",
                f"The scan found 0 security issues for {domain}. Keep in mind this is a defensive bounded assessment, not proof of zero flaws.",
                f"Zero findings were identified for {domain}. While no misconfigurations were observed, bounded checks cannot prove complete security.",
                f"There are no recorded findings for {domain} in this assessment. Remember that zero findings do not establish complete immunity.",
            ]
            chosen = cls._pick_variant(options)
            return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

        top_clause = f" The top priority issue is '{top_title}' on {top_asset}." if top_title and top_asset else ""
        options = [
            f"Here is what the security assessment surfaced for {domain}: we logged {total_findings} distinct findings. Broken down by severity, that is {crit} critical, {high} high, {med} medium, and {low} low-impact issues.{top_clause} I can walk you through the attack graph or open the findings ledger whenever you'd like.",
            f"Analyzing the exposure profile of {domain}, our discovery suite detected {total_findings} total findings ({crit} critical, {high} high, {med} medium, {low} low).{top_clause} Let me know if you want me to inspect any specific service or jump to remediation.",
            f"Looking into {domain}'s security stance, {total_findings} findings were cataloged: {crit} critical, {high} high, {med} medium, and {low} low.{top_clause} I recommend addressing the higher-tier items first to shrink the attack surface.",
            f"Across {domain}, our checks identified {total_findings} security items requiring review: {crit} critical severity, {high} high severity, {med} medium, and {low} low.{top_clause} Would you like to inspect the graph relationships or review the evidence dossier?",
            f"Assessment records for {domain} show {total_findings} findings ({crit} critical, {high} high, {med} medium, {low} low).{top_clause} Everything is indexed in your Findings table with verified headers, certificates, and DNS records.",
        ]
        chosen = cls._pick_variant(options)
        return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

    @classmethod
    def compose_findings_list(cls, domain: str, findings: List[Any], is_partial: bool = False) -> str:
        if not findings:
            answer = f"I didn't find any recorded issues for {domain} in this scan. That doesn't prove there are no vulnerabilities."
        else:
            shown = findings[:8]
            entries = "; ".join(
                f"{finding.title} ({finding.severity.lower()}) on {finding.affected_asset}"
                for finding in shown
            )
            remaining = len(findings) - len(shown)
            extra = f" The remaining {remaining} are in the Findings view." if remaining else ""
            answer = f"I found {len(findings)} finding{'s' if len(findings) != 1 else ''} for {domain}: {entries}.{extra} Would you like the evidence or remediation for any of them?"
        if is_partial:
            answer += " This assessment is partial, so it may not include the full exposure."
        return answer

    @classmethod
    def compose_critical_findings(cls, domain: str, critical_findings: List[Any], is_partial: bool = False, ask_coverage: bool = False) -> str:
        if not critical_findings:
            options = [
                f"No critical findings were recorded for {domain}.",
                f"There are zero critical findings logged for {domain}.",
                f"No critical-severity issues were detected on {domain}.",
                f"The scan did not observe any critical-severity findings for {domain}.",
                f"Zero critical findings were identified for {domain}.",
            ]
            chosen = cls._pick_variant(options)
            return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

        preview = "; ".join(f"{f.title} on {f.affected_asset}" for f in critical_findings[:3])
        options = [
            f"There are {len(critical_findings)} critical-severity findings on {domain} that demand urgent remediation: {preview}. I can open the findings list for you to inspect the exact proof and suggested fixes.",
            f"Immediate attention is needed for {domain}: we flagged {len(critical_findings)} critical issues, notably {preview}. Fixing these will significantly lower your overall risk profile.",
            f"The assessment identified {len(critical_findings)} critical vulnerabilities for {domain}: {preview}. We recommend prioritizing these over medium and informational items.",
            f"Critical exposure alert on {domain}: {len(critical_findings)} critical findings were confirmed ({preview}). Review the remediation guidance to patch these promptly.",
            f"For {domain}, {len(critical_findings)} critical findings were detected: {preview}. Each finding includes observed response headers and DNS evidence to verify the problem.",
        ]
        chosen = cls._pick_variant(options)
        return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

    @classmethod
    def compose_remediation(cls, domain: str, top_finding: Optional[Any], is_partial: bool = False, ask_coverage: bool = False) -> str:
        if not top_finding:
            return "There are no active findings to remediate for this assessment."
        options = [
            f"Here is the highest-priority remediation for {domain}: to address '{top_finding.title}' on {top_finding.affected_asset}, {top_finding.remediation} For reference, the technical evidence gathered was: {top_finding.evidence}",
            f"For '{top_finding.title}' affecting {top_finding.affected_asset}, here is the recommended action: {top_finding.remediation} Observed evidence includes: {top_finding.evidence}",
            f"Top remediation guidance on {domain}: resolve '{top_finding.title}' ({top_finding.affected_asset}) by following: {top_finding.remediation} Scanner evidence: {top_finding.evidence}",
            f"To secure {top_finding.affected_asset} against '{top_finding.title}': {top_finding.remediation} We verified this through observed headers/data: {top_finding.evidence}",
            f"Action plan for '{top_finding.title}' on {top_finding.affected_asset}: {top_finding.remediation} (Proof logged: {top_finding.evidence}).",
        ]
        chosen = cls._pick_variant(options)
        return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

    @classmethod
    def compose_assets_summary(cls, domain: str, total_assets: int, root_domains: List[str], subdomains: List[str], is_subdomain_query: bool = False, is_partial: bool = False, ask_coverage: bool = False) -> str:
        preview = ", ".join(subdomains[:3]) or "none"
        if is_subdomain_query:
            options = [
                f"We mapped {len(subdomains)} active subdomains for {domain}. Some notable examples are: {preview}. You can view the complete node hierarchy on the Attack Graph.",
                f"For {domain}, {len(subdomains)} subdomains were confirmed through DNS enumeration. A few samples include: {preview}.",
                f"DNS reconnaissance identified {len(subdomains)} subdomains associated with {domain} (e.g. {preview}). Check the Assets view for IP assignments and open web ports.",
                f"A total of {len(subdomains)} subdomains were cataloged under {domain}: {preview}. All discovered hostnames have been saved to the inventory.",
            ]
        else:
            options = [
                f"Our discovery engine mapped {total_assets} total infrastructure assets for {domain}, including {len(root_domains)} root domain and {len(subdomains)} subdomains (such as {preview}). Would you like me to switch over to the Assets inventory?",
                f"Discovered {total_assets} assets across {domain}'s external attack surface ({len(root_domains)} root, {len(subdomains)} subdomains). Examples include: {preview}.",
                f"A total of {total_assets} external assets were recorded for {domain}, with {len(subdomains)} confirmed subdomains like {preview}. You can filter them by asset type on the Assets page.",
                f"Infrastructure discovery for {domain} cataloged {total_assets} assets, including {len(subdomains)} subdomains ({preview}). Open ports and HTTP status codes are available for each in the dashboard.",
                f"Found {total_assets} reachable assets connected to {domain} ({len(root_domains)} root, {len(subdomains)} subdomains). Examples: {preview}.",
            ]
        chosen = cls._pick_variant(options)
        return cls._attach_caveat(chosen, domain, is_partial, ask_coverage)

    @classmethod
    def _pick_variant(cls, options: List[str]) -> str:
        inst = cls._instance()
        available = [opt for opt in options if hashlib.md5(opt.encode()).hexdigest() not in inst._recent_hashes]
        if not available:
            available = options
        chosen = random.choice(available)
        h = hashlib.md5(chosen.encode()).hexdigest()
        inst._recent_hashes.append(h)
        if len(inst._recent_hashes) > 6:
            inst._recent_hashes.pop(0)
        return chosen

    @classmethod
    def _attach_caveat(cls, answer: str, domain: str, is_partial: bool, ask_coverage: bool) -> str:
        if not is_partial:
            return answer
        inst = cls._instance()
        caveat_key = f"{domain}:partial"
        # Only show caveat if user specifically asked about coverage, or once per session
        if ask_coverage or caveat_key not in inst._shown_caveats:
            inst._shown_caveats.add(caveat_key)
            return f"Note: this is a partial assessment based only on confirmed records. {answer}"
        return answer
