"""Module: the arsenal.

Runs the full probe catalogue (1 300+ probes across 28 sections) against the
target, streaming one event per probe, and folds the confirmed hits into the
normal finding model. Token analysis (JWT, serialised blobs) runs afterwards on
what the site actually served.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import parse_qsl, urlsplit

from ..core.events import EventType
from ..core.models import Confidence, Finding, Observation, Severity, Verification
from ..core.scope import join_url
from .base import BaseModule, ModuleOutcome
from ..recon.crawl import Crawler
from ..recon.crawl import Parameter, dedupe_parameters, extract_query_params
from ..arsenal.catalog import PROBE_COUNT, SECTION_LABELS, build_probes, section_counts
from ..arsenal.executor import ExecutorConfig, ProbeExecutor

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")
SERIALISED_RE = re.compile(
    r"(rO0AB|aced0005|O:\d+:\"|a:\d+:\{|__VIEWSTATE|AAEAAAD/////|gASV)"
)


class ArsenalModule(BaseModule):
    name = "arsenal"
    title = "Probe Arsenal"
    description = (
        "1 300+ catalogued probes across every web attack class, with differential "
        "judging and a live per-probe stream."
    )

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        profile = getattr(ctx.options, "arsenal_profile", "normal") or "normal"
        sections = tuple(getattr(ctx.options, "arsenal_sections", []) or ())
        probes = build_probes(profile)

        counts = section_counts(probes)
        ctx.state.set_stage("arsenal")
        await ctx.emit(
            EventType.STAGE,
            f"Probe arsenal: {len(probes)} probes across {len(counts)} sections",
            {"probes": len(probes), "sections": counts},
        )
        outcome.observe(
            Observation(
                kind="arsenal",
                target=ctx.base_url,
                label="catalogue",
                status="loaded",
                detail=", ".join(f"{name}={count}" for name, count in counts.items()),
                metadata={"module": self.name, "total": len(probes), "profile": profile},
            )
        )

        await self._ensure_surface(ctx, outcome)

        config = ExecutorConfig(
            concurrency=max(2, min(int(getattr(ctx.options, "threads", 16) or 16), 64)),
            max_params=max(1, int(getattr(ctx.options, "max_blind_params", 2) or 2)),
            blind_delay=float(getattr(ctx.options, "blind_delay", 2.0) or 2.0) + 2.0,
            sections=sections,
        )
        def _sink(hit) -> None:
            """First hit per endpoint becomes a finding; the rest confirm it."""
            if hit.probe.severity is Severity.INFO:
                outcome.observe(hit.to_observation(self.name))
            else:
                outcome.add(hit.to_finding(self.name))

        executor = ProbeExecutor(ctx, probes, config=config, hit_sink=_sink)
        result = await executor.run()

        # Findings are added live by the executor, one per endpoint + parameter.
        # Here we only record the confirmation count so the report is honest
        # about how many payloads actually worked.
        confirmations = len(result.hits) - len(
            {
                (hit.probe.section, hit.result.url.split("?", 1)[0], hit.extra.get("parameter") or "")
                for hit in result.hits
            }
        )
        if confirmations:
            outcome.notes.append(
                f"Arsenal: {confirmations} additional payload(s) confirmed the same endpoints."
            )

        for section in result.sections:
            if not section.total:
                continue
            outcome.observe(
                Observation(
                    kind="arsenal",
                    target=ctx.base_url,
                    label=f"{section.label} ({section.name})",
                    status="done",
                    detail=f"{section.done}/{section.total} probes, {section.hits} hit(s)",
                    severity=Severity.INFO,
                    metadata={"module": self.name, "section": section.name},
                )
            )

        outcome.findings.extend(self._analyse_tokens(ctx, result))

        outcome.notes.append(
            f"Arsenal: {result.requests} probes executed, {len(result.hits)} confirmed hit(s)."
        )
        return outcome

    # ------------------------------------------------------------------ setup
    async def _ensure_surface(self, ctx, outcome: ModuleOutcome) -> None:
        """Make sure we have parameters and a baseline before probing."""
        if ctx.crawl_result is None:
            ctx.state.set_operation("arsenal: crawling")
            ctx.crawl_result = await Crawler(
                ctx.http, ctx.base_url, max_pages=5, max_scripts=5, cancel=ctx.cancel
            ).crawl()

        params: list[Parameter] = list(extract_query_params(ctx.base_url))
        for form in ctx.crawl_result.forms:
            action = form.action or "/"
            action_url = action if action.startswith("http") else join_url(ctx.base_url, action)
            for field in form.fields:
                params.append(Parameter(name=field, value="", source="form", url=action_url))
        for link in ctx.crawl_result.links[:40]:
            params.extend(extract_query_params(link))
        ctx.params = dedupe_parameters(params)

        if not ctx.baseline_body:
            baseline = await ctx.http.get(ctx.base_url, allow_redirects=True)
            ctx.baseline_body = baseline.body or ""

        interesting = [p.name for p in ctx.params if p.interesting]
        await ctx.emit(
            EventType.INFO,
            f"Arsenal surface: {len(ctx.params)} parameters "
            f"({len(interesting)} interesting), {len(ctx.crawl_result.links)} links",
            {"params": len(ctx.params), "interesting": interesting[:20]},
        )
        if not interesting:
            outcome.notes.append(
                "No parameters were discovered; injection sections fall back to a "
                "default parameter name."
            )

    # --------------------------------------------------------------- analysis
    def _analyse_tokens(self, ctx, result) -> list[Finding]:
        findings: list[Finding] = []
        corpus_parts = [ctx.baseline_body or ""]
        for hit in result.hits:
            corpus_parts.append(hit.result.body or "")
        corpus = "\n".join(corpus_parts)

        for token in dict.fromkeys(JWT_RE.findall(corpus)):
            findings.append(self._jwt_finding(ctx, token))

        if SERIALISED_RE.search(corpus):
            findings.append(
                Finding(
                    title="Serialised object in a client-visible value",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    module=self.name,
                    check="deserialization-surface",
                    endpoint=ctx.base_url,
                    evidence=_snippet(corpus, SERIALISED_RE),
                    impact="A serialised blob (Java, PHP, .NET or pickle) is exposed to the client; if the server deserialises it back, code execution follows.",
                    remediation="Sign serialised state and never accept it from the client.",
                    cwe="CWE-502",
                    scan_type="passive",
                    verification=Verification.INDICATOR,
                )
            )
        return findings

    def _jwt_finding(self, ctx, token: str) -> Finding:
        header, payload = _decode_jwt(token)
        issues: list[str] = []
        severity = Severity.LOW
        if header.get("alg", "").lower() == "none":
            issues.append("alg=none (unsigned tokens accepted)")
            severity = Severity.CRITICAL
        if "exp" not in payload:
            issues.append("no exp claim (token never expires)")
            severity = max(severity, Severity.MEDIUM, key=lambda s: -s.rank)
        if "iss" not in payload:
            issues.append("no iss claim")
        if "aud" not in payload:
            issues.append("no aud claim")
        detail = "; ".join(issues) or "token structure exposed"
        return Finding(
            title="JWT exposed with weak claims",
            severity=severity,
            confidence=Confidence.HIGH,
            module=self.name,
            check="jwt-exposure",
            endpoint=ctx.base_url,
            evidence=f"header={json.dumps(header)[:200]} payload={json.dumps(payload)[:300]} issues={detail}",
            impact="A client-visible token reveals claims and, with alg=none, can be forged.",
            remediation="Pin the accepted algorithms, require exp/iss/aud and keep tokens out of HTML.",
            cwe="CWE-347",
            scan_type="passive",
            verification=Verification.CONFIRMED,
        )


def _decode_jwt(token: str) -> tuple[dict, dict]:
    def part(chunk: str) -> dict:
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")))
        except Exception:
            return {}

    pieces = token.split(".")
    header = part(pieces[0]) if pieces else {}
    payload = part(pieces[1]) if len(pieces) > 1 else {}
    return header, payload


def _snippet(text: str, pattern: re.Pattern[str], width: int = 120) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    start = max(0, match.start() - 20)
    return " ".join(text[start: match.end() + width].split())


def catalogue_summary() -> dict[str, int]:
    return section_counts(build_probes())


__all__ = ["ArsenalModule", "catalogue_summary", "PROBE_COUNT", "SECTION_LABELS"]
