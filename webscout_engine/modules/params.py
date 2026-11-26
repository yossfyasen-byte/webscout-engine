"""Module: hidden parameter discovery.

Crawling only finds parameters that appear in links and forms. Many applications
accept others silently (`?debug=1`, `?format=json`, `?admin=true`), and those are
exactly where injection checks need to look. This module appends each name from
the bundled wordlist with a canary value and keeps the ones that change the
response, then hands them to the web module.
"""

from __future__ import annotations

from pathlib import Path

from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity
from ..recon.crawl import Parameter, canary, set_query_param
from .base import BaseModule, ModuleOutcome

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MAX_REQUESTS = 200


def load_param_names(path: Path | None = None) -> list[str]:
    source = path or (DATA_DIR / "params.txt")
    if not source.exists():
        return []
    names: dict[str, None] = {}
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            names.setdefault(clean, None)
    return list(names)[:MAX_REQUESTS]


class ParameterDiscoveryModule(BaseModule):
    name = "params"
    title = "Hidden Parameter Discovery"
    description = "Finds accepted-but-undocumented query parameters."

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        names = load_param_names()
        if not names:
            ctx.skip_module(self.name, "the parameter wordlist is missing")
            return outcome

        known = {param.name for param in (ctx.params or [])}
        candidates = [name for name in names if name not in known]
        if not candidates:
            ctx.skip_module(self.name, "every wordlist parameter is already known from crawling")
            return outcome

        ctx.state.set_stage("parameter discovery")
        ctx.add_total(len(candidates) + 1)
        await ctx.emit(
            EventType.OPERATION,
            f"Testing {len(candidates)} candidate parameter names",
            {"count": len(candidates)},
        )

        baseline = await ctx.http.get(ctx.base_url, retries=0)
        ctx.progress()
        if baseline.error:
            outcome.notes.append("parameter discovery skipped: the base page did not respond")
            return outcome

        baseline_length = baseline.body_length
        baseline_status = baseline.status
        discovered: list[Parameter] = []

        for name in candidates:
            if ctx.cancel.is_cancelled:
                break
            ctx.state.set_operation(f"param: {name}")
            value = canary("p")
            url = set_query_param(ctx.base_url, name, value)
            try:
                result = await ctx.http.get(url, retries=0)
            except Exception:
                ctx.progress(failed=True)
                continue
            finally:
                ctx.progress()
            if result.error or not result.status:
                continue
            if result.status != baseline_status:
                changed, reason = True, f"status {baseline_status} -> {result.status}"
            elif result.body_length != baseline_length and abs(
                result.body_length - baseline_length
            ) > max(40, baseline_length * 0.02):
                changed = True
                reason = f"length {baseline_length} -> {result.body_length}"
            elif value in result.body:
                changed, reason = True, "value reflected"
            else:
                changed = False
                reason = ""
            if not changed:
                continue
            discovered.append(Parameter(name=name, value="", source="discovered", url=ctx.base_url))
            outcome.observe(
                Observation(
                    kind="parameter",
                    target=ctx.base_url,
                    label=name,
                    status="accepted",
                    detail=reason,
                    severity=Severity.INFO,
                    metadata={"module": self.name},
                )
            )

        if discovered:
            ctx.params = list(ctx.params or []) + discovered
            outcome.add(
                self.finding(
                    title=f"{len(discovered)} undocumented query parameter(s) accepted",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH if len(discovered) > 2 else Confidence.MEDIUM,
                    module=self.name,
                    check="hidden-parameter",
                    endpoint=ctx.base_url,
                    evidence=(
                        "Parameters that change the response: "
                        + ", ".join(param.name for param in discovered[:12])
                        + (" ..." if len(discovered) > 12 else "")
                    ),
                    impact=(
                        "Undocumented parameters widen the input surface and are frequently "
                        "forgotten in validation; they are now included in the injection checks."
                    ),
                    remediation=(
                        "Remove debug and feature parameters from production, or validate them "
                        "against a strict allow-list."
                    ),
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    cwe="CWE-1059",
                )
            )

        outcome.notes.append(
            f"{len(candidates)} parameter names tested, {len(discovered)} accepted by the application."
        )
        if not discovered:
            ctx.note("parameter discovery found no additional accepted parameter")
        return outcome
