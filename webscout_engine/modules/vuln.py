"""Module 4 - Web security assessment.

Runs the registered checks against the target. Every check is independent and
registered through the plugin registry, so the module only orchestrates.
"""

from __future__ import annotations

from ..checks import CheckContext, build_checks, load_checks, load_failures
from ..core.events import EventType
from ..core.models import Observation, Severity
from ..core.scope import join_url
from ..recon.crawl import Crawler
from ..recon.crawl import Parameter, dedupe_parameters, extract_query_params
from ..recon.tech import TechFingerprinter
from .base import BaseModule, ModuleOutcome


class WebSecurityModule(BaseModule):
    name = "vuln"
    title = "Web Security Assessment"
    description = "Modular, low-impact web checks with per-finding remediation."

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        ctx.state.set_stage("crawl")
        await ctx.emit(EventType.STAGE, "Web assessment: crawling and parameter discovery")

        crawl = ctx.crawl_result
        if crawl is None:
            crawl = await Crawler(ctx.http, ctx.base_url, max_pages=5, max_scripts=5, cancel=ctx.cancel).crawl()
            ctx.crawl_result = crawl

        params: list[Parameter] = list(extract_query_params(ctx.base_url))
        for form in crawl.forms:
            action = form.action or "/"
            action_url = action if action.startswith("http") else join_url(ctx.base_url, action)
            for field in form.fields:
                params.append(Parameter(name=field, value="", source="form", url=action_url))
        for link in crawl.links[:40]:
            params.extend(extract_query_params(link))
        ctx.params = dedupe_parameters(params)

        baseline = await ctx.http.get(ctx.base_url, allow_redirects=True)
        ctx.baseline_body = baseline.body or ""
        if not ctx.tech_matches and not baseline.error:
            ctx.tech_matches = TechFingerprinter.from_data().analyse(
                baseline.headers, baseline.body, server=baseline.header("server")
            )

        outcome.observe(
            Observation(
                kind="crawl",
                target=ctx.base_url,
                label="pages",
                status="crawled",
                detail=(
                    f"{len(crawl.pages)} page(s), {len(crawl.scripts)} script(s), "
                    f"{len(crawl.forms)} form(s), {len(ctx.params)} parameter(s)"
                ),
                metadata={"module": self.name},
            )
        )

        check_ctx = CheckContext(
            http=ctx.http,
            base_url=ctx.base_url,
            state=ctx.state,
            crawl=crawl,
            params=ctx.params,
            tech=ctx.tech_matches,
            tls=ctx.tls_info,
            soft404=ctx.soft404,
            cancel=ctx.cancel,
            baseline_body=ctx.baseline_body,
            blind_delay=ctx.options.blind_delay,
            max_blind_params=ctx.options.max_blind_params,
            active_forms=ctx.options.active_forms,
            concurrency=ctx.options.threads,
        )

        registry = load_checks()
        for module_name, reason in load_failures().items():
            ctx.note(f"Check module '{module_name}' was skipped: {reason}")
        selected = ctx.options.checks or None
        if selected:
            unknown = [name for name in selected if name not in registry]
            if unknown:
                ctx.note(f"Unknown check name(s) ignored: {', '.join(unknown)}")
        checks = build_checks(check_ctx, names=selected)
        if not checks:
            outcome.notes.append("No checks were selected.")
            return outcome

        ctx.add_total(len(checks))
        ctx.state.set_stage("checks")
        await ctx.emit(EventType.OPERATION, f"Running {len(checks)} web security checks")

        for check in checks:
            if ctx.cancel.is_cancelled:
                break
            ctx.state.set_operation(f"check: {check.meta.name}")
            await ctx.emit(
                EventType.OPERATION,
                f"Running check {check.meta.name} ({check.meta.title})",
                {"check": check.meta.name},
            )
            try:
                findings = await check.run()
            except Exception as exc:
                outcome.notes.append(f"Check {check.meta.name} failed: {type(exc).__name__}: {exc}")
                ctx.progress(failed=True)
                continue
            for finding in findings:
                outcome.add(finding)
            ctx.progress()

        outcome.notes.append(
            f"{len(checks)} checks executed, {len(outcome.findings)} finding(s)."
        )
        if outcome.findings:
            worst = min(outcome.findings, key=lambda f: f.severity.rank).severity
            outcome.observe(
                Observation(
                    kind="summary",
                    target=ctx.base_url,
                    label="highest severity",
                    status=worst.value,
                    detail=f"{len(outcome.findings)} finding(s) from {len(checks)} checks",
                    severity=Severity(worst),
                    metadata={"module": self.name},
                )
            )
        return outcome
