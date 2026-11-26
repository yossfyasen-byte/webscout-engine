"""Source-side modules: static analysis and dependency analysis."""

from __future__ import annotations

from ..analysis.analysis import RULES, scan_tree
from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity, Verification
from ..core.redaction import redact_evidence
from .base import BaseModule, ModuleOutcome
from ..analysis.analysis import collect_dependencies, load_advisories, match_advisories


# -------------------------------------------------------------------------
# from code.py
# -------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SourceCodeModule(BaseModule):
    name = "code"
    title = "Source Code Analysis"
    description = "Pattern-based static analysis with file and line reporting."

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        source = ctx.options.source_path
        if not source:
            ctx.skip_module(self.name, "requires --source <path> to a local project tree")
            return outcome

        ctx.state.set_stage("static analysis")
        ctx.add_total(1)
        await ctx.emit(EventType.STAGE, f"Static analysis of {source}", {"source": source})

        summary = scan_tree(source)
        ctx.progress(failed=bool(summary.errors))

        for error in summary.errors[:5]:
            ctx.note(f"SAST: {error}")

        for match in summary.matches:
            rule = match.rule
            outcome.add(
                self.finding(
                    title=f"{rule.title} ({match.path}:{match.line})",
                    severity=SEVERITY_MAP.get(rule.severity, Severity.MEDIUM),
                    confidence=Confidence.HIGH if rule.confidence == "high" else Confidence.MEDIUM,
                    module=self.name,
                    check=rule.id.lower(),
                    endpoint=f"{match.path}:{match.line}",
                    method="STATIC",
                    evidence=redact_evidence(match.snippet, limit=200),
                    impact=rule.impact,
                    remediation=rule.remediation,
                    references=[f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[1]}.html"],
                )
            )
            finding = outcome.findings[-1]
            finding.cwe = rule.cwe
            finding.scan_type = "source"
            finding.verification = (
                Verification.CONFIRMED if rule.confidence == "high" else Verification.INDICATOR
            )

        for language, count in sorted(summary.languages.items()):
            outcome.observe(
                Observation(
                    kind="source",
                    target=source,
                    label=language,
                    status="analysed",
                    detail=f"{count} file(s)",
                    metadata={"module": self.name},
                )
            )

        outcome.notes.append(
            f"{summary.files_scanned} file(s) analysed, {summary.files_skipped} skipped "
            f"(size or access), {len(summary.matches)} rule hit(s) from {len(RULES)} rules."
        )
        if summary.files_scanned == 0:
            ctx.skip_module(self.name, f"no analysable source file found under {source}")
        return outcome


# -------------------------------------------------------------------------
# from deps.py
# -------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class DependencyModule(BaseModule):
    name = "deps"
    title = "Dependency Analysis"
    description = "Inventory of declared dependencies plus offline advisory matching."

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        source = ctx.options.source_path
        if not source:
            ctx.skip_module(self.name, "requires --source <path> to a local project tree")
            return outcome

        ctx.state.set_stage("dependency inventory")
        ctx.add_total(1)
        await ctx.emit(EventType.STAGE, f"Dependency inventory of {source}", {"source": source})

        dependencies, manifests, notes = collect_dependencies(source)
        ctx.progress(failed=not dependencies)
        for note in notes:
            ctx.note(f"SCA: {note}")

        for dependency in dependencies[:200]:
            outcome.observe(
                Observation(
                    kind="dependency",
                    target=dependency.source,
                    label=f"{dependency.name} {dependency.version or '(unpinned)'}",
                    status=dependency.ecosystem,
                    detail=dependency.declared or dependency.version,
                    metadata={"module": self.name, "ecosystem": dependency.ecosystem},
                )
            )

        advisories = load_advisories()
        matches = match_advisories(dependencies, advisories)
        for dependency, advisory in matches:
            outcome.add(
                self.finding(
                    title=f"{dependency.name} {dependency.version} matches {advisory.id}",
                    severity=SEVERITY_MAP.get(advisory.severity, Severity.MEDIUM),
                    confidence=Confidence.LOW,
                    module=self.name,
                    check="dependency-vulnerability",
                    endpoint=f"{dependency.source}:{dependency.name}",
                    method="STATIC",
                    evidence=(
                        f"Manifest {dependency.source} declares {dependency.name} "
                        f"{dependency.version}; the bundled advisory map lists {advisory.id} "
                        f"for versions {advisory.affected}. Confirm the deployed version "
                        f"before treating this as exploitable."
                    ),
                    impact=advisory.summary,
                    remediation=(
                        f"Upgrade {dependency.name} past {advisory.affected} and verify the "
                        f"change against the vendor advisory."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{advisory.id}"],
                )
            )
            finding = outcome.findings[-1]
            finding.cwe = advisory.cwe
            finding.scan_type = "source"
            finding.verification = Verification.INDICATOR

        outcome.notes.append(
            f"{len(dependencies)} dependency declaration(s) parsed from "
            f"{', '.join(manifests) if manifests else 'no manifest'}; "
            f"{len(matches)} advisory match(es)."
        )
        if not manifests:
            ctx.skip_module(self.name, "no supported manifest or lockfile was found")
        return outcome
