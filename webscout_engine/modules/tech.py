"""Module: technology-specific probes.

Only runs the probe set for technologies that were actually fingerprinted on the
target. A probe never guesses: it requests one path and looks for one matcher.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity
from .base import BaseModule, ModuleOutcome


@dataclass(frozen=True)
class Probe:
    path: str
    title: str
    matcher: str
    severity: Severity
    impact: str
    remediation: str
    cwe: str = "CWE-200"


# technology name (as produced by the fingerprinter) -> probes
TECH_PROBES: dict[str, tuple[Probe, ...]] = {
    "WordPress": (
        Probe(
            "wp-json/wp/v2/users",
            "WordPress REST API exposes author accounts",
            r'"slug"\s*:',
            Severity.MEDIUM,
            "Usernames harvested here feed credential-stuffing attempts.",
            "Disable the users endpoint for anonymous callers or restrict it by role.",
            "CWE-200",
        ),
        Probe(
            "xmlrpc.php",
            "WordPress XML-RPC endpoint is enabled",
            r"XML-RPC server accepts POST requests",
            Severity.LOW,
            "XML-RPC enables high-volume password guessing and pingback abuse.",
            "Disable XML-RPC unless a plugin requires it.",
            "CWE-16",
        ),
        Probe(
            "readme.html",
            "WordPress readme discloses the version",
            r"WordPress",
            Severity.LOW,
            "The exact version shortens vulnerability selection.",
            "Remove readme.html from production.",
            "CWE-200",
        ),
    ),
    "Drupal": (
        Probe(
            "CHANGELOG.txt",
            "Drupal CHANGELOG discloses the version",
            r"Drupal \d",
            Severity.LOW,
            "Exact core version disclosure.",
            "Remove CHANGELOG.txt from the web root.",
        ),
    ),
    "Joomla": (
        Probe(
            "administrator/",
            "Joomla administrator login is reachable",
            r"Joomla|mod-login",
            Severity.LOW,
            "Administrative login exposed to the internet.",
            "Restrict /administrator/ by IP allow-list.",
        ),
    ),
    "Spring Boot": (
        Probe(
            "actuator/env",
            "Spring Boot actuator env is exposed",
            r"propertySources|activeProfiles",
            Severity.HIGH,
            "Environment properties often contain datasource credentials and keys.",
            "Disable actuator endpoints or require authentication.",
            "CWE-200",
        ),
        Probe(
            "actuator/mappings",
            "Spring Boot actuator mappings are exposed",
            r"\{.*mappings|dispatcherServlets",
            Severity.MEDIUM,
            "Every route, including internal ones, becomes enumerable.",
            "Restrict actuator to an internal management port.",
        ),
        Probe(
            "actuator/heapdump",
            "Spring Boot heapdump may be downloadable",
            r"\x00|HPROF|JAVA PROFILE",
            Severity.HIGH,
            "A heap dump contains in-memory credentials and tokens.",
            "Disable the heapdump endpoint.",
        ),
    ),
    "Laravel": (
        Probe(
            "telescope",
            "Laravel Telescope is publicly reachable",
            r"Telescope|telescope",
            Severity.HIGH,
            "Telescope records requests, queries, mail and jobs, including secrets.",
            "Restrict Telescope to local or authorised users.",
        ),
        Probe(
            "_ignition/health-check",
            "Laravel Ignition debug endpoint responds",
            r"can_execute_commands|ignition",
            Severity.MEDIUM,
            "Ignition has been the entry point for unauthenticated code execution when debug is on.",
            "Disable debug mode in production and remove Ignition.",
        ),
    ),
    "Django": (
        Probe(
            "admin/",
            "Django admin login is reachable",
            r"csrfmiddlewaretoken|Django administration",
            Severity.INFO,
            "Administrative login exposed (expected for many deployments).",
            "Restrict the admin path and enforce strong authentication.",
        ),
    ),
    "Jenkins": (
        Probe(
            "script",
            "Jenkins script console is reachable",
            r"Groovy|script console",
            Severity.CRITICAL,
            "The script console executes arbitrary Groovy on the controller.",
            "Require authentication and remove the console from untrusted networks.",
            "CWE-94",
        ),
        Probe(
            "asynchPeople/",
            "Jenkins user list is readable",
            r"People|user",
            Severity.LOW,
            "User enumeration on the CI server.",
            "Restrict anonymous read access.",
        ),
    ),
    "Grafana": (
        Probe(
            "api/health",
            "Grafana API is reachable",
            r"\"database\"\s*:\s*\"ok\"|commit",
            Severity.INFO,
            "Monitoring API version disclosure.",
            "Restrict Grafana to trusted networks.",
        ),
    ),
    "Elasticsearch": (
        Probe(
            "_cat/indices",
            "Elasticsearch index listing is public",
            r"health\s+status\s+index|green|yellow",
            Severity.CRITICAL,
            "Every index and document is readable without authentication.",
            "Enable Elasticsearch security and bind to a private interface.",
        ),
    ),
    "Kibana": (
        Probe(
            "api/status",
            "Kibana status API is reachable",
            r"\"status\"|\"version\"",
            Severity.LOW,
            "Analytics stack version disclosure.",
            "Restrict Kibana access.",
        ),
    ),
    "Docker Registry": (
        Probe(
            "v2/_catalog",
            "Docker registry catalog is readable",
            r"\"repositories\"",
            Severity.HIGH,
            "Every image and tag in the registry becomes enumerable.",
            "Require authentication on the registry.",
        ),
    ),
    "Microsoft IIS": (
        Probe(
            "trace.axd",
            "ASP.NET trace viewer is reachable",
            r"Trace Information|Application Trace",
            Severity.HIGH,
            "Request traces leak session identifiers and internal paths.",
            "Disable tracing in production.",
        ),
    ),
    "ASP.NET": (
        Probe(
            "elmah.axd",
            "ELMAH error log is reachable",
            r"Error Log|ELMAH",
            Severity.HIGH,
            "The error log exposes stack traces, connection strings and query text.",
            "Restrict elmah.axd to local requests.",
        ),
    ),
    "GitLab": (
        Probe(
            "users/sign_in",
            "GitLab sign-in page is reachable",
            r"GitLab",
            Severity.INFO,
            "Self-hosted GitLab instance identified.",
            "Keep GitLab patched; it has a history of critical authentication bypasses.",
        ),
    ),
    "Magento": (
        Probe(
            "admin",
            "Magento admin panel is reachable",
            r"adminhtml|Magento",
            Severity.LOW,
            "Administrative surface exposed.",
            "Restrict /admin by IP allow-list.",
        ),
    ),
    "Nuxt": (
        Probe(
            "_nuxt/",
            "Nuxt build directory is exposed",
            r"window\.__NUXT__|_nuxt",
            Severity.LOW,
            "Build artefacts can reveal routes and configuration.",
            "Serve only compiled assets, not the build directory.",
        ),
    ),
}


class TechnologyProbeModule(BaseModule):
    name = "tech"
    title = "Technology-Specific Probes"
    description = "Runs probe sets only for technologies fingerprinted on the target."

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        detected = [match.name for match in (ctx.tech_matches or [])]
        applicable = [name for name in detected if name in TECH_PROBES]

        if not detected:
            ctx.skip_module(
                self.name,
                "no technology was fingerprinted, so no technology-specific probe applies",
            )
            return outcome
        if not applicable:
            ctx.skip_module(
                self.name,
                f"detected technologies ({', '.join(detected[:6])}) have no probe set",
            )
            return outcome

        ctx.state.set_stage("technology probes")
        ctx.add_total(sum(len(TECH_PROBES[name]) for name in applicable))
        await ctx.emit(
            EventType.STAGE,
            f"Technology probes for: {', '.join(applicable)}",
            {"technologies": applicable},
        )

        for technology in applicable:
            for probe in TECH_PROBES[technology]:
                if ctx.cancel.is_cancelled:
                    return outcome
                ctx.state.set_operation(f"{technology}: /{probe.path}")
                url = ctx.base_url.rstrip("/") + "/" + probe.path.lstrip("/")
                result = await ctx.http.get(url, allow_redirects=False, retries=0)
                try:
                    if result.error or result.status not in (200, 206):
                        continue
                    if ctx.soft404.evaluate(result).is_soft:
                        continue
                    if not _matches(probe.matcher, result.body):
                        continue
                    outcome.observe(
                        Observation(
                            kind="technology",
                            target=ctx.base_url,
                            label=f"{technology} /{probe.path}",
                            status="reachable",
                            detail=probe.title,
                            severity=probe.severity,
                            metadata={"module": self.name, "technology": technology},
                        )
                    )
                    outcome.add(
                        self.finding(
                            title=f"{technology}: {probe.title}",
                            severity=probe.severity,
                            confidence=Confidence.HIGH,
                            module=self.name,
                            check="technology-probe",
                            endpoint=url,
                            status_code=result.status,
                            evidence=(
                                f"GET /{probe.path} returned {result.status} and matched "
                                f"/{probe.matcher}/"
                            ),
                            impact=probe.impact,
                            remediation=probe.remediation,
                            references=["https://owasp.org/www-project-top-ten/"],
                            cwe=probe.cwe,
                        )
                    )
                finally:
                    ctx.progress()

        outcome.notes.append(
            f"{len(applicable)} technology probe set(s) executed: {', '.join(applicable)}."
        )
        return outcome


def _matches(pattern: str, body: str) -> bool:
    import re

    try:
        return re.search(pattern, body or "", re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        return False
