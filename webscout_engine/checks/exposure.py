"""Exposure and API surface checks: API discovery, secrets in responses and
subdomain takeover."""

from __future__ import annotations

import json
import re
from ..core.models import Confidence, Severity, Verification
from .base import BaseCheck, CheckMeta
from .registry import register
import ipaddress
from ..core.redaction import redact_evidence
import asyncio
from ..core.models import Confidence, Finding, Severity, Verification


# -------------------------------------------------------------------------
# from api_surface.py
# -------------------------------------------------------------------------

INTROSPECTION_QUERY = '{"query":"{__schema{types{name kind}}}"}'
SUGGESTION_QUERY = '{"query":"{__typename zzzNotAField}"}'
DEPTH_QUERY = '{"query":"{__schema{types{fields{type{fields{type{fields{name}}}}}}}}"}'


@register
class GraphqlSecurityCheck(BaseCheck):
    meta = CheckMeta(
        name="graphql-security",
        title="GraphQL introspection and query limits",
        description=(
            "Sends three read-only GraphQL queries: schema introspection, a field suggestion "
            "probe and a deeply nested query to check for a depth limit."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Disable introspection in production, turn off field suggestions and enforce query "
            "depth and cost limits."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
    )

    async def _post(self, url: str, query: str):
        if self.ctx.cancelled:
            return None
        try:
            return await self.ctx.http.post(
                url, data=query, headers={"Content-Type": "application/json"}, allow_redirects=False
            )
        except Exception:
            return None

    async def run(self) -> list:
        findings: list = []
        endpoint = self.ctx.base_url.rstrip("/") + "/graphql"
        probe = await self._post(endpoint, '{"query":"{__typename}"}')
        if probe is None or probe.error or probe.status != 200 or '"data"' not in probe.body:
            return findings

        schema = await self._post(endpoint, INTROSPECTION_QUERY)
        if schema is not None and not schema.error and '"__schema"' in schema.body:
            try:
                types = json.loads(schema.body)["data"]["__schema"]["types"]
                type_count = len(types)
            except (ValueError, KeyError, TypeError):
                type_count = 0
            findings.append(
                self.make_finding(
                    title="GraphQL introspection is enabled",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    endpoint=endpoint,
                    method="POST",
                    status_code=schema.status,
                    evidence=f"__schema returned {type_count} type(s).",
                    impact=(
                        "The full schema, including internal fields and mutations, is published to "
                        "anonymous callers."
                    ),
                    verification=Verification.CONFIRMED,
                )
            )

        suggestions = await self._post(endpoint, SUGGESTION_QUERY)
        if suggestions is not None and not suggestions.error and "did you mean" in suggestions.body.lower():
            findings.append(
                self.make_finding(
                    title="GraphQL field suggestions are enabled",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    endpoint=endpoint,
                    method="POST",
                    status_code=suggestions.status,
                    evidence="An invalid field returned a 'Did you mean' suggestion.",
                    impact="Suggestions let a caller reconstruct the schema without introspection.",
                    verification=Verification.CONFIRMED,
                )
            )

        deep = await self._post(endpoint, DEPTH_QUERY)
        if deep is not None and not deep.error and deep.status == 200 and '"errors"' not in deep.body:
            findings.append(
                self.make_finding(
                    title="Deeply nested GraphQL query was accepted",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    endpoint=endpoint,
                    method="POST",
                    status_code=deep.status,
                    evidence="A four-level nested query returned data without a depth error.",
                    impact="Without depth or cost limits a single query can exhaust the server.",
                    verification=Verification.INDICATOR,
                )
            )
        return findings


@register
class ApiInventoryCheck(BaseCheck):
    meta = CheckMeta(
        name="api-inventory",
        title="Multiple API versions exposed",
        description="Probes common version prefixes and reports when several respond.",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        remediation=(
            "Retire superseded API versions, publish a deprecation policy and keep an inventory "
            "of every reachable endpoint."
        ),
        references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"],
    )

    VERSIONS = ("api/v1/", "api/v2/", "api/v3/", "v1/", "v2/", "api/beta/")

    async def run(self) -> list:
        findings: list = []
        alive: list[str] = []
        for version in self.VERSIONS:
            if self.ctx.cancelled:
                break
            url = self.ctx.base_url.rstrip("/") + "/" + version
            result = await self.get(url, allow_redirects=False)
            if result is None or result.error or result.status != 200:
                continue
            if self.is_soft_404(result):
                continue
            alive.append(version.rstrip("/"))
        if len(alive) >= 2:
            findings.append(
                self.make_finding(
                    title=f"{len(alive)} API versions are reachable at once",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    endpoint=self.ctx.base_url,
                    evidence=f"Reachable versions: {', '.join(alive)}",
                    impact=(
                        "Old versions are rarely patched and often lack the authorisation rules "
                        "added to the current one."
                    ),
                    verification=Verification.OBSERVED,
                )
            )
        return findings


@register
class WebsocketEndpointCheck(BaseCheck):
    meta = CheckMeta(
        name="websocket-endpoints",
        title="WebSocket endpoints in client code",
        description=(
            "Finds WebSocket URLs referenced by the client. The connection is not opened; the "
            "check only reports where authentication must be verified."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Authenticate the WebSocket handshake, validate Origin, and use wss:// on HTTPS pages."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html"],
    )

    PATTERN = re.compile(r"(wss?://[A-Za-z0-9_.\-:]+[A-Za-z0-9_\-./?=&%]*)")

    async def run(self) -> list:
        findings: list = []
        sources: list[str] = []
        crawl = self.ctx.crawl
        if crawl is not None:
            sources.extend(crawl.script_bodies.values())
        page = await self.get(self.ctx.base_url)
        if page is not None and not page.error:
            sources.append(page.body)
        endpoints: list[str] = []
        for text in sources:
            for match in self.PATTERN.finditer(text or ""):
                endpoint = match.group(1)
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        if not endpoints:
            return findings
        insecure = [item for item in endpoints if item.startswith("ws://")]
        findings.append(
            self.make_finding(
                title="WebSocket endpoint referenced by the client",
                severity=Severity.LOW if insecure else Severity.INFO,
                confidence=Confidence.MEDIUM,
                endpoint=endpoints[0],
                evidence=(
                    f"Endpoints: {', '.join(endpoints[:4])}"
                    + (" (unencrypted ws://)" if insecure else "")
                ),
                impact=(
                    "WebSocket handshakes bypass many HTTP authorisation layers; confirm the "
                    "server authenticates the connection and validates Origin."
                ),
                verification=Verification.INDICATOR,
            )
        )
        return findings


@register
class UploadFormCheck(BaseCheck):
    meta = CheckMeta(
        name="upload-form",
        title="File upload form present",
        description=(
            "Detects a file input in the page and reports the absence of a client-side accept "
            "restriction as a review item. Nothing is uploaded."
        ),
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        remediation=(
            "Validate type, extension and content server-side, store uploads outside the web "
            "root and serve them with a fixed content type."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
    )

    FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    FILE_INPUT = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?file", re.IGNORECASE)
    ACCEPT = re.compile(r"<input\b[^>]*accept\s*=", re.IGNORECASE)

    async def run(self) -> list:
        findings: list = []
        response = await self.get(self.ctx.base_url)
        if response is None or response.error or not response.body:
            return findings
        if not self.FILE_INPUT.search(response.body):
            return findings
        restricted = bool(self.ACCEPT.search(response.body))
        findings.append(
            self.make_finding(
                title="File upload form without a client-side type restriction"
                if not restricted
                else "File upload form present",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM if not restricted else Confidence.LOW,
                endpoint=response.final_url or self.ctx.base_url,
                status_code=response.status,
                evidence=(
                    "The page contains a file input"
                    + (" with no accept attribute." if not restricted else " with an accept attribute (client-side only).")
                ),
                impact=(
                    "Client-side restrictions are advisory. Confirm the server validates the "
                    "content type and stores uploads outside the web root."
                ),
                verification=Verification.INDICATOR,
            )
        )
        return findings


# -------------------------------------------------------------------------
# from secrets.py
# -------------------------------------------------------------------------

PATTERNS: tuple[tuple[str, str, str, Severity], ...] = (
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "CWE-798", Severity.CRITICAL),
    ("AWS secret key", r"(?i)aws_?secret_?access_?key[\"'\s:=]+([A-Za-z0-9/+=]{32,})", "CWE-798", Severity.CRITICAL),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{30,}\b", "CWE-798", Severity.HIGH),
    ("Stripe live key", r"\bsk_live_[0-9A-Za-z]{20,}\b", "CWE-798", Severity.CRITICAL),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b", "CWE-798", Severity.HIGH),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "CWE-798", Severity.HIGH),
    ("Private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "CWE-321", Severity.CRITICAL),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b", "CWE-522", Severity.MEDIUM),
    ("Bearer token", r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}=*)", "CWE-522", Severity.MEDIUM),
    ("Generic API key assignment", r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\"']([^\"'\s]{12,})", "CWE-798", Severity.HIGH),
    ("Basic auth in URL", r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]{4,})@", "CWE-798", Severity.HIGH),
    ("Internal hostname", r"\b(?:[a-z0-9-]+\.)+(?:internal|local|corp|lan|intranet|private)\b", "CWE-200", Severity.LOW),
)

PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


@register
class SecretInResponseCheck(BaseCheck):
    meta = CheckMeta(
        name="secret-in-response",
        title="Credential or internal detail in the response",
        description=(
            "Scans the page and its JavaScript bundles for API keys, private keys, tokens, "
            "internal hostnames and private IP addresses."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="disclosure",
        remediation=(
            "Never ship secrets to the client. Rotate anything exposed, move the call "
            "server-side and keep internal hostnames out of the bundle."
        ),
        references=["https://cwe.mitre.org/data/definitions/798.html"],
    )

    MAX_SOURCES = 8

    def _sources(self) -> list[tuple[str, str]]:
        sources: list[tuple[str, str]] = []
        page = self.ctx.baseline_body or ""
        if page:
            sources.append((self.ctx.base_url, page))
        crawl = self.ctx.crawl
        if crawl is not None:
            for url, body in list(crawl.script_bodies.items())[: self.MAX_SOURCES - 1]:
                sources.append((url, body))
        return sources

    async def run(self) -> list:
        findings: list = []
        for url, body in self._sources():
            if not body:
                continue
            for label, pattern, cwe, severity in PATTERNS:
                match = re.search(pattern, body, re.MULTILINE)
                if not match:
                    continue
                start = max(0, match.start() - 40)
                snippet = body[start : match.end() + 40]
                findings.append(
                    self.make_finding(
                        title=f"{label} found in {url.rsplit('/', 1)[-1] or 'the page'}",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        endpoint=url,
                        evidence=redact_evidence(snippet, limit=180),
                        impact=(
                            "A credential or internal identifier is delivered to every visitor, "
                            "where it can be copied from the page source or a bundle."
                        ),
                        cwe=cwe,
                        verification=Verification.CONFIRMED,
                    )
                )
            private_ips: list[str] = []
            for candidate in IP_PATTERN.findall(body):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if any(address in network for network in PRIVATE_RANGES):
                    private_ips.append(candidate)
            if private_ips:
                findings.append(
                    self.make_finding(
                        title="Private IP address in the response",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        endpoint=url,
                        evidence=f"Private address(es): {', '.join(dict.fromkeys(private_ips))[:160]}",
                        impact=(
                            "Internal addressing leaks the network layout and is a strong hint "
                            "for SSRF targets."
                        ),
                        cwe="CWE-200",
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


# -------------------------------------------------------------------------
# from takeover.py
# -------------------------------------------------------------------------

# provider suffix -> human name
CLAIMABLE: dict[str, str] = {
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "now.sh": "Vercel",
    "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "readme.io": "ReadMe",
    "unbouncepages.com": "Unbounce",
    "statuspage.io": "Statuspage",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout",
    "teamwork.com": "Teamwork",
    "desk.com": "Desk",
    "cargocollective.com": "Cargo",
    "feedpress.me": "FeedPress",
    "ghost.io": "Ghost",
    "hatenablog.com": "Hatena",
    "surveygizmo.com": "SurveyGizmo",
    "ngrok.io": "ngrok",
    "ngrok.app": "ngrok",
    "fly.dev": "Fly.io",
    "onrender.com": "Render",
    "web.app": "Firebase Hosting",
    "firebaseapp.com": "Firebase Hosting",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "repl.co": "Replit",
    "glitch.me": "Glitch",
}

COMMON_SUBDOMAINS: tuple[str, ...] = (
    "www", "blog", "shop", "status", "help", "support", "docs", "dev",
    "staging", "test", "demo", "app", "api", "cdn", "static", "assets",
    "mail", "portal", "dashboard", "admin", "careers", "news", "go",
)


@register
class SubdomainTakeoverCheck(BaseCheck):
    meta = CheckMeta(
        name="subdomain-takeover",
        title="Dangling CNAME pointing at a claimable service",
        description=(
            "Resolves the target and its common subdomains and reports CNAMEs that point at "
            "third-party platforms where an unclaimed name can be registered by anyone."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="exposure",
        remediation=(
            "Remove DNS records for decommissioned services, and keep an inventory that is "
            "checked whenever a third-party resource is deleted."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        cwe="CWE-350",
        cvss=8.1,
        scan_type="passive",
        impact="none",
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        host = (self.ctx.base_url.split("//", 1)[-1]).split("/", 1)[0].split(":", 1)[0]
        domain = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        names = [host] + [f"{prefix}.{domain}" for prefix in COMMON_SUBDOMAINS]
        if host.count(".") > 2:
            names = [host]
        try:
            import dns.asyncresolver  # noqa: F401
        except Exception:
            return findings

        for name in dict.fromkeys(names):
            chain = await self._cname_chain(name)
            for target in chain:
                for suffix, provider in CLAIMABLE.items():
                    if target.endswith(suffix):
                        findings.append(
                            self.make_finding(
                                title=f"Dangling CNAME to {provider}",
                                severity=Severity.HIGH,
                                confidence=Confidence.LOW,
                                endpoint=f"https://{name}",
                                status_code=None,
                                evidence=f"{name} -> {' -> '.join(chain)} (provider: {provider})",
                                impact=(
                                    f"If the {provider} resource behind {target} is unclaimed, "
                                    "anyone can register it and serve content on your domain."
                                ),
                                verification=Verification.INDICATOR,
                            )
                        )
                        break
                else:
                    continue
                break
        return findings

    async def _cname_chain(self, name: str) -> list[str]:
        import dns.asyncresolver
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        resolver.timeout = 3.0
        chain: list[str] = []
        current = name
        for _ in range(4):
            try:
                answer = await asyncio.wait_for(
                    resolver.resolve(current, "CNAME"), timeout=4.0
                )
            except (dns.exception.DNSException, asyncio.TimeoutError, Exception):
                break
            target = str(answer[0].target).rstrip(".").lower()
            chain.append(target)
            current = target
        return chain
