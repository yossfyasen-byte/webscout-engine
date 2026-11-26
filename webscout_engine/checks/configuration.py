"""Configuration and transport checks: headers, cookies, CORS, methods,
disclosure, redirects, HTTP behaviour, framing and TLS."""

from __future__ import annotations

from urllib.parse import urlsplit
from ..core.models import Confidence, Finding, Severity
from .base import BaseCheck, CheckMeta
from .registry import register
import re
from ..core.redaction import redact_evidence
from ..core.models import Confidence, Severity
from ..recon.crawl import set_query_param
from .helpers import load_payloads
from ..core.models import Confidence, Severity, Verification
from ..recon.crawl import canary
from .helpers import MAX_PARAMS, any_param
from ..core.models import Confidence, Finding, Severity, Verification
from ..recon.tech import WEAK_PROTOCOLS, inspect_tls


# -------------------------------------------------------------------------
# from headers.py
# -------------------------------------------------------------------------

@register
class SecurityHeadersCheck(BaseCheck):
    meta = CheckMeta(
        name="security-headers",
        title="Missing or weak HTTP security headers",
        description=(
            "Checks the response for the headers that instruct browsers to enforce "
            "transport security, framing rules, content-type sniffing protection and "
            "a restrictive content security policy."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        category="configuration",
        remediation=(
            "Set Strict-Transport-Security, Content-Security-Policy, "
            "X-Content-Type-Options: nosniff, X-Frame-Options (or CSP frame-ancestors), "
            "Referrer-Policy and Permissions-Policy at the edge or application layer."
        ),
        references=[
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
        ],
    )

    async def run(self) -> list:
        result = await self.get(self.ctx.base_url)
        if result is None or result.error or not result.status:
            return []
        headers = result.headers
        scheme = urlsplit(self.ctx.base_url).scheme
        endpoint = result.final_url or self.ctx.base_url
        findings: list[Finding] = []

        if scheme == "https" and "strict-transport-security" not in headers:
            findings.append(
                self.make_finding(
                    title="Missing Strict-Transport-Security header",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence="No Strict-Transport-Security header in the HTTPS response.",
                    impact=(
                        "Without HSTS a network attacker can downgrade the first visit to "
                        "plain HTTP and intercept session cookies."
                    ),
                )
            )

        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(
                self.make_finding(
                    title="Missing Content-Security-Policy header",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence="No Content-Security-Policy header in the response.",
                    impact=(
                        "Without a CSP the browser will execute any injected script, which "
                        "turns a single reflection into full cross-site scripting."
                    ),
                )
            )
        else:
            weak = [token for token in ("unsafe-inline", "unsafe-eval") if token in csp]
            if weak:
                findings.append(
                    self.make_finding(
                        title="Content-Security-Policy allows unsafe script sources",
                        severity=Severity.LOW,
                        endpoint=endpoint,
                        status_code=result.status,
                        evidence=f"Content-Security-Policy contains: {', '.join(weak)}",
                        impact="The policy no longer mitigates script injection.",
                    )
                )

        if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
            findings.append(
                self.make_finding(
                    title="Missing X-Content-Type-Options: nosniff",
                    severity=Severity.LOW,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence=f"x-content-type-options: {headers.get('x-content-type-options', '<absent>')}",
                    impact="Browsers may sniff content types and execute non-script responses.",
                )
            )

        frame_headers = "x-frame-options" in headers or "frame-ancestors" in csp
        if not frame_headers:
            findings.append(
                self.make_finding(
                    title="Missing clickjacking protection",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence="Neither X-Frame-Options nor CSP frame-ancestors is present.",
                    impact="The page can be framed by a third-party site and used for clickjacking.",
                )
            )

        if "referrer-policy" not in headers:
            findings.append(
                self.make_finding(
                    title="Missing Referrer-Policy header",
                    severity=Severity.LOW,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence="No Referrer-Policy header in the response.",
                    impact="Full URLs, including tokens in query strings, may leak to third parties.",
                )
            )

        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append(
                self.make_finding(
                    title="Missing Permissions-Policy header",
                    severity=Severity.INFO,
                    endpoint=endpoint,
                    status_code=result.status,
                    evidence="No Permissions-Policy (or Feature-Policy) header in the response.",
                    impact="Browser features such as camera, microphone and geolocation stay enabled for embedded content.",
                )
            )
        return findings


# -------------------------------------------------------------------------
# from cookies.py
# -------------------------------------------------------------------------

SESSION_HINTS = ("session", "sess", "sid", "auth", "token", "jwt", "login", "remember")


def parse_set_cookie(header_value: str) -> list[dict[str, object]]:
    """Parse one or more Set-Cookie lines into structured dictionaries."""
    cookies: list[dict[str, object]] = []
    for line in header_value.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name, _, value = parts[0].partition("=")
        attributes = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True) for p in parts[1:]}
        cookies.append(
            {
                "name": name.strip(),
                "value": value.strip(),
                "secure": "secure" in attributes,
                "httponly": "httponly" in attributes,
                "samesite": str(attributes.get("samesite", "")).lower(),
                "domain": str(attributes.get("domain", "")),
                "path": str(attributes.get("path", "")),
            }
        )
    return cookies


@register
class CookieAttributesCheck(BaseCheck):
    meta = CheckMeta(
        name="cookie-attributes",
        title="Insecure cookie attributes",
        description=(
            "Inspects Set-Cookie responses for missing Secure, HttpOnly and SameSite "
            "attributes and for session cookies that are not protected."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        category="configuration",
        remediation=(
            "Mark session cookies Secure and HttpOnly, set SameSite=Lax or Strict, and "
            "avoid Domain attributes that widen the cookie scope."
        ),
        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    )

    async def run(self) -> list:
        result = await self.get(self.ctx.base_url)
        if result is None or result.error:
            return []
        raw = result.headers.get("set-cookie", "")
        if not raw:
            return []
        scheme = urlsplit(self.ctx.base_url).scheme
        endpoint = result.final_url or self.ctx.base_url
        findings: list[Finding] = []

        for cookie in parse_set_cookie(raw):
            name = str(cookie["name"])
            issues: list[str] = []
            severity = Severity.LOW
            if scheme == "https" and not cookie["secure"]:
                issues.append("missing Secure attribute")
                severity = Severity.MEDIUM
            if not cookie["httponly"]:
                issues.append("missing HttpOnly attribute")
                if any(hint in name.lower() for hint in SESSION_HINTS):
                    severity = Severity.MEDIUM
            samesite = str(cookie["samesite"])
            if samesite not in ("lax", "strict"):
                issues.append(f"SameSite={samesite or 'unset'}")
            if not issues:
                continue
            findings.append(
                self.make_finding(
                    title=f"Cookie '{name}' is missing protective attributes",
                    severity=severity,
                    endpoint=endpoint,
                    status_code=result.status,
                    parameter=name,
                    evidence=f"Set-Cookie {name}: {'; '.join(issues)}",
                    impact=(
                        "Cookies without these attributes can be sent over plain HTTP, read "
                        "by injected scripts, or attached to cross-site requests."
                    ),
                )
            )
        return findings


# -------------------------------------------------------------------------
# from cors.py
# -------------------------------------------------------------------------

CANARY_ORIGIN = "https://webscout_engine-canary.invalid"


@register
class CorsPolicyCheck(BaseCheck):
    meta = CheckMeta(
        name="cors-policy",
        title="Permissive cross-origin resource sharing policy",
        description=(
            "Sends a canary Origin header and inspects Access-Control-Allow-Origin and "
            "Access-Control-Allow-Credentials to detect reflected or wildcard policies."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        category="configuration",
        remediation=(
            "Return Access-Control-Allow-Origin only for an explicit allow-list of trusted "
            "origins, and never combine a wildcard with credentials."
        ),
        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        endpoint = self.ctx.base_url
        for origin_value in (CANARY_ORIGIN, "null"):
            result = await self.get(endpoint, headers={"Origin": origin_value})
            if result is None or result.error or not result.status:
                continue
            allow_origin = result.header("access-control-allow-origin").strip()
            allow_creds = result.header("access-control-allow-credentials").strip().lower()
            if not allow_origin:
                continue
            if allow_origin == origin_value and allow_creds == "true":
                findings.append(
                    self.make_finding(
                        title="CORS reflects arbitrary origins with credentials",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        endpoint=result.final_url or endpoint,
                        status_code=result.status,
                        evidence=(
                            f"Origin: {origin_value} -> Access-Control-Allow-Origin: {allow_origin}; "
                            f"Access-Control-Allow-Credentials: true"
                        ),
                        impact=(
                            "Any website can read authenticated responses from this endpoint on "
                            "behalf of a logged-in victim."
                        ),
                    )
                )
            elif allow_origin == origin_value:
                findings.append(
                    self.make_finding(
                        title="CORS reflects arbitrary origins",
                        severity=Severity.MEDIUM,
                        endpoint=result.final_url or endpoint,
                        status_code=result.status,
                        evidence=(
                            f"Origin: {origin_value} -> Access-Control-Allow-Origin: {allow_origin}"
                        ),
                        impact=(
                            "Third-party sites can read unauthenticated responses, which often "
                            "exposes internal identifiers and metadata."
                        ),
                    )
                )
            elif allow_origin == "*" and allow_creds == "true":
                findings.append(
                    self.make_finding(
                        title="CORS wildcard combined with credentials",
                        severity=Severity.MEDIUM,
                        endpoint=result.final_url or endpoint,
                        status_code=result.status,
                        evidence=(
                            "Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true"
                        ),
                        impact="The combination is invalid in browsers but signals a broken policy that often degrades into origin reflection.",
                    )
                )
            elif allow_origin == "*":
                findings.append(
                    self.make_finding(
                        title="CORS allows any origin",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or endpoint,
                        status_code=result.status,
                        evidence="Access-Control-Allow-Origin: *",
                        impact="Public cross-origin reads are permitted for this resource.",
                    )
                )
            if findings:
                break
        return findings


# -------------------------------------------------------------------------
# from methods.py
# -------------------------------------------------------------------------

RISKY_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND"}


@register
class HttpMethodsCheck(BaseCheck):
    meta = CheckMeta(
        name="http-methods",
        title="Risky or unnecessary HTTP methods exposed",
        description=(
            "Reads the Allow header from an OPTIONS response and checks whether TRACE "
            "is answered. Only non-mutating methods are used."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        category="configuration",
        remediation="Disable unused methods at the server or reverse proxy and disable TRACE entirely.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        options = await self.get(self.ctx.base_url, allow_redirects=False)
        if options is not None and not options.error:
            allow = options.header("allow") or options.header("access-control-allow-methods")
            if allow:
                advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
                risky = sorted(advertised & RISKY_METHODS)
                if risky:
                    findings.append(
                        self.make_finding(
                            title=f"Server advertises risky HTTP methods: {', '.join(risky)}",
                            severity=Severity.LOW,
                            endpoint=options.final_url or self.ctx.base_url,
                            method="OPTIONS",
                            status_code=options.status,
                            evidence=f"Allow: {allow}",
                            impact=(
                                "Advertised write or debug methods widen the attack surface if the "
                                "application does not enforce authorisation on them."
                            ),
                        )
                    )

        trace = await self._trace()
        if trace is not None and trace.status == 200 and "TRACE" in trace.body.upper():
            findings.append(
                self.make_finding(
                    title="HTTP TRACE method is enabled",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    endpoint=trace.final_url or self.ctx.base_url,
                    method="TRACE",
                    status_code=trace.status,
                    evidence="TRACE request was echoed back in the response body.",
                    impact="TRACE can be combined with legacy browser bugs to steal cookies and auth headers.",
                )
            )
        return findings

    async def _trace(self):
        if self.ctx.cancelled:
            return None
        try:
            return await self.ctx.http.request("TRACE", self.ctx.base_url, allow_redirects=False)
        except Exception:
            return None


# -------------------------------------------------------------------------
# from disclosure.py
# -------------------------------------------------------------------------

DEBUG_PATHS = (
    "debug",
    "__debug__",
    "actuator/env",
    "actuator/health",
    "server-status",
    "phpinfo.php",
    "console",
    "trace",
    "elmah.axd",
)

STACK_TRACE_PATTERNS = (
    r"Traceback \(most recent call last\)",
    r"<b>Fatal error</b>",
    r"Notice: Undefined (variable|index)",
    r"Warning: mysqli?_",
    r"SQLSTATE\[",
    r"at java\.lang\.",
    r"System\.NullReferenceException",
    r"Whoops\\Exception",
    r"DEBUG = True",
    r"werkzeug\.debug",
)

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache")

SENSITIVE_COMMENT_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token|todo|fixme|internal|staging|debug)"
)


def is_directory_listing(body: str) -> bool:
    lowered = body.lower()
    return (
        "<title>index of /" in lowered
        or "directory listing for" in lowered
        or ("<pre>" in lowered and "<a href=\"" in lowered and "parent directory" in lowered)
    )


@register
class InformationDisclosureCheck(BaseCheck):
    meta = CheckMeta(
        name="information-disclosure",
        title="Information disclosure",
        description=(
            "Looks for version banners, verbose error pages, exposed diagnostic endpoints, "
            "directory listings and sensitive HTML comments."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="disclosure",
        remediation=(
            "Remove or genericise banner headers, disable debug mode in production, "
            "return uniform error pages and disable directory indexing."
        ),
        references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        base = await self.get(self.ctx.base_url)
        if base is None or base.error or not base.status:
            return findings
        endpoint = base.final_url or self.ctx.base_url

        for header in VERSION_HEADERS:
            value = base.header(header)
            if not value:
                continue
            if re.search(r"\d+\.\d+", value) or header != "server":
                findings.append(
                    self.make_finding(
                        title=f"Technology version disclosed in '{header}' header",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        endpoint=endpoint,
                        status_code=base.status,
                        evidence=f"{header}: {value}",
                        impact="Exact versions let an attacker select matching public exploits without probing.",
                    )
                )

        for pattern in STACK_TRACE_PATTERNS:
            match = re.search(pattern, base.body, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 60)
                snippet = base.body[start : match.end() + 120]
                findings.append(
                    self.make_finding(
                        title="Verbose error output exposes internal details",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=endpoint,
                        status_code=base.status,
                        evidence=redact_evidence(snippet),
                        impact="Stack traces reveal framework versions, file paths and query structure.",
                    )
                )
                break

        if is_directory_listing(base.body):
            findings.append(
                self.make_finding(
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    endpoint=endpoint,
                    status_code=base.status,
                    evidence="Response body contains an auto-generated directory index.",
                    impact="Files that were never meant to be public become enumerable.",
                )
            )

        for comment in (self.ctx.crawl.comments if self.ctx.crawl else [])[:20]:
            if SENSITIVE_COMMENT_RE.search(comment):
                findings.append(
                    self.make_finding(
                        title="Sensitive information in an HTML comment",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        endpoint=endpoint,
                        status_code=base.status,
                        evidence=redact_evidence(comment),
                        impact="Developer notes can reveal internal paths, endpoints or credentials.",
                    )
                )
                break

        for path in DEBUG_PATHS:
            if self.ctx.cancelled:
                break
            url = self.ctx.base_url.rstrip("/") + "/" + path
            result = await self.get(url, allow_redirects=False)
            if result is None or result.error or result.status != 200:
                continue
            if self.is_soft_404(result):
                continue
            body = result.body.lower()
            looks_like_debug = any(
                marker in body
                for marker in (
                    "actuator",
                    "phpinfo()",
                    "server status",
                    "debug toolbar",
                    "environment variables",
                    "stack trace",
                    "swagger",
                    "traceback",
                )
            )
            if looks_like_debug:
                findings.append(
                    self.make_finding(
                        title="Diagnostic endpoint reachable",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=url,
                        status_code=result.status,
                        evidence=f"GET /{path} returned 200 with diagnostic content.",
                        impact="Diagnostic endpoints frequently expose environment variables, connection strings and internal state.",
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from redirects.py
# -------------------------------------------------------------------------

CANARY_HOST = "webscout_engine-canary.invalid"
REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_url",
    "next", "url", "target", "dest", "destination", "continue", "callback", "goto",
    "out", "link", "forward",
}


@register
class OpenRedirectCheck(BaseCheck):
    meta = CheckMeta(
        name="open-redirect",
        title="Open redirect",
        description=(
            "Places a canary host in redirect-style parameters and checks whether it is "
            "emitted in the Location header. The redirect is never followed."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="validation",
        remediation=(
            "Resolve redirect targets against an allow-list of local paths and reject any "
            "absolute URL that leaves the application origin."
        ),
        references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
    )

    async def run(self) -> list:
        findings = []
        candidates = [p for p in self.ctx.params if p.name.lower() in REDIRECT_PARAMS]
        variants = [
            payload.replace("evil.com", CANARY_HOST).replace("evil.example", CANARY_HOST)
            for payload in load_payloads("redirect")[:14]
        ] or [f"https://{CANARY_HOST}/zs", f"//{CANARY_HOST}/zs"]
        for param in candidates[:6]:
            for value in variants:
                if self.ctx.cancelled:
                    break
                target = param.url or self.ctx.base_url
                url = set_query_param(target, param.name, value)
                result = await self.get(url, allow_redirects=False)
                if result is None or result.error:
                    continue
                location = result.header("location")
                if CANARY_HOST in location:
                    findings.append(
                        self.make_finding(
                            title=f"Open redirect via parameter '{param.name}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            endpoint=result.final_url or url,
                            parameter=param.name,
                            status_code=result.status,
                            evidence=f"Location: {location[:200]}",
                            impact=(
                                "Attackers can craft trusted links that bounce users to a "
                                "malicious site, which undermines phishing defences."
                            ),
                        )
                    )
                    break
        return findings


@register
class HostHeaderCheck(BaseCheck):
    meta = CheckMeta(
        name="host-header-injection",
        title="Host header reflection or CRLF header injection",
        description=(
            "Sends a canary Host / X-Forwarded-Host value and an encoded CRLF sequence to "
            "detect reflection in links or injected response headers."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="validation",
        remediation=(
            "Validate the Host header against configured virtual hosts, ignore forwarding "
            "headers from untrusted sources and reject CR/LF characters in all inputs."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"],
    )

    async def run(self) -> list:
        findings = []
        endpoint = self.ctx.base_url

        for header in ("X-Forwarded-Host", "X-Forwarded-For-Host"):
            result = await self.get(endpoint, headers={header: CANARY_HOST})
            if result is None or result.error:
                continue
            if CANARY_HOST in result.body or CANARY_HOST in result.header("location"):
                findings.append(
                    self.make_finding(
                        title=f"{header} is reflected in the response",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or endpoint,
                        status_code=result.status,
                        evidence=f"{header}: {CANARY_HOST} appears in the response output.",
                        impact=(
                            "Reflected forwarding headers enable cache poisoning and password "
                            "reset link hijacking when the application builds absolute URLs."
                        ),
                    )
                )
                break

        params = self.target_params[:3]
        for param in params:
            if self.ctx.cancelled:
                break
            payload = "%0d%0aX-webscout_engine-Injected%3a%201"
            target = param.url or endpoint
            url = set_query_param(target, param.name, payload)
            result = await self.get(url, allow_redirects=False)
            if result is None or result.error:
                continue
            if "x-webscout_engine-injected" in result.headers:
                findings.append(
                    self.make_finding(
                        title=f"CRLF sequence injected into response headers via '{param.name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or url,
                        parameter=param.name,
                        status_code=result.status,
                        evidence="A response header 'X-webscout_engine-Injected' was created from user input.",
                        impact="Header injection enables response splitting, cache poisoning and cookie fixation.",
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from http_behaviour.py
# -------------------------------------------------------------------------

CACHE_HEADERS = ("x-cache", "cf-cache-status", "age", "x-varnish", "x-proxy-cache")


@register
class WebCacheMisconfigurationCheck(BaseCheck):
    meta = CheckMeta(
        name="web-cache-misconfiguration",
        title="Web cache misconfiguration",
        description=(
            "Checks whether an unkeyed header is reflected into a cacheable response, and "
            "whether a response that sets cookies is cacheable."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Include every reflected header in the cache key, strip unkeyed headers at the edge "
            "and mark authenticated responses private or no-store."
        ),
        references=["https://portswigger.net/web-security/web-cache-poisoning"],
    )

    async def run(self) -> list:
        findings: list = []
        token = canary()
        base = await self.get(self.ctx.base_url)
        if base is None or base.error:
            return findings

        cache_control = base.header("cache-control").lower()
        cacheable = (
            any(base.header(header) for header in CACHE_HEADERS)
            or "public" in cache_control
            or "max-age" in cache_control
        )

        for header in ("X-Forwarded-Host", "X-Host", "X-Original-URL"):
            result = await self.get(self.ctx.base_url, headers={header: f"{token}.invalid"})
            if result is None or result.error:
                continue
            if token not in result.body:
                continue
            findings.append(
                self.make_finding(
                    title=f"Unkeyed header '{header}' is reflected into the response",
                    severity=Severity.MEDIUM if cacheable else Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    endpoint=result.final_url or self.ctx.base_url,
                    status_code=result.status,
                    evidence=(
                        f"{header}: {token}.invalid appears in the body"
                        + (" and the response is cacheable" if cacheable else
                           "; no cache header was observed, so impact depends on an upstream cache")
                    ),
                    impact=(
                        "When a shared cache stores this response, an attacker can poison the "
                        "cached copy for other users (host header poisoning, redirect or script injection)."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
            break

        if base.header("set-cookie") and "no-store" not in cache_control and "private" not in cache_control:
            findings.append(
                self.make_finding(
                    title="Response sets a cookie without Cache-Control: no-store",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    endpoint=base.final_url or self.ctx.base_url,
                    status_code=base.status,
                    evidence=f"Set-Cookie present; Cache-Control: {cache_control or '<absent>'}",
                    impact="An intermediary cache may store a personalised response.",
                    verification=Verification.INDICATOR,
                )
            )
        return findings


@register
class ParameterPollutionCheck(BaseCheck):
    meta = CheckMeta(
        name="parameter-pollution",
        title="HTTP parameter pollution",
        description=(
            "Sends the same parameter twice with different values and checks whether both are "
            "consumed by the application."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Read the first or last occurrence deterministically, reject duplicates, and keep "
            "the same rule at every layer (proxy, framework, application)."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"],
    )

    async def run(self) -> list:
        findings: list = []
        for param in any_param(self.target_params, MAX_PARAMS):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            first = canary("alpha")
            second = canary("beta")
            separator = "&" if "?" in target else "?"
            url = f"{target}{separator}{param.name}={first}&{param.name}={second}"
            result = await self.get(url)
            if result is None or result.error or not result.body:
                continue
            if first in result.body and second in result.body:
                findings.append(
                    self.make_finding(
                        title=f"Duplicate '{param.name}' parameters are both used",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        endpoint=result.final_url or target,
                        parameter=param.name,
                        status_code=result.status,
                        evidence="Both duplicate values appear in the response body.",
                        impact=(
                            "Divergent duplicate-parameter handling between a proxy and the "
                            "application enables filter bypass and cache key confusion."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


@register
class InsecureDeserializationCheck(BaseCheck):
    meta = CheckMeta(
        name="insecure-deserialization",
        title="Insecure deserialisation surface",
        description=(
            "Detects serialised object formats in cookies and hidden fields (Java stream, PHP "
            "object, ASP.NET ViewState without MAC)."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        remediation=(
            "Do not deserialise client-controlled data. Use a data format with a strict schema "
            "and sign state that must round-trip through the client."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        response = await self.get(self.ctx.base_url)
        if response is None or response.error:
            return findings

        for line in response.headers.get("set-cookie", "").split("\n"):
            if not line.strip():
                continue
            value = line.split(";", 1)[0]
            name = value.split("=", 1)[0]
            payload = value.split("=", 1)[1] if "=" in value else ""
            if payload.startswith("rO0AB"):
                findings.append(
                    self.make_finding(
                        title=f"Java serialised object in cookie '{name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=response.final_url or self.ctx.base_url,
                        parameter=name,
                        status_code=response.status,
                        evidence="Cookie value starts with the Java serialisation magic rO0AB.",
                        impact=(
                            "A client-controlled Java stream is deserialised server-side, which is "
                            "the classic remote code execution gadget path."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
            elif re.match(r"^O:\d+:\"", payload):
                findings.append(
                    self.make_finding(
                        title=f"PHP serialised object in cookie '{name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=response.final_url or self.ctx.base_url,
                        parameter=name,
                        status_code=response.status,
                        evidence="Cookie value matches the PHP serialize() object format.",
                        impact="unserialize() on client data enables object injection.",
                        verification=Verification.CONFIRMED,
                    )
                )

        body = response.body or ""
        if "__VIEWSTATE" in body and "__VIEWSTATEMAC" not in body and "__EVENTVALIDATION" not in body:
            findings.append(
                self.make_finding(
                    title="ASP.NET ViewState without a MAC or event validation field",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    endpoint=response.final_url or self.ctx.base_url,
                    status_code=response.status,
                    evidence="__VIEWSTATE is present but __VIEWSTATEMAC and __EVENTVALIDATION are not.",
                    impact=(
                        "Unsigned ViewState can be tampered with; the classic outcome is "
                        "deserialisation-based code execution."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
        return findings


@register
class MixedContentCheck(BaseCheck):
    meta = CheckMeta(
        name="mixed-content",
        title="Mixed content on an HTTPS page",
        description="Finds plain-HTTP sub-resources referenced from an HTTPS page.",
        severity=Severity.LOW,
        confidence=Confidence.CERTAIN,
        remediation="Serve every sub-resource over HTTPS and add upgrade-insecure-requests to the CSP.",
        references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
    )

    PATTERN = re.compile(
        r"""(?:src|href|action)\s*=\s*["']http://([^"']+)["']""", re.IGNORECASE
    )

    async def run(self) -> list:
        findings: list = []
        if urlsplit(self.ctx.base_url).scheme != "https":
            return findings
        response = await self.get(self.ctx.base_url)
        if response is None or response.error or not response.body:
            return findings
        hosts: list[str] = []
        for match in self.PATTERN.finditer(response.body):
            host = match.group(1).split("/", 1)[0]
            if host and host not in hosts:
                hosts.append(host)
        if hosts:
            findings.append(
                self.make_finding(
                    title="HTTPS page loads resources over plain HTTP",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    endpoint=response.final_url or self.ctx.base_url,
                    status_code=response.status,
                    evidence=f"Plain-HTTP resources: {', '.join(hosts[:5])}",
                    impact=(
                        "Mixed content can be modified in transit and is blocked by modern "
                        "browsers, which breaks the page."
                    ),
                    verification=Verification.CONFIRMED,
                )
            )
        return findings


# -------------------------------------------------------------------------
# from desync.py
# -------------------------------------------------------------------------

FRAMING_VARIANTS: tuple[tuple[str, dict[str, str], str], ...] = (
    ("CL.TE", {"Content-Length": "6", "Transfer-Encoding": "chunked"}, "0\r\n\r\nX"),
    ("TE.CL", {"Transfer-Encoding": "chunked", "Content-Length": "6"}, "0\r\n\r\nX"),
    ("TE space obfuscation", {"Transfer-Encoding": "chunked ", "Content-Length": "6"}, "0\r\n\r\nX"),
    ("TE tab obfuscation", {"Transfer-Encoding": "\tchunked", "Content-Length": "6"}, "0\r\n\r\nX"),
    ("TE duplicate", {"Transfer-Encoding": "chunked, chunked", "Content-Length": "6"}, "0\r\n\r\nX"),
    ("TE only", {"Transfer-Encoding": "chunked"}, "0\r\n\r\n"),
)


@register
class DesyncFramingCheck(BaseCheck):
    meta = CheckMeta(
        name="http-request-smuggling",
        title="Ambiguous HTTP framing (smuggling precondition)",
        description=(
            "Sends requests whose Content-Length and Transfer-Encoding disagree and records "
            "whether the server rejects them. Acceptance is the precondition for CL.TE/TE.CL "
            "desync and for cache poisoning through request splitting."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        category="configuration",
        remediation=(
            "Reject requests that carry both Content-Length and Transfer-Encoding, normalise "
            "framing at the edge and terminate HTTP/1.1 only once."
        ),
        references=["https://portswigger.net/web-security/request-smuggling"],
        cwe="CWE-444",
        cvss=6.5,
        scan_type="active",
        impact="low",
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        endpoint = self.ctx.base_url
        baseline = await self.get(endpoint)
        if baseline is None or baseline.error:
            return findings
        baseline_status = baseline.status

        accepted: list[str] = []
        rejected = 0
        for label, headers, body in FRAMING_VARIANTS:
            result = await self.ctx.http.post(
                endpoint,
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=body,
                allow_redirects=False,
            )
            if result is None or result.error:
                continue
            if result.status in (400, 411, 413, 501):
                rejected += 1
            elif 200 <= result.status < 500:
                accepted.append(f"{label} -> {result.status}")

        if accepted and rejected == 0:
            findings.append(
                self.make_finding(
                    title="Server accepts contradictory request framing",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    endpoint=endpoint,
                    method="POST",
                    status_code=baseline_status,
                    evidence="; ".join(accepted),
                    impact=(
                        "A front-end and back-end that disagree about request boundaries allow "
                        "request smuggling, which can poison the cache or bypass access control. "
                        "Confirmation needs a raw-socket CL.TE/TE.CL test in a controlled "
                        "environment."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
        return findings


# -------------------------------------------------------------------------
# from tls_check.py
# -------------------------------------------------------------------------

@register
class TlsConfigurationCheck(BaseCheck):
    meta = CheckMeta(
        name="tls-configuration",
        title="Weak TLS configuration",
        description=(
            "Verifies HTTPS availability, the negotiated protocol version, certificate "
            "trust, self-signing and remaining validity."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="transport",
        remediation=(
            "Serve TLS 1.2 or newer only, use a certificate from a trusted CA, enable "
            "automatic renewal and redirect all plain HTTP traffic to HTTPS."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        parts = urlsplit(self.ctx.base_url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        findings: list[Finding] = []

        info = self.ctx.tls
        if info is None:
            if not host:
                return findings
            info = await inspect_tls(host, 443 if port != 80 else 443, timeout=6.0)

        if not info.enabled:
            if parts.scheme == "https":
                findings.append(
                    self.make_finding(
                        title="HTTPS endpoint does not complete a TLS handshake",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=self.ctx.base_url,
                        evidence=f"TLS handshake failed: {info.error or 'unknown error'}",
                        impact="Traffic cannot be protected by transport encryption.",
                    )
                )
            else:
                findings.append(
                    self.make_finding(
                        title="Site is served over plain HTTP",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        endpoint=self.ctx.base_url,
                        evidence="The target URL uses the http scheme.",
                        impact="Credentials and session cookies travel in clear text.",
                    )
                )
            return findings

        if info.version in WEAK_PROTOCOLS:
            findings.append(
                self.make_finding(
                    title=f"Deprecated TLS protocol negotiated ({info.version})",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    endpoint=self.ctx.base_url,
                    evidence=f"Negotiated {info.version} with cipher {info.cipher or 'unknown'}",
                    impact="Deprecated protocols have known cryptographic weaknesses.",
                )
            )

        if not info.trusted:
            findings.append(
                self.make_finding(
                    title="TLS certificate is not trusted by a public CA",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    endpoint=self.ctx.base_url,
                    evidence=f"{info.error or 'certificate verification failed'}; subject={info.subject or 'n/a'}",
                    impact="Users cannot distinguish the site from an impersonation attempt.",
                )
            )
        elif info.self_signed:
            findings.append(
                self.make_finding(
                    title="TLS certificate is self-signed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    endpoint=self.ctx.base_url,
                    evidence=f"issuer == subject ({info.issuer or 'unknown'})",
                    impact="No third party vouches for the identity of the host.",
                )
            )

        if info.days_remaining is not None:
            if info.days_remaining < 0:
                findings.append(
                    self.make_finding(
                        title="TLS certificate has expired",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        endpoint=self.ctx.base_url,
                        evidence=f"Certificate expired {abs(info.days_remaining)} day(s) ago (notAfter={info.not_after})",
                        impact="Browsers block the site and users are trained to click through warnings.",
                    )
                )
            elif info.days_remaining < 30:
                findings.append(
                    self.make_finding(
                        title="TLS certificate expires soon",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        endpoint=self.ctx.base_url,
                        evidence=f"{info.days_remaining} day(s) remaining (notAfter={info.not_after})",
                        impact="An expired certificate causes a full outage for HTTPS clients.",
                    )
                )
        return findings
