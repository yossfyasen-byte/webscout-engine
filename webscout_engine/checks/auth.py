"""Authentication, session and authorisation checks: sessions, CSRF, JWT,
OAuth, access control, mass assignment and the bypass matrix."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
from ..core.models import Confidence, Severity, Verification
from ..recon.crawl import canary
from .base import BaseCheck, CheckMeta
from .registry import register
import base64
import binascii
from urllib.parse import parse_qsl, urlsplit
from ..core.models import Confidence, Finding, Severity
from ..core.redaction import redact_evidence
from ..core.models import Confidence, Finding, Severity, Verification
import difflib
from ..recon.crawl import set_query_param


# -------------------------------------------------------------------------
# from auth_session.py
# -------------------------------------------------------------------------

TOKEN_FIELD = re.compile(
    r"(csrf|xsrf|authenticity|_token|token|nonce|requestverificationtoken)", re.IGNORECASE
)
SESSION_COOKIE = re.compile(r"(sess|sid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid)", re.IGNORECASE)


@register
class SessionConfigurationCheck(BaseCheck):
    meta = CheckMeta(
        name="session-configuration",
        title="Session management weakness",
        description=(
            "Looks for a session identifier issued before authentication, session cookies "
            "without an expiry, and identifiers accepted in URLs."
        ),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        remediation=(
            "Issue a new session identifier at login, set an idle and absolute timeout, and "
            "never accept session identifiers from the query string."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        response = await self.get(self.ctx.base_url)
        if response is None or response.error:
            return findings

        for line in response.headers.get("set-cookie", "").split("\n"):
            if not line.strip():
                continue
            name = line.split("=", 1)[0].strip()
            lowered = line.lower()
            if not SESSION_COOKIE.search(name):
                continue
            if "max-age" not in lowered and "expires" not in lowered:
                findings.append(
                    self.make_finding(
                        title=f"Session cookie '{name}' has no expiry",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        endpoint=response.final_url or self.ctx.base_url,
                        parameter=name,
                        status_code=response.status,
                        evidence=f"Set-Cookie {name}: no Max-Age or Expires attribute.",
                        impact=(
                            "The session lives as long as the browser tab, so an unattended device "
                            "keeps an authenticated session open."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
            if name.lower() in urlsplit(self.ctx.base_url).query.lower():
                findings.append(
                    self.make_finding(
                        title=f"Session identifier '{name}' is accepted in the URL",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=self.ctx.base_url,
                        parameter=name,
                        evidence="The session parameter appears in the query string.",
                        impact="Session identifiers in URLs leak through logs, referrers and browser history.",
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


@register
class CsrfProtectionCheck(BaseCheck):
    meta = CheckMeta(
        name="csrf-protection",
        title="Missing CSRF protection on a state-changing form",
        description=(
            "Inspects crawled POST forms for an anti-CSRF token field or a SameSite cookie."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        remediation=(
            "Add a per-session synchroniser token to every state-changing form and set "
            "SameSite=Lax or Strict on the session cookie."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        crawl = self.ctx.crawl
        if crawl is None or not crawl.forms:
            return findings
        for form in crawl.forms:
            if (form.method or "get").lower() != "post":
                continue
            if any(TOKEN_FIELD.search(field) for field in form.fields):
                continue
            action = form.action or self.ctx.base_url
            findings.append(
                self.make_finding(
                    title="POST form without an anti-CSRF token",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    endpoint=action,
                    method="POST",
                    evidence=(
                        f"Form action {action} posts fields "
                        f"({', '.join(form.fields[:6]) or 'none detected'}) with no token field."
                    ),
                    impact=(
                        "A third-party page can submit this form on behalf of a logged-in user "
                        "unless the session cookie is SameSite and the server checks Origin."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
        return findings


@register
class OauthConfigurationCheck(BaseCheck):
    meta = CheckMeta(
        name="oauth-configuration",
        title="OAuth 2.0 / OpenID Connect misconfiguration",
        description=(
            "Reads the OIDC discovery document and probes the authorize endpoint with an "
            "out-of-band redirect_uri. No authorisation code is requested or redeemed."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Register exact redirect URIs, require state and PKCE, disable the implicit flow and "
            "keep discovery documents free of internal endpoints."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        discovery_url = self.ctx.base_url.rstrip("/") + "/.well-known/openid-configuration"
        discovery = await self.get(discovery_url, allow_redirects=False)
        authorize_endpoint = ""
        if discovery is not None and not discovery.error and discovery.status == 200:
            try:
                payload = json.loads(discovery.body)
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                authorize_endpoint = str(payload.get("authorization_endpoint", ""))
                response_types = payload.get("response_types_supported") or []
                if "token" in [str(item).lower() for item in response_types]:
                    findings.append(
                        self.make_finding(
                            title="OIDC provider advertises the implicit flow",
                            severity=Severity.LOW,
                            confidence=Confidence.CERTAIN,
                            endpoint=discovery_url,
                            status_code=discovery.status,
                            evidence=f"response_types_supported: {response_types}",
                            impact=(
                                "The implicit flow returns tokens in the fragment, where they are "
                                "exposed to scripts and browser history."
                            ),
                            verification=Verification.CONFIRMED,
                        )
                    )
                if not payload.get("code_challenge_methods_supported"):
                    findings.append(
                        self.make_finding(
                            title="OIDC provider does not advertise PKCE support",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            endpoint=discovery_url,
                            status_code=discovery.status,
                            evidence="code_challenge_methods_supported is absent from the discovery document.",
                            impact="Public clients cannot bind the authorisation code to the requester.",
                            verification=Verification.INDICATOR,
                        )
                    )

        endpoint = authorize_endpoint or (self.ctx.base_url.rstrip("/") + "/oauth/authorize")
        if not endpoint.startswith("http"):
            endpoint = self.ctx.base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        canary_host = f"https://{canary('zs')}.invalid/callback"
        separator = "&" if "?" in endpoint else "?"
        probe_url = (
            f"{endpoint}{separator}response_type=code&client_id=webscout_engine"
            f"&redirect_uri={canary_host}&scope=openid&state=webscout_engine"
        )
        result = await self.get(probe_url, allow_redirects=False)
        if result is not None and not result.error:
            location = result.header("location")
            if canary_host.split("//")[-1] in location:
                findings.append(
                    self.make_finding(
                        title="Authorize endpoint accepts an unregistered redirect_uri",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=endpoint,
                        status_code=result.status,
                        evidence=f"Location: {location[:180]}",
                        impact=(
                            "An attacker can receive authorisation codes for any client id, which "
                            "leads to account takeover."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
        return findings


# -------------------------------------------------------------------------
# from jwt.py
# -------------------------------------------------------------------------

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")


def _b64decode(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
        parsed = json.loads(raw.decode("utf-8", "replace"))
        return parsed if isinstance(parsed, dict) else {}
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    header = _b64decode(parts[0]) if len(parts) > 0 else {}
    payload = _b64decode(parts[1]) if len(parts) > 1 else {}
    return {"header": header, "payload": payload, "segments": len(parts)}


@register
class JwtConfigurationCheck(BaseCheck):
    meta = CheckMeta(
        name="jwt-configuration",
        title="JWT configuration weaknesses",
        description=(
            "Decodes JWTs found in cookies, URLs and JavaScript to inspect the algorithm, "
            "expiry claims and whether the token is exposed to client-side code."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="authentication",
        remediation=(
            "Reject alg=none, pin a strong algorithm server-side, always set short exp and "
            "aud/iss claims, and keep tokens in HttpOnly cookies rather than URLs or storage."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        tokens: list[tuple[str, str]] = []  # (token, location)

        page = await self.get(self.ctx.base_url)
        if page is not None and not page.error:
            for cookie_line in page.headers.get("set-cookie", "").split("\n"):
                for token in JWT_RE.findall(cookie_line):
                    tokens.append((token, "Set-Cookie header"))
            for token in JWT_RE.findall(page.body):
                tokens.append((token, "page source"))

        for name, _value in parse_qsl(urlsplit(self.ctx.base_url).query):
            if JWT_RE.fullmatch(_value or ""):
                tokens.append((_value, f"query parameter '{name}'"))

        if self.ctx.crawl:
            for url, script in self.ctx.crawl.script_bodies.items():
                for token in JWT_RE.findall(script)[:2]:
                    tokens.append((token, f"JavaScript file {url}"))

        seen: set[str] = set()
        for token, location in tokens[:8]:
            if token in seen:
                continue
            seen.add(token)
            decoded = decode_jwt(token)
            header = decoded["header"]
            payload = decoded["payload"]
            algorithm = str(header.get("alg", "")).lower()
            endpoint = self.ctx.base_url

            if algorithm == "none":
                findings.append(
                    self.make_finding(
                        title="JWT uses the 'none' algorithm",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        endpoint=endpoint,
                        parameter=location,
                        evidence=f"Decoded header: {json.dumps(header)[:200]}",
                        impact="A token with alg=none is accepted without any signature check if the server is naive.",
                    )
                )
                continue

            if "exp" not in payload:
                findings.append(
                    self.make_finding(
                        title="JWT has no expiry claim",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=endpoint,
                        parameter=location,
                        evidence=f"Decoded payload keys: {', '.join(sorted(payload)) or 'none'}",
                        impact="A stolen token stays valid indefinitely.",
                    )
                )

            if location.startswith("query parameter") or location == "page source":
                findings.append(
                    self.make_finding(
                        title="JWT is exposed outside an HttpOnly cookie",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=endpoint,
                        parameter=location,
                        evidence=redact_evidence(f"Token found in {location}: {token[:40]}..."),
                        impact=(
                            "Tokens in URLs are logged by proxies and servers; tokens in page "
                            "source are readable by any injected script."
                        ),
                    )
                )
        return findings


# -------------------------------------------------------------------------
# from jwt_abuse.py
# -------------------------------------------------------------------------

JWT_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        parsed = json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8", "replace"))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


@register
class JwtAlgorithmConfusionCheck(BaseCheck):
    meta = CheckMeta(
        name="jwt-alg-none",
        title="JWT accepted without a signature",
        description=(
            "Replays a token issued by the application with its algorithm set to none and the "
            "signature removed, and compares the response with the original."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.LOW,
        category="authentication",
        remediation=(
            "Pin the accepted algorithms to an explicit list, reject alg=none and verify the "
            "signature before reading any claim."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        cwe="CWE-347",
        cvss=9.1,
        scan_type="active",
        impact="low",
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        endpoint = self.ctx.base_url
        baseline = await self.get(endpoint)
        if baseline is None or baseline.error:
            return findings

        tokens = JWT_TOKEN_RE.findall(baseline.body or "")
        for cookie in (baseline.header("set-cookie") or "").split("\n"):
            tokens.extend(JWT_TOKEN_RE.findall(cookie))
        for parameter in self.ctx.params[:6]:
            tokens.extend(JWT_TOKEN_RE.findall(getattr(parameter, "value", "") or ""))
        if not tokens:
            return findings

        for token in dict.fromkeys(tokens)[:2]:
            parts = token.split(".")
            if len(parts) < 3:
                continue
            header = _decode(parts[0])
            if not header:
                continue
            forged_header = dict(header)
            forged_header["alg"] = "none"
            forged = ".".join([_b64url(json.dumps(forged_header).encode()), parts[1], ""])
            for name in ("Authorization", "X-Auth-Token", "X-Access-Token"):
                original = await self.get(endpoint, headers={name: f"Bearer {token}"})
                candidate = await self.get(endpoint, headers={name: f"Bearer {forged}"})
                if original is None or candidate is None:
                    continue
                if original.error or candidate.error:
                    continue
                if candidate.status == original.status and candidate.body_length == original.body_length:
                    if candidate.status in (200, 201, 204):
                        findings.append(
                            self.make_finding(
                                title="API accepts a JWT with alg=none",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.MEDIUM,
                                endpoint=endpoint,
                                status_code=candidate.status,
                                evidence=(
                                    f"{name}: original token -> {original.status}/"
                                    f"{original.body_length}B; unsigned token -> "
                                    f"{candidate.status}/{candidate.body_length}B"
                                ),
                                impact=(
                                    "An attacker can mint a token for any user without knowing "
                                    "the signing key."
                                ),
                                verification=Verification.CONFIRMED,
                            )
                        )
                        return findings
        return findings


# -------------------------------------------------------------------------
# from accesscontrol.py
# -------------------------------------------------------------------------

ADMIN_PATHS = ("admin", "admin/", "administrator", "dashboard", "manage", "internal", "admin/users")
ADMIN_MARKERS = (
    "user management", "manage users", "admin panel", "administration",
    "delete user", "role management", "audit log", "system settings",
)
ID_PARAMS = {"id", "user_id", "userid", "account", "account_id", "order_id", "doc_id", "file_id"}


@register
class AccessControlCheck(BaseCheck):
    meta = CheckMeta(
        name="access-control-indicators",
        title="Potential access-control weakness",
        description=(
            "Checks whether administrative paths render without authentication and whether "
            "sequential numeric identifiers return different objects."
        ),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="authorisation",
        remediation=(
            "Enforce authorisation on the server for every object and route, deny by "
            "default, and verify object ownership rather than relying on unguessable ids."
        ),
        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        for path in ADMIN_PATHS:
            if self.ctx.cancelled:
                break
            url = self.ctx.base_url.rstrip("/") + "/" + path
            result = await self.get(url, allow_redirects=False)
            if result is None or result.error or result.status != 200:
                continue
            if self.is_soft_404(result):
                continue
            lowered = result.body.lower()
            markers = [m for m in ADMIN_MARKERS if m in lowered]
            if markers:
                findings.append(
                    self.make_finding(
                        title="Administrative interface reachable without authentication",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        endpoint=url,
                        status_code=result.status,
                        evidence=f"GET /{path} returned 200 containing: {', '.join(markers[:3])}",
                        impact=(
                            "If this page is not intended to be public, administrative actions "
                            "may be reachable by unauthenticated users. Manual confirmation "
                            "with an account is required."
                        ),
                    )
                )
                break

        numeric = [p for p in self.ctx.params if p.name.lower() in ID_PARAMS and p.value.isdigit()]
        for param in numeric[:2]:
            if self.ctx.cancelled:
                break
            base_value = int(param.value)
            target = param.url or self.ctx.base_url
            first = await self.get(set_query_param(target, param.name, str(base_value)))
            second = await self.get(set_query_param(target, param.name, str(base_value + 1)))
            if first is None or second is None or first.error or second.error:
                continue
            if first.status != 200 or second.status != 200:
                continue
            similarity = difflib.SequenceMatcher(None, first.body[:4000], second.body[:4000]).ratio()
            if similarity < 0.85 and abs(first.body_length - second.body_length) > 50:
                findings.append(
                    self.make_finding(
                        title=f"Sequential identifiers return different objects ('{param.name}')",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        endpoint=self.ctx.base_url,
                        parameter=param.name,
                        status_code=second.status,
                        evidence=(
                            f"{param.name}={base_value} and {param.name}={base_value + 1} both "
                            f"returned 200 with {similarity:.0%} body similarity."
                        ),
                        impact=(
                            "Object-level authorisation may be missing. This is an indicator only: "
                            "the objects could legitimately be public."
                        ),
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from api.py
# -------------------------------------------------------------------------

API_PATHS: list[tuple[str, str]] = [
    ("swagger.json", "Swagger/OpenAPI description"),
    ("openapi.json", "OpenAPI description"),
    ("api-docs", "API documentation UI"),
    ("swagger-ui.html", "Swagger UI"),
    ("api/", "API index"),
    ("api/v1/", "API v1 index"),
    ("graphql", "GraphQL endpoint"),
    ("redoc", "ReDoc API browser"),
]


@register
class ApiExposureCheck(BaseCheck):
    meta = CheckMeta(
        name="api-exposure",
        title="Public API documentation or endpoint exposure",
        description=(
            "Probes common documentation and API entry points, then sends a single "
            "read-only GraphQL type query to confirm the endpoint is live."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="exposure",
        remediation=(
            "Restrict API documentation to authenticated internal users, disable GraphQL "
            "introspection in production and require authentication on data endpoints."
        ),
        references=["https://owasp.org/www-project-api-security/"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        for path, label in API_PATHS:
            if self.ctx.cancelled:
                break
            url = self.ctx.base_url.rstrip("/") + "/" + path
            result = await self.get(url, allow_redirects=False)
            if result is None or result.error or result.status not in (200, 401, 403):
                continue
            if self.is_soft_404(result):
                continue

            if path == "graphql" and result.status == 200:
                probe = await self._graphql_probe(url)
                if probe and probe.status == 200 and '"data"' in probe.body:
                    findings.append(
                        self.make_finding(
                            title="GraphQL endpoint answers schema queries",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            endpoint=url,
                            method="POST",
                            status_code=probe.status,
                            evidence='POST {"query":"{__typename}"} returned a data envelope.',
                            impact=(
                                "An open GraphQL endpoint lets clients enumerate the schema and "
                                "may expose fields that the UI never calls."
                            ),
                        )
                    )
                continue

            if result.status == 200 and self._looks_like_api_doc(path, result.body):
                findings.append(
                    self.make_finding(
                        title=f"{label} is publicly reachable",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        endpoint=url,
                        status_code=result.status,
                        evidence=f"GET /{path} returned 200 with documentation content ({result.body_length} bytes).",
                        impact="Published schema details shorten the reconnaissance phase for an attacker.",
                    )
                )
            elif result.status in (401, 403) and path in ("swagger.json", "openapi.json"):
                self.ctx.note(f"API description at /{path} exists but is protected ({result.status}).")
        return findings

    @staticmethod
    def _looks_like_api_doc(path: str, body: str) -> bool:
        lowered = body.lower()
        if path.endswith(".json"):
            return '"openapi"' in lowered or '"swagger"' in lowered or '"paths"' in lowered
        return any(marker in lowered for marker in ("swagger", "openapi", "redoc", "api reference", '"paths"'))

    async def _graphql_probe(self, url: str):
        if self.ctx.cancelled:
            return None
        try:
            return await self.ctx.http.post(
                url,
                data='{"query":"{__typename}"}',
                headers={"Content-Type": "application/json"},
                allow_redirects=False,
            )
        except Exception:
            return None


# -------------------------------------------------------------------------
# from forms_active.py
# -------------------------------------------------------------------------

PERSISTENT_ACTIONS = ("search", "comment", "message", "feedback", "contact", "review", "note", "post")


@register
class StoredReflectionCheck(BaseCheck):
    meta = CheckMeta(
        name="stored-reflection",
        title="Stored (persistent) cross-site scripting indicator",
        description=(
            "Submits a canary through a search or comment form and re-fetches the page to see "
            "whether it persisted. Requires --active-forms."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Encode output for its context on render and sanitise stored HTML with an allow-list."
        ),
        references=["https://owasp.org/www-community/attacks/xss/"],
    )

    async def run(self) -> list:
        findings: list = []
        if not getattr(self.ctx, "active_forms", False):
            self.ctx.note("stored-reflection skipped: requires --active-forms")
            return findings
        crawl = self.ctx.crawl
        if crawl is None or not crawl.forms:
            return findings

        token = canary("stored")
        for form in crawl.forms:
            action = form.action or self.ctx.base_url
            if not action.startswith("http"):
                action = self.ctx.base_url.rstrip("/") + "/" + action.lstrip("/")
            if not any(word in action.lower() for word in PERSISTENT_ACTIONS):
                continue
            if not form.fields:
                continue
            payload = dict.fromkeys(form.fields[:3], token)
            try:
                submitted = await self.ctx.http.post(action, data=payload, allow_redirects=True)
            except Exception:
                continue
            if submitted is None or submitted.error:
                continue
            if token in submitted.body:
                findings.append(
                    self.make_finding(
                        title=f"Submitted value is returned unencoded by {action.rsplit('/', 1)[-1]}",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=action,
                        method="POST",
                        status_code=submitted.status,
                        evidence=f"Canary '{token}' appears in the response to the submission.",
                        impact=(
                            "The value round-trips without encoding. If it is stored and rendered to "
                            "other users, that is stored cross-site scripting."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
                continue
            follow_up = await self.get(action)
            if follow_up is None or follow_up.error or not follow_up.body:
                continue
            if token in follow_up.body:
                findings.append(
                    self.make_finding(
                        title="Submitted value persists and is rendered unencoded",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=action,
                        method="POST",
                        status_code=follow_up.status,
                        evidence=f"Canary '{token}' survived a later GET of the same page.",
                        impact=(
                            "The application stores user input and renders it without encoding, "
                            "which is stored cross-site scripting."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
                break
        return findings


@register
class MassAssignmentCheck(BaseCheck):
    meta = CheckMeta(
        name="mass-assignment",
        title="Mass assignment indicator",
        description=(
            "Posts privileged field names to a JSON endpoint and checks whether the response "
            "echoes them back. Requires --active-forms."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        remediation=(
            "Bind request bodies to an explicit allow-list of writable fields and never map the "
            "raw body onto a model."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
    )

    PRIVILEGED_FIELDS = ("role", "is_admin", "isAdmin", "admin", "verified", "active", "balance", "owner_id")

    async def run(self) -> list:
        findings: list = []
        if not getattr(self.ctx, "active_forms", False):
            self.ctx.note("mass-assignment skipped: requires --active-forms")
            return findings
        crawl = self.ctx.crawl
        candidates: list[str] = []
        if crawl is not None:
            for link in crawl.links:
                if "/api" in link.lower():
                    candidates.append(link)
        if not candidates:
            return findings
        body = {"name": "webscout_engine", "role": "admin", "is_admin": True}
        for url in candidates[:4]:
            if self.ctx.cancelled:
                break
            try:
                result = await self.ctx.http.post(
                    url, data=json.dumps(body), headers={"Content-Type": "application/json"}
                )
            except Exception:
                continue
            if result is None or result.error or not result.body:
                continue
            echoed = [field for field in self.PRIVILEGED_FIELDS if f'"{field}"' in result.body]
            if not echoed:
                continue
            findings.append(
                self.make_finding(
                    title=f"Privileged fields are accepted by {url.rsplit('/', 1)[-1]}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    endpoint=url,
                    method="POST",
                    status_code=result.status,
                    evidence=f"Response echoes the submitted field(s): {', '.join(echoed[:4])}",
                    impact=(
                        "If these fields are persisted, a user can grant themselves privileges. "
                        "The echo is an indicator, not proof of persistence."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
            break
        return findings


# -------------------------------------------------------------------------
# from bypass.py
# -------------------------------------------------------------------------

PROTECTED_HINTS: tuple[str, ...] = (
    "admin", "api/admin", "internal", "private", "manage", "dashboard",
    "settings", "config", "users", "console", "staff", "superuser",
)

HEADER_BYPASSES: tuple[tuple[str, dict[str, str]], ...] = (
    ("X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Real-IP", {"X-Real-IP": "127.0.0.1"}),
    ("X-Client-IP", {"X-Client-IP": "127.0.0.1"}),
    ("X-Originating-IP", {"X-Originating-IP": "127.0.0.1"}),
    ("Forwarded", {"Forwarded": "for=127.0.0.1"}),
    ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Remote-IP", {"X-Remote-IP": "127.0.0.1"}),
    ("X-Original-URL", {"X-Original-URL": "/admin"}),
    ("X-Rewrite-URL", {"X-Rewrite-URL": "/admin"}),
)


@register
class AccessControlBypassCheck(BaseCheck):
    meta = CheckMeta(
        name="access-control-bypass",
        title="Access-control bypass through path or header tricks",
        description=(
            "Retries protected paths with alternative encodings, trailing separators and "
            "spoofed forwarding headers to detect authorisation that can be walked around."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="authorisation",
        remediation=(
            "Normalise the request path before authorising, and never derive the client "
            "identity or privilege from a forwarded header."
        ),
        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
        cwe="CWE-284",
        cvss=8.1,
        scan_type="active",
        impact="low",
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        base = self.ctx.base_url.rstrip("/")
        candidates: list[str] = []
        crawl = self.ctx.crawl
        if crawl is not None:
            for link in list(crawl.links)[:120]:
                lowered = link.lower()
                if any(hint in lowered for hint in PROTECTED_HINTS):
                    candidates.append(link)
        for hint in ("/admin", "/api/admin", "/dashboard", "/settings"):
            candidates.append(base + hint)

        seen: set[str] = set()
        checked = 0
        for url in candidates:
            if url in seen or checked >= 8:
                continue
            seen.add(url)
            original = await self.get(url)
            checked += 1
            if original is None or original.error or original.status not in (401, 403):
                continue
            path = url.split(base, 1)[-1] or "/"
            for label, variant in self._variants(base, path):
                result = await self.get(variant)
                if result is None or result.error:
                    continue
                if result.status == 200 and result.body_length > 32:
                    findings.append(
                        self.make_finding(
                            title="Protected path reachable through an access-control bypass",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            endpoint=variant,
                            status_code=result.status,
                            evidence=(
                                f"original {path} -> {original.status}; "
                                f"variant ({label}) -> 200, {result.body_length} bytes"
                            ),
                            impact=(
                                "An unauthenticated visitor reaches an administrative surface by "
                                "changing how the path is written."
                            ),
                            verification=Verification.CONFIRMED,
                        )
                    )
                    break
            else:
                for label, headers in HEADER_BYPASSES:
                    result = await self.get(url, headers=headers)
                    if result is None or result.error:
                        continue
                    if result.status == 200 and result.body_length > 32:
                        findings.append(
                            self.make_finding(
                                title="Protected path reachable with a spoofed client address",
                                severity=Severity.HIGH,
                                confidence=Confidence.LOW,
                                endpoint=url,
                                status_code=result.status,
                                evidence=(
                                    f"{label}: 127.0.0.1 turned {original.status} into 200 "
                                    f"({result.body_length} bytes)"
                                ),
                                impact="Access control trusts a header the client controls.",
                                verification=Verification.INDICATOR,
                            )
                        )
                        break
        return findings

    @staticmethod
    def _variants(base: str, path: str) -> list[tuple[str, str]]:
        clean = path.lstrip("/")
        upper = clean.upper()
        mixed = "".join(ch.upper() if index % 2 else ch for index, ch in enumerate(clean))
        return [
            ("trailing slash", f"{base}/{clean}/"),
            ("double slash", f"{base}//{clean}"),
            ("dot segment", f"{base}/./{clean}"),
            ("dot-dot segment", f"{base}/x/../{clean}"),
            ("encoded slash", f"{base}/%2f{clean}"),
            ("trailing encoded slash", f"{base}/{clean}%2f"),
            ("semicolon", f"{base}/{clean};/"),
            ("semicolon json", f"{base}/{clean};.json"),
            ("trailing dot", f"{base}/{clean}."),
            ("upper case", f"{base}/{upper}"),
            ("mixed case", f"{base}/{mixed}"),
            ("null byte", f"{base}/{clean}%00"),
            ("double encoded slash", f"{base}/%252f{clean}"),
            ("path parameter", f"{base}/{clean}%3f"),
        ]
