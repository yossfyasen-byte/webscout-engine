"""Injection checks: SQL, NoSQL, command, template, XPath, LDAP, XXE, SSRF,
path traversal, reflection, DOM sinks, CRLF and prototype pollution."""

from __future__ import annotations

import re
from ..core.models import Confidence, Finding, Severity
from ..recon.crawl import canary, set_query_param
from .base import BaseCheck, CheckMeta
from .helpers import MAX_PARAMS, load_payloads
from .registry import register
from ..core.models import Confidence, Severity, Verification
from .helpers import MAX_PARAMS, any_param, similarity, timed_get
from .helpers import MAX_PARAMS, any_param, first_match, timed_get
from ..recon.crawl import set_query_param
from .helpers import URL_PARAMS, first_match, load_payloads, pick
from .helpers import FILE_PARAMS, first_match, load_payloads, pick, similarity
from urllib.parse import quote
from ..core.models import Confidence, Finding, Severity, Verification


# -------------------------------------------------------------------------
# from sqli.py
# -------------------------------------------------------------------------

ERROR_PATTERNS = (
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)\s*\[",
    r"postgresql.*syntax error",
    r"sqlite3?\.(operational|programming)error",
    r"ora-\d{4,5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sqlstate\[",
    r"jdbc.*sqlexception",
)

MAX_PAYLOADS = 12


@register
class SqlErrorCheck(BaseCheck):
    meta = CheckMeta(
        name="sql-error-disclosure",
        title="SQL error disclosure",
        description=(
            "Sends single quote characters and looks for database engine error messages. "
            "Detection is limited to error text; no data is extracted."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="injection",
        remediation=(
            "Use parameterised queries everywhere and return a generic error page that "
            "never includes database messages."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    )

    MAX_PAYLOADS = 12

    async def run(self) -> list:
        findings: list[Finding] = []
        baseline = self.ctx.baseline_body.lower()
        payloads = load_payloads("sqli_error")[: self.MAX_PAYLOADS] or ("'", '"')
        for param in self.target_params[:MAX_PARAMS]:
            for payload in payloads:
                if self.ctx.cancelled:
                    break
                target = param.url or self.ctx.base_url
                url = set_query_param(target, param.name, f"{canary()}{payload}")
                result = await self.get(url)
                if result is None or result.error or not result.body:
                    continue
                body = result.body.lower()
                for pattern in ERROR_PATTERNS:
                    match = re.search(pattern, body)
                    if not match:
                        continue
                    if re.search(pattern, baseline):
                        break  # the error exists on the clean page too
                    start = max(0, match.start() - 80)
                    findings.append(
                        self.make_finding(
                            title=f"Database error message returned for parameter '{param.name}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            endpoint=result.final_url or url,
                            parameter=param.name,
                            status_code=result.status,
                            evidence=result.body[start : match.end() + 100],
                            impact=(
                                "Unsanitised input reaches a SQL parser. Error text leaks schema "
                                "details and is a strong indicator of an injectable parameter."
                            ),
                        )
                    )
                    break
                else:
                    continue
                break
        return findings


# -------------------------------------------------------------------------
# from injection_advanced.py
# -------------------------------------------------------------------------

SQL_ERRORS = (
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\)",
    r"sqlite3?\.(operational|programming)error",
    r"ora-\d{4,5}",
)


@register
class SqlBooleanBlindCheck(BaseCheck):
    meta = CheckMeta(
        name="sql-boolean-blind",
        title="Boolean-based blind SQL injection",
        description=(
            "Sends a TRUE and a FALSE condition through a parameter and compares the two "
            "responses. A stable difference means the condition reached the database."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Use parameterised queries for every value and reject input that is not of the "
            "expected type."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        for param in any_param(self.target_params, MAX_PARAMS):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            token = canary()
            baseline = await self.get(set_query_param(target, param.name, token))
            true_url = set_query_param(target, param.name, f"{token}' AND '1'='1")
            false_url = set_query_param(target, param.name, f"{token}' AND '1'='2")
            true_result = await self.get(true_url)
            false_result = await self.get(false_url)
            if true_result is None or false_result is None or baseline is None:
                continue
            if true_result.error or false_result.error or baseline.error:
                continue
            if true_result.status != false_result.status:
                if true_result.status < 400 <= false_result.status:
                    findings.append(
                        self.make_finding(
                            title=f"Boolean condition changes the response for '{param.name}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            endpoint=true_url,
                            parameter=param.name,
                            status_code=true_result.status,
                            evidence=(
                                f"TRUE condition -> HTTP {true_result.status} "
                                f"({true_result.body_length} bytes); FALSE condition -> "
                                f"HTTP {false_result.status} ({false_result.body_length} bytes)."
                            ),
                            impact=(
                                "The injected condition is evaluated by the database, which is the "
                                "defining behaviour of SQL injection."
                            ),
                            verification=Verification.INDICATOR,
                        )
                    )
                continue
            ratio = similarity(true_result.body, false_result.body)
            delta = abs(true_result.body_length - false_result.body_length)
            # The TRUE response must look like an ordinary page while the FALSE one
            # does not; otherwise the difference is just the value being echoed.
            resembles_baseline = similarity(baseline.body, true_result.body) - similarity(
                baseline.body, false_result.body
            )
            # Similarity carries the signal: >=10% of the content must differ, and the
            # TRUE response must look more like an ordinary page than the FALSE one.
            if ratio < 0.90 and resembles_baseline > 0.15:
                findings.append(
                    self.make_finding(
                        title=f"Boolean condition changes the response body for '{param.name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        endpoint=true_url,
                        parameter=param.name,
                        status_code=true_result.status,
                        evidence=(
                            f"TRUE and FALSE conditions returned different bodies "
                            f"(similarity {ratio:.2f}, {delta} byte difference); the TRUE "
                            f"response resembles the benign baseline {resembles_baseline:+.2f} more."
                        ),
                        impact=(
                            "Response content depends on a database condition, indicating "
                            "boolean-based blind SQL injection."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


@register
class SqlTimeBlindCheck(BaseCheck):
    meta = CheckMeta(
        name="sql-time-blind",
        title="Time-based blind SQL injection",
        description=(
            "Sends a database sleep function and measures the delay against a baseline "
            "request. Capped by --blind-delay and --max-blind-params."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation="Parameterise queries; never concatenate request data into SQL.",
        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    )

    async def run(self) -> list:
        findings: list = []
        delay = max(1.0, float(getattr(self.ctx, "blind_delay", 2.0)))
        limit = int(getattr(self.ctx, "max_blind_params", 2) or 2)
        payloads = (
            f"'; SELECT SLEEP({delay:.0f})-- ",
            f"'; SELECT pg_sleep({delay:.0f})-- ",
            f"'; WAITFOR DELAY '0:0:{delay:.0f}'-- ",
        )
        for param in any_param(self.target_params, limit):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            _, baseline = await timed_get(self, set_query_param(target, param.name, canary()))
            if baseline > delay / 2:
                continue  # already slow: timing cannot be trusted
            for payload in payloads:
                result, elapsed = await timed_get(
                    self, set_query_param(target, param.name, f"{canary()}{payload}")
                )
                if result is None or result.error:
                    continue
                if elapsed >= baseline + delay * 0.75:
                    findings.append(
                        self.make_finding(
                            title=f"Time-based SQL injection in '{param.name}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            endpoint=result.final_url or target,
                            parameter=param.name,
                            status_code=result.status,
                            evidence=(
                                f"Baseline {baseline:.2f}s, payload {elapsed:.2f}s "
                                f"(expected delay {delay:.0f}s) for {payload.strip()!r}."
                            ),
                            impact=(
                                "A database sleep function executed, which confirms the parameter "
                                "reaches SQL and can be used for blind extraction."
                            ),
                            verification=Verification.CONFIRMED,
                        )
                    )
                    break
        return findings


@register
class SqlUnionCandidateCheck(BaseCheck):
    meta = CheckMeta(
        name="sql-union-candidate",
        title="UNION-based SQL injection candidate",
        description=(
            "Increments an ORDER BY clause until the query breaks. The column count that "
            "stops working identifies a UNION-capable parameter. No data is selected."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation="Parameterise queries and validate that inputs are numeric where expected.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    )

    MAX_COLUMNS = 8

    async def run(self) -> list:
        findings: list = []
        for param in any_param(self.target_params, MAX_PARAMS):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            working = 0
            broke_at = 0
            for column in range(1, self.MAX_COLUMNS + 1):
                url = set_query_param(target, param.name, f"{canary()}' ORDER BY {column}-- ")
                result = await self.get(url)
                if result is None or result.error:
                    break
                if result.status >= 400:
                    broke_at = column
                    break
                working = column
            if broke_at and working >= 1:
                findings.append(
                    self.make_finding(
                        title=f"ORDER BY column count is controllable via '{param.name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        endpoint=target,
                        parameter=param.name,
                        status_code=400,
                        evidence=(
                            f"ORDER BY 1..{working} returned HTTP 200 while ORDER BY {broke_at} "
                            f"returned an error, which indicates {working} selectable column(s)."
                        ),
                        impact=(
                            "The injected ORDER BY is parsed by the database and the column count "
                            "is known, which is the prerequisite for a UNION-based attack."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


@register
class NoSqlInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="nosql-injection",
        title="NoSQL injection",
        description=(
            "Adds a Mongo-style operator to an authentication-style parameter and compares the "
            "outcome with a benign request."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        remediation=(
            "Cast request values to the expected scalar type and never pass client objects "
            "straight into a query filter."
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
    )

    async def run(self) -> list:
        findings: list = []
        from .helpers import AUTH_PARAMS, pick

        candidates = pick(self.ctx.params, AUTH_PARAMS, 2)
        if not candidates:
            return findings
        for param in candidates:
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            baseline = await self.get(set_query_param(target, param.name, "webscout_engine-probe"))
            if baseline is None or baseline.error:
                continue
            payloads = (
                f"{param.name}[$ne]=webscout_engine",
                f"{param.name}[$gt]=",
                f"{param.name}[$regex]=.*",
            )
            for payload in payloads:
                separator = "&" if "?" in target else "?"
                url = f"{target}{separator}{payload}"
                result = await self.get(url)
                if result is None or result.error:
                    continue
                escalated = baseline.status in (401, 403) and result.status < 400
                changed = result.status != baseline.status or similarity(
                    baseline.body, result.body
                ) < 0.9
                if not (escalated or changed):
                    continue
                findings.append(
                    self.make_finding(
                        title=f"Mongo-style operator accepted by '{param.name}'",
                        severity=Severity.HIGH if escalated else Severity.MEDIUM,
                        confidence=Confidence.MEDIUM if escalated else Confidence.LOW,
                        endpoint=url,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=(
                            f"Baseline HTTP {baseline.status}; operator payload {payload} "
                            f"returned HTTP {result.status}"
                            + (" (authentication bypass indicator)" if escalated else "")
                        ),
                        impact=(
                            "A query operator injected through the parameter changes the query "
                            "result, which can bypass authentication or widen a filter."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from injection_server.py
# -------------------------------------------------------------------------

XPATH_ERRORS = (
    r"xpathevalerror",
    r"invalid xpath",
    r"xpath syntax error",
    r"org\.jaxen",
    r"lxml\.etree\.xpath",
    r"System\.Xml\.XPath",
    r"XPathException",
)

LDAP_ERRORS = (
    r"javax\.naming",
    r"ldapexception",
    r"invalid dn syntax",
    r"ldap_search",
    r"ldap_bind",
    r"protocol error occurred",
)

XML_ERRORS = (
    r"failed to load external entity",
    r"doctype is disallowed",
    r"saxparseexception",
    r"xmlsyntaxerror",
    r"external entity",
    r"entityref",
    r"org\.xml\.sax",
    r"lxml\.etree\.xml",
)


@register
class CommandInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="command-injection",
        title="OS command injection",
        description=(
            "Injects a sleep command into a parameter and compares the response time with a "
            "baseline request. No command output is requested or read."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Never build shell commands from request data; use an argument list with "
            "shell=False and validate against an allow-list."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        delay = max(1.0, float(getattr(self.ctx, "blind_delay", 2.0)))
        limit = int(getattr(self.ctx, "max_blind_params", 2) or 2)
        payloads = (f"; sleep {delay:.0f}", f"| sleep {delay:.0f}", f"$(sleep {delay:.0f})",
                    f"&& sleep {delay:.0f}", f"`sleep {delay:.0f}`", f"%0a sleep {delay:.0f}")
        for param in any_param(self.target_params, limit):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            _, baseline = await timed_get(self, set_query_param(target, param.name, canary()))
            if baseline > delay / 2:
                continue
            for payload in payloads:
                result, elapsed = await timed_get(
                    self, set_query_param(target, param.name, f"{canary()}{payload}")
                )
                if result is None or result.error:
                    continue
                if elapsed >= baseline + delay * 0.75:
                    findings.append(
                        self.make_finding(
                            title=f"Time-based command injection in '{param.name}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            endpoint=result.final_url or target,
                            parameter=param.name,
                            status_code=result.status,
                            evidence=(
                                f"Baseline {baseline:.2f}s, payload {elapsed:.2f}s for "
                                f"{payload!r} (expected delay {delay:.0f}s)."
                            ),
                            impact=(
                                "A shell command executed on the server. This is normally remote "
                                "code execution with the privileges of the web process."
                            ),
                            verification=Verification.CONFIRMED,
                        )
                    )
                    break
        return findings


@register
class XxeCheck(BaseCheck):
    meta = CheckMeta(
        name="xxe",
        title="XML external entity injection",
        description=(
            "Posts XML declaring an external entity that points at a nonexistent path and "
            "looks for a parser error that proves entity resolution was attempted."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Disable DTD and external entity processing in the XML parser, or accept JSON only."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
    )

    def _candidates(self) -> list[str]:
        """Endpoints that plausibly accept XML, most specific first."""
        strong = ("xml", "soap", "wsdl", "rss", "feed", "atom")
        weak = ("api", "rest", "service", "import")
        specific: list[str] = []
        generic: list[str] = []
        crawl = self.ctx.crawl
        if crawl is not None:
            for link in list(crawl.links)[:60]:
                lowered = link.lower()
                if any(token in lowered for token in strong):
                    specific.append(link)
                elif any(token in lowered for token in weak):
                    generic.append(link)
        ordered: dict[str, None] = {}
        for url in [*specific, self.ctx.base_url, *generic]:
            ordered.setdefault(url, None)
        return list(ordered)[:4]

    async def run(self) -> list:
        findings: list = []
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE data [<!ENTITY zs SYSTEM "file:///webscout_engine-nonexistent">]>'
            "<data>&zs;</data>"
        )
        headers = {"Content-Type": "application/xml"}
        for url in self._candidates():
            if self.ctx.cancelled:
                break
            try:
                result = await self.ctx.http.post(
                    url, data=body, headers=headers, allow_redirects=False
                )
            except Exception:
                continue
            if result.error or not result.body:
                continue
            marker = first_match(result.body, XML_ERRORS)
            if marker:
                findings.append(
                    self.make_finding(
                        title="XML parser attempted to resolve an external entity",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        endpoint=url,
                        method="POST",
                        status_code=result.status,
                        evidence=f"Parser error after a DOCTYPE entity: {marker}",
                        impact=(
                            "External entity resolution is enabled, which enables local file "
                            "disclosure and server-side request forgery through XML."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
        return findings


@register
class XPathInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="xpath-injection",
        title="XPath injection",
        description="Sends quote characters into parameters and looks for XPath parser errors.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        remediation="Use parameterised XPath queries and validate the input grammar.",
        references=["https://owasp.org/www-community/attacks/XPATH_Injection"],
    )

    async def run(self) -> list:
        findings: list = []
        for param in any_param(self.target_params, MAX_PARAMS):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            for payload in ("'", "']", "' or '1'='1"):
                result = await self.get(set_query_param(target, param.name, f"{canary()}{payload}"))
                if result is None or result.error or not result.body:
                    continue
                marker = first_match(result.body, XPATH_ERRORS)
                if not marker:
                    continue
                findings.append(
                    self.make_finding(
                        title=f"XPath error from parameter '{param.name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or target,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=marker,
                        impact="The input reaches an XPath expression and breaks its syntax.",
                        verification=Verification.CONFIRMED,
                    )
                )
                break
        return findings


@register
class LdapInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="ldap-injection",
        title="LDAP injection",
        description="Sends LDAP filter metacharacters and looks for filter errors or behaviour changes.",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        remediation="Escape LDAP filter metacharacters and validate the input grammar.",
        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
    )

    async def run(self) -> list:
        findings: list = []
        for param in any_param(self.target_params, MAX_PARAMS):
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            baseline = await self.get(set_query_param(target, param.name, canary()))
            if baseline is None or baseline.error:
                continue
            for payload in ("*)(uid=*", ")(|(password=*)"):
                result = await self.get(set_query_param(target, param.name, f"{canary()}{payload}"))
                if result is None or result.error or not result.body:
                    continue
                marker = first_match(result.body, LDAP_ERRORS)
                if not marker:
                    continue
                findings.append(
                    self.make_finding(
                        title=f"LDAP filter error from parameter '{param.name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or target,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=marker,
                        impact="Filter metacharacters reach an LDAP query, enabling filter bypass.",
                        verification=Verification.CONFIRMED,
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from ssrf.py
# -------------------------------------------------------------------------

REFUSED_MARKERS = (
    r"connection refused",
    r"econnrefused",
    r"failed to connect",
    r"could not connect",
    r"dial tcp",
    r"connection reset by peer",
    r"no route to host",
    r"getaddrinfo",
)


@register
class SsrfCheck(BaseCheck):
    meta = CheckMeta(
        name="ssrf",
        title="Server-side request forgery",
        description=(
            "Supplies a loopback URL on a closed port to a URL-taking parameter. A connection "
            "error in the response shows the server fetched it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        remediation=(
            "Allow-list destination hosts, block link-local and loopback ranges, and never "
            "follow redirects for user-supplied URLs."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    )

    async def run(self) -> list:
        findings: list = []
        candidates = pick(self.ctx.params, URL_PARAMS, 3)
        if not candidates:
            return findings
        for param in candidates:
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            payloads = load_payloads("ssrf") or ("http://127.0.0.1:1/zs",)
            for payload in payloads:
                result = await self.get(set_query_param(target, param.name, payload))
                if result is None or result.error or not result.body:
                    continue
                marker = first_match(result.body, REFUSED_MARKERS)
                if not marker:
                    continue
                findings.append(
                    self.make_finding(
                        title=f"Server fetched an attacker-supplied URL via '{param.name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=result.final_url or target,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=f"{payload} produced a connection error in the response: {marker}",
                        impact=(
                            "The server issues requests to a destination the client chooses, which "
                            "reaches internal services and cloud metadata endpoints."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from ssti.py
# -------------------------------------------------------------------------

# (payload, expected result) - arithmetic only.
PAYLOADS = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
)


@register
class TemplateInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="template-evaluation",
        title="Potential server-side template injection",
        description=(
            "Submits an arithmetic template expression and checks whether the evaluated "
            "result appears in the response."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category="injection",
        remediation=(
            "Never build templates from user input; use logic-less templates or strict "
            "sandboxing, and validate every parameter against an allow-list."
        ),
        references=["https://portswigger.net/web-security/server-side-template-injection"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        baseline = self.ctx.baseline_body
        for param in self.target_params[:4]:
            for payload, expected in PAYLOADS:
                if self.ctx.cancelled:
                    break
                target = param.url or self.ctx.base_url
                url = set_query_param(target, param.name, f"{canary()}{payload}")
                result = await self.get(url)
                if result is None or result.error or not result.body:
                    continue
                if expected not in result.body:
                    continue
                if expected in baseline:
                    continue  # the number is part of the page already
                if payload in result.body:
                    continue  # reflected verbatim, not evaluated
                findings.append(
                    self.make_finding(
                        title=f"Template expression evaluated for parameter '{param.name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        endpoint=result.final_url or url,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=f"Payload {payload!r} produced the arithmetic result {expected}.",
                        impact=(
                            "User input is evaluated by the template engine. Depending on the "
                            "engine, further expressions may expose configuration or objects."
                        ),
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from file_inclusion.py
# -------------------------------------------------------------------------

OS_ERRORS = (
    r"no such file or directory",
    r"failed to open stream",
    r"java\.io\.filenotfoundexception",
    r"system\.io\.file(notfound)?exception",
    r"permission denied",
    r"open_basedir restriction",
    r"root:x:0:0",
    r"\[errno 2\]",
)

SOURCE_MARKERS = (
    r"<\?php",
    r"<\?=",
    r"^\s*import\s+\w+",
    r"^\s*def\s+\w+\(",
    r"^\s*class\s+\w+[:({]",
    r"^\s*function\s+\w+\(",
    r"#!/",
    r"use\s+strict",
)

SOURCE_SUFFIXES = (".bak", ".old", "~", ".save", ".orig", ".swp")


@register
class PathTraversalCheck(BaseCheck):
    meta = CheckMeta(
        name="path-traversal",
        title="Path traversal / file inclusion indicator",
        description=(
            "Compares a traversal request for a nonexistent file with a plain missing-file "
            "request and looks for filesystem errors. No real file is read."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        remediation=(
            "Resolve requested paths against a fixed base directory, reject '..' segments and "
            "map identifiers to an allow-list of files."
        ),
        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
    )

    async def run(self) -> list:
        findings: list = []
        candidates = pick(self.ctx.params, FILE_PARAMS, 3)
        if not candidates:
            return findings
        for param in candidates:
            if self.ctx.cancelled:
                break
            target = param.url or self.ctx.base_url
            token = canary()
            plain = await self.get(set_query_param(target, param.name, f"{token}.txt"))
            if plain is None or plain.error:
                continue
            variants = load_payloads("lfi")[:10]
            probes = [
                variant.replace("/etc/passwd", f"{token}.txt").replace("etc%2fpasswd", f"{token}.txt")
                for variant in variants
            ] or [f"../../../../{token}.txt", f"..%2f..%2f..%2f..%2f{token}.txt"]
            for payload in probes:
                result = await self.get(set_query_param(target, param.name, payload))
                if result is None or result.error or not result.body:
                    continue
                marker = first_match(result.body, OS_ERRORS)
                differs = result.status != plain.status or similarity(
                    plain.body, result.body
                ) < 0.9
                if not (marker or differs):
                    continue
                findings.append(
                    self.make_finding(
                        title=f"Traversal sequence changes file resolution in '{param.name}'",
                        severity=Severity.MEDIUM if marker else Severity.LOW,
                        confidence=Confidence.MEDIUM if marker else Confidence.LOW,
                        endpoint=result.final_url or target,
                        parameter=param.name,
                        status_code=result.status,
                        evidence=(
                            (f"Filesystem error: {marker}" if marker else "Response differs from a plain missing-file request")
                            + f" | payload {payload}"
                        ),
                        impact=(
                            "The parameter reaches the filesystem layer. With a working traversal "
                            "this becomes arbitrary file read (CWE-22 / CWE-98)."
                        ),
                        verification=Verification.INDICATOR,
                    )
                )
                break
        return findings


@register
class SourceDisclosureCheck(BaseCheck):
    meta = CheckMeta(
        name="source-disclosure",
        title="Source code disclosure",
        description=(
            "Requests editor backup and swap variants of crawled paths and checks whether the "
            "response contains source code rather than rendered HTML."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        remediation=(
            "Block backup and editor artefacts at the web server and deploy without them."
        ),
        references=["https://cwe.mitre.org/data/definitions/540.html"],
    )

    MAX_BASES = 6

    def _bases(self) -> list[str]:
        bases: dict[str, None] = {}
        crawl = self.ctx.crawl
        if crawl is not None:
            for link in crawl.pages + crawl.links:
                path = link.split("?", 1)[0]
                if path.endswith((".php", ".asp", ".aspx", ".jsp", ".py", ".rb")):
                    bases.setdefault(path, None)
        return list(bases)[: self.MAX_BASES]

    async def run(self) -> list:
        findings: list = []
        for base in self._bases():
            for suffix in SOURCE_SUFFIXES:
                if self.ctx.cancelled:
                    break
                url = f"{base}{suffix}"
                result = await self.get(url, allow_redirects=False)
                if result is None or result.error or result.status != 200:
                    continue
                if self.is_soft_404(result):
                    continue
                lowered = result.body.lower()
                if "<html" in lowered[:500] and "<?php" not in lowered:
                    continue
                marker = first_match(result.body, SOURCE_MARKERS)
                if not marker:
                    continue
                findings.append(
                    self.make_finding(
                        title=f"Source code served from {url.rsplit('/', 1)[-1]}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=url,
                        status_code=result.status,
                        evidence=f"Backup variant returned source: {marker[:160]}",
                        impact=(
                            "Source disclosure exposes credentials, internal paths and business "
                            "logic, and often reveals further vulnerabilities."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from reflection.py
# -------------------------------------------------------------------------

@register
class ReflectionCheck(BaseCheck):
    meta = CheckMeta(
        name="reflected-input",
        title="User input is reflected in the response",
        description=(
            "Injects a unique alphanumeric canary into query parameters and checks whether "
            "it is returned unencoded. No script payload is sent: the finding states that "
            "reflection exists, not that script execution was proven."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        category="injection",
        remediation=(
            "Encode all output for its HTML context and validate input server-side. Treat "
            "reflection as a precursor to cross-site scripting, not as harmless behaviour."
        ),
        references=["https://owasp.org/www-community/attacks/xss/"],
    )

    MAX_PAYLOADS = 6

    async def run(self) -> list:
        findings: list[Finding] = []
        payloads = load_payloads("xss")[: self.MAX_PAYLOADS] or ("<script>alert(1)</script>",)
        for param in self.target_params[:MAX_PARAMS]:
            if self.ctx.cancelled:
                break
            token = canary()
            target = param.url or self.ctx.base_url
            url = set_query_param(target, param.name, token)
            result = await self.get(url)
            if result is None or result.error or not result.body:
                continue
            if token not in result.body:
                continue
            index = result.body.find(token)
            window = result.body[max(0, index - 120) : index + len(token) + 120].lower()
            in_script = "<script" in window
            in_attribute = "=\"" in window or "='" in window
            context = "inside a script block" if in_script else ("inside an HTML attribute" if in_attribute else "in the HTML body")
            # Try the classic XSS variants to show the parameter accepts markup.
            accepted = 0
            for payload in payloads:
                probe = await self.get(set_query_param(target, param.name, payload))
                if probe is None or probe.error or not probe.body:
                    continue
                if payload in probe.body:
                    accepted += 1
            findings.append(
                self.make_finding(
                    title=f"Parameter '{param.name}' is reflected unencoded in the response",
                    severity=Severity.MEDIUM if in_script else Severity.LOW,
                    confidence=Confidence.HIGH,
                    endpoint=result.final_url or url,
                    parameter=param.name,
                    status_code=result.status,
                    evidence=(
                        f"Canary '{token}' appeared {context}; "
                        f"{accepted}/{len(payloads)} markup payload(s) were echoed verbatim."
                    ),
                    impact=(
                        "Unencoded reflection in a script context is directly exploitable as "
                        "cross-site scripting when an attacker controls the value."
                    ),
                )
            )
        return findings


# -------------------------------------------------------------------------
# from domjs.py
# -------------------------------------------------------------------------

SINKS: list[tuple[str, str]] = [
    (r"\.innerHTML\s*=", "element.innerHTML assignment"),
    (r"\.outerHTML\s*=", "element.outerHTML assignment"),
    (r"document\.write\s*\(", "document.write call"),
    (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML call"),
    (r"eval\s*\(", "eval call"),
    (r"setTimeout\s*\(\s*[\"']", "setTimeout with a string body"),
    (r"new\s+Function\s*\(", "Function constructor"),
    (r"\$\([^)]*\)\.html\s*\(", "jQuery .html() call"),
    (r"dangerouslySetInnerHTML", "React dangerouslySetInnerHTML"),
]

SOURCES: list[tuple[str, str]] = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"\.postMessage\s*\(", "postMessage"),
]


@register
class DomSinkCheck(BaseCheck):
    meta = CheckMeta(
        name="dom-xss-sinks",
        title="DOM-based XSS sinks in client-side JavaScript",
        description=(
            "Downloads the application's scripts and reports dangerous DOM sinks, noting "
            "whether a known attacker-controlled source appears in the same file."
        ),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category="injection",
        remediation=(
            "Prefer textContent over innerHTML, sanitise any HTML fragment with a maintained "
            "library, and avoid eval and string-based timers."
        ),
        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
    )

    async def run(self) -> list:
        findings: list[Finding] = []
        crawl = self.ctx.crawl
        if crawl is None:
            return findings
        bodies = dict(crawl.script_bodies)
        if self.ctx.baseline_body:
            bodies.setdefault(self.ctx.base_url, self.ctx.baseline_body)

        for url, script in list(bodies.items())[:8]:
            for pattern, label in SINKS:
                if not re.search(pattern, script):
                    continue
                sources = [name for source, name in SOURCES if re.search(source, script)]
                findings.append(
                    self.make_finding(
                        title=f"DOM sink '{label}' found in {url.rsplit('/', 1)[-1]}",
                        severity=Severity.LOW if sources else Severity.INFO,
                        confidence=Confidence.LOW,
                        endpoint=url,
                        evidence=(
                            f"Pattern {pattern!r} matched; "
                            + (f"attacker-controlled sources in the same file: {', '.join(sources)}" if sources else "no obvious source in the same file")
                        ),
                        impact=(
                            "If untrusted data reaches this sink, the browser executes it as HTML "
                            "or script. Presence of a sink alone is not proof of exploitability."
                        ),
                    )
                )
                break
        return findings


# -------------------------------------------------------------------------
# from crlf.py
# -------------------------------------------------------------------------

CANARY_HEADER = "Zs-Crlf-Canary"
PAYLOADS: tuple[tuple[str, str], ...] = (
    ("crlf", "%0d%0a"),
    ("lf", "%0a"),
    ("double-encoded", "%250d%250a"),
    ("unicode", "%E5%98%8A%E5%98%8D"),
)


@register
class CrlfInjectionCheck(BaseCheck):
    meta = CheckMeta(
        name="crlf-injection",
        title="CRLF injection into response headers",
        description=(
            "Injects carriage-return/line-feed sequences through a parameter and checks whether "
            "the injected header appears in the response."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="injection",
        remediation="Strip CR and LF from every value written into a response header.",
        references=["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
        cwe="CWE-113",
        cvss=7.3,
        scan_type="active",
        impact="low",
    )

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        params = self.target_params[: self.ctx.max_blind_params * 2]
        if not params:
            return findings
        for parameter in params:
            for label, sequence in PAYLOADS:
                payload = f"{sequence}{CANARY_HEADER}: 1"
                url = self._inject(parameter, payload)
                if url is None:
                    continue
                result = await self.get(url)
                if result is None or result.error:
                    continue
                if CANARY_HEADER.lower() in {key.lower() for key in result.headers}:
                    findings.append(
                        self.make_finding(
                            title="CRLF injection in a response header",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            endpoint=url,
                            parameter=parameter.name,
                            status_code=result.status,
                            evidence=(
                                f"payload={label}:{payload} -> response carries "
                                f"{CANARY_HEADER}: {result.header(CANARY_HEADER)}"
                            ),
                            impact=(
                                "An attacker can inject arbitrary response headers or a second "
                                "response body, enabling cache poisoning, cookie fixation and XSS."
                            ),
                            verification=Verification.CONFIRMED,
                        )
                    )
                    return findings
        return findings

    def _inject(self, parameter, payload: str) -> str | None:
        url = getattr(parameter, "url", "") or self.ctx.base_url
        name = parameter.name
        if "?" in url and f"{name}=" in url:
            import re

            return re.sub(
                rf"([?&]{re.escape(name)}=)[^&#]*",
                lambda match: match.group(1) + quote(payload, safe="%"),
                url,
                count=1,
            )
        joiner = "&" if "?" in url else "?"
        return f"{url}{joiner}{quote(name, safe='')}={quote(payload, safe='%')}"


# -------------------------------------------------------------------------
# from prototype.py
# -------------------------------------------------------------------------

MARKER = "zspp"
MARKER_VALUE = "polluted"


@register
class PrototypePollutionCheck(BaseCheck):
    meta = CheckMeta(
        name="prototype-pollution",
        title="Prototype pollution in parameter parsing",
        description=(
            "Sends __proto__ / constructor.prototype payloads in query strings and JSON bodies "
            "and checks whether the marker changes the response, which indicates an unsafe "
            "recursive merge on the server."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        category="injection",
        remediation=(
            "Reject __proto__, constructor and prototype keys, or use a merge that only copies "
            "own properties onto a null-prototype object."
        ),
        references=["https://portswigger.net/web-security/prototype-pollution"],
        cwe="CWE-1321",
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

        probes: list[tuple[str, str, str | None]] = [
            ("query __proto__", f"{endpoint}{'&' if '?' in endpoint else '?'}__proto__[{MARKER}]={MARKER_VALUE}", None),
            ("query constructor", f"{endpoint}{'&' if '?' in endpoint else '?'}constructor[prototype][{MARKER}]={MARKER_VALUE}", None),
            ("query dot notation", f"{endpoint}{'&' if '?' in endpoint else '?'}__proto__.{MARKER}={MARKER_VALUE}", None),
        ]
        for label, url, _ in probes:
            result = await self.get(url)
            if result is None or result.error:
                continue
            if MARKER_VALUE in result.body and MARKER_VALUE not in baseline.body:
                findings.append(
                    self.make_finding(
                        title="Prototype pollution reflected by the server",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        endpoint=url,
                        status_code=result.status,
                        evidence=f"{label}: marker {MARKER_VALUE!r} appears in the response body",
                        impact=(
                            "A polluted prototype changes application behaviour for every "
                            "request, which can escalate to authorisation bypass or code execution."
                        ),
                        verification=Verification.CONFIRMED,
                    )
                )
                return findings

        payload = f'{{"__proto__":{{"{MARKER}":"{MARKER_VALUE}"}},"constructor":{{"prototype":{{"{MARKER}":"{MARKER_VALUE}"}}}}}}'
        result = await self.ctx.http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            data=payload,
            allow_redirects=False,
        )
        if result is not None and not result.error and MARKER_VALUE in (result.body or ""):
            findings.append(
                self.make_finding(
                    title="Prototype pollution accepted from a JSON body",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    endpoint=endpoint,
                    method="POST",
                    status_code=result.status,
                    evidence=f"JSON __proto__ payload echoed: {result.short_body(160)}",
                    impact=(
                        "Recursive merge of an attacker-controlled JSON object pollutes the "
                        "prototype chain."
                    ),
                    verification=Verification.INDICATOR,
                )
            )
        return findings
