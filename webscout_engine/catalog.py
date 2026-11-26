"""Central registry: what every check covers and what every module needs.

Two tables live here and nowhere else:

* :data:`CHECK_INFO` - per-check metadata (CWE, CVSS estimate, scan type,
  operational impact). ``checks.registry.register`` applies it automatically, so
  adding a check never means editing the reporting layer.
* :data:`MODULE_SPECS` - per-module metadata used by the full-scan planner, the
  coverage report and the CLI.

A test asserts that every registered check has an entry, so coverage cannot
silently drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Scan types -----------------------------------------------------------------
PASSIVE = "passive"      # reads only what a normal visitor would see
ACTIVE = "active"        # sends crafted input to the target
SOURCE = "source"        # analyses local files, never touches the network

IMPACT_NONE = "none"
IMPACT_LOW = "low"
IMPACT_MEDIUM = "medium"


@dataclass(frozen=True)
class CheckInfo:
    cwe: str | None
    cvss: float | None
    scan_type: str
    impact: str
    category: str
    summary: str


# name -> CheckInfo ---------------------------------------------------------
CHECK_INFO: dict[str, CheckInfo] = {
    # ---- configuration and transport -------------------------------------
    "security-headers": CheckInfo(
        "CWE-693", 3.7, PASSIVE, IMPACT_NONE, "configuration",
        "Missing or weak browser security headers (HSTS, CSP, nosniff, framing, referrer, permissions).",
    ),
    "cookie-attributes": CheckInfo(
        "CWE-1004", 3.1, PASSIVE, IMPACT_NONE, "session",
        "Set-Cookie responses lacking Secure, HttpOnly or a strict SameSite value.",
    ),
    "tls-configuration": CheckInfo(
        "CWE-326", 5.9, PASSIVE, IMPACT_NONE, "transport",
        "Protocol version, cipher, certificate trust, self-signing and expiry.",
    ),
    "cors-policy": CheckInfo(
        "CWE-942", 5.3, ACTIVE, IMPACT_NONE, "configuration",
        "Origin reflection, wildcard with credentials and null-origin acceptance.",
    ),
    "http-methods": CheckInfo(
        "CWE-650", 3.1, ACTIVE, IMPACT_NONE, "configuration",
        "Risky methods advertised in Allow and TRACE echo.",
    ),
    "mixed-content": CheckInfo(
        "CWE-319", 3.1, PASSIVE, IMPACT_NONE, "transport",
        "Plain-HTTP sub-resources referenced from an HTTPS page.",
    ),
    # ---- disclosure -------------------------------------------------------
    "information-disclosure": CheckInfo(
        "CWE-200", 5.3, PASSIVE, IMPACT_NONE, "disclosure",
        "Version banners, verbose errors, debug endpoints, directory listings and sensitive comments.",
    ),
    "secret-in-response": CheckInfo(
        "CWE-798", 7.5, PASSIVE, IMPACT_NONE, "disclosure",
        "API keys, private keys, tokens, internal hostnames and private IPs in HTML or JavaScript.",
    ),
    "source-disclosure": CheckInfo(
        "CWE-540", 5.3, ACTIVE, IMPACT_NONE, "disclosure",
        "Editor backups, swp files and source fragments served as text.",
    ),
    "api-exposure": CheckInfo(
        "CWE-200", 3.7, ACTIVE, IMPACT_NONE, "exposure",
        "Swagger/OpenAPI documents and a live GraphQL endpoint.",
    ),
    "template-probes": CheckInfo(
        "CWE-200", 5.3, PASSIVE, IMPACT_LOW, "exposure",
        "1028 bundled probes for product consoles, default pages, backups, logs and "
        "diagnostic endpoints, each with its own signature.",
    ),
    "api-inventory": CheckInfo(
        "CWE-1059", 3.1, ACTIVE, IMPACT_NONE, "exposure",
        "Multiple API versions reachable at once (inventory management).",
    ),
    "graphql-security": CheckInfo(
        "CWE-200", 4.3, ACTIVE, IMPACT_NONE, "exposure",
        "GraphQL introspection, field suggestions and unbounded query depth.",
    ),
    "websocket-endpoints": CheckInfo(
        "CWE-1385", 3.1, PASSIVE, IMPACT_NONE, "exposure",
        "WebSocket endpoints referenced by the client, with no visible transport protection.",
    ),
    # ---- injection --------------------------------------------------------
    "reflected-input": CheckInfo(
        "CWE-79", 6.1, ACTIVE, IMPACT_LOW, "injection",
        "A unique canary returned unencoded in the response (reflection, not proof of execution).",
    ),
    "stored-reflection": CheckInfo(
        "CWE-79", 5.3, ACTIVE, IMPACT_LOW, "injection",
        "A canary submitted through a form is returned by a later GET (persistent reflection).",
    ),
    "dom-xss-sinks": CheckInfo(
        "CWE-79", 3.1, PASSIVE, IMPACT_NONE, "injection",
        "Dangerous DOM sinks in client-side JavaScript, with attacker-controlled sources nearby.",
    ),
    "sql-error-disclosure": CheckInfo(
        "CWE-89", 5.3, ACTIVE, IMPACT_LOW, "injection",
        "Database error text produced by an unbalanced quote.",
    ),
    "sql-boolean-blind": CheckInfo(
        "CWE-89", 5.9, ACTIVE, IMPACT_LOW, "injection",
        "A TRUE/FALSE condition pair changes the response (boolean-based blind SQLi).",
    ),
    "sql-time-blind": CheckInfo(
        "CWE-89", 5.9, ACTIVE, IMPACT_MEDIUM, "injection",
        "A sleep payload delays the response measurably (time-based blind SQLi).",
    ),
    "sql-union-candidate": CheckInfo(
        "CWE-89", 5.9, ACTIVE, IMPACT_LOW, "injection",
        "ORDER BY column-count probing flips from success to error (UNION candidate).",
    ),
    "nosql-injection": CheckInfo(
        "CWE-943", 6.5, ACTIVE, IMPACT_LOW, "injection",
        "Mongo-style operator objects change authentication or query behaviour.",
    ),
    "template-evaluation": CheckInfo(
        "CWE-1336", 6.5, ACTIVE, IMPACT_LOW, "injection",
        "An arithmetic template expression is evaluated by the server.",
    ),
    "command-injection": CheckInfo(
        "CWE-78", 8.1, ACTIVE, IMPACT_MEDIUM, "injection",
        "A sleep command in a parameter delays the response (time-based OS command injection).",
    ),
    "xpath-injection": CheckInfo(
        "CWE-643", 5.3, ACTIVE, IMPACT_LOW, "injection",
        "XPath parser errors produced by quote characters.",
    ),
    "ldap-injection": CheckInfo(
        "CWE-90", 5.3, ACTIVE, IMPACT_LOW, "injection",
        "LDAP filter errors or behaviour changes from filter metacharacters.",
    ),
    "xxe": CheckInfo(
        "CWE-611", 6.5, ACTIVE, IMPACT_LOW, "injection",
        "An XML parser resolves a DOCTYPE-declared external entity.",
    ),
    "ssrf": CheckInfo(
        "CWE-918", 6.5, ACTIVE, IMPACT_LOW, "injection",
        "The server fetches a URL supplied in a parameter (closed-port probe).",
    ),
    "path-traversal": CheckInfo(
        "CWE-22", 5.3, ACTIVE, IMPACT_LOW, "injection",
        "Traversal sequences reach the filesystem layer (error-shape indicator only).",
    ),
    # ---- validation and redirects ----------------------------------------
    "open-redirect": CheckInfo(
        "CWE-601", 4.3, ACTIVE, IMPACT_NONE, "validation",
        "A canary host appears in the Location header.",
    ),
    "host-header-injection": CheckInfo(
        "CWE-644", 5.3, ACTIVE, IMPACT_NONE, "validation",
        "Forwarded host headers reflected, or CRLF injected into response headers.",
    ),
    "parameter-pollution": CheckInfo(
        "CWE-235", 3.7, ACTIVE, IMPACT_NONE, "validation",
        "Duplicate parameters are both consumed by the application.",
    ),
    # ---- authentication, session, authorisation --------------------------
    "session-configuration": CheckInfo(
        "CWE-384", 4.3, PASSIVE, IMPACT_NONE, "session",
        "Session cookie issued pre-authentication, or missing rotation hints.",
    ),
    "jwt-configuration": CheckInfo(
        "CWE-347", 5.3, PASSIVE, IMPACT_NONE, "authentication",
        "alg=none, missing expiry, kid/jku abuse surface, token leakage.",
    ),
    "oauth-configuration": CheckInfo(
        "CWE-601", 5.3, PASSIVE, IMPACT_NONE, "authentication",
        "Authorize endpoint missing state/nonce, implicit flow or open redirect_uri.",
    ),
    "csrf-protection": CheckInfo(
        "CWE-352", 4.3, PASSIVE, IMPACT_NONE, "session",
        "State-changing forms without an anti-CSRF token.",
    ),
    "access-control-indicators": CheckInfo(
        "CWE-639", 3.1, ACTIVE, IMPACT_NONE, "authorisation",
        "Administrative pages reachable unauthenticated, sequential ids returning objects.",
    ),
    "mass-assignment": CheckInfo(
        "CWE-915", 5.3, ACTIVE, IMPACT_LOW, "authorisation",
        "Privileged field names accepted and echoed back by a JSON endpoint.",
    ),
    # ---- caching and state ------------------------------------------------
    "web-cache-misconfiguration": CheckInfo(
        "CWE-525", 4.3, ACTIVE, IMPACT_NONE, "configuration",
        "Unkeyed headers reflected into a cacheable response (poisoning surface).",
    ),
    "insecure-deserialization": CheckInfo(
        "CWE-502", 6.5, PASSIVE, IMPACT_NONE, "injection",
        "Serialised object formats in cookies or hidden fields (Java, PHP, ViewState).",
    ),
    "upload-form": CheckInfo(
        "CWE-434", 3.1, PASSIVE, IMPACT_NONE, "validation",
        "A file upload form with no visible client-side restriction.",
    ),

    # ---- advanced (2.0 arsenal) -------------------------------------------
    "http-request-smuggling": CheckInfo(
        "CWE-444", 6.5, ACTIVE, IMPACT_LOW, "configuration",
        "Contradictory Content-Length / Transfer-Encoding framing accepted by the server.",
    ),
    "crlf-injection": CheckInfo(
        "CWE-113", 7.3, ACTIVE, IMPACT_LOW, "injection",
        "CR/LF sequences reach the response header parser (response splitting).",
    ),
    "prototype-pollution": CheckInfo(
        "CWE-1321", 6.5, ACTIVE, IMPACT_LOW, "injection",
        "__proto__ / constructor.prototype keys merged into server-side objects.",
    ),
    "access-control-bypass": CheckInfo(
        "CWE-284", 8.1, ACTIVE, IMPACT_LOW, "authorisation",
        "Protected paths reachable through alternative encodings or spoofed address headers.",
    ),
    "subdomain-takeover": CheckInfo(
        "CWE-350", 8.1, PASSIVE, IMPACT_NONE, "exposure",
        "CNAME records pointing at third-party services whose resource may be unclaimed.",
    ),
    "jwt-alg-none": CheckInfo(
        "CWE-347", 9.1, ACTIVE, IMPACT_LOW, "authentication",
        "An unsigned (alg=none) token is accepted in place of a signed one.",
    ),
}

# Modules -------------------------------------------------------------------
@dataclass(frozen=True)
class ModuleSpec:
    name: str
    module_id: str
    title: str
    categories: tuple[str, ...]
    scan_type: str
    impact: str
    requires: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    description: str = ""
    checks: tuple[str, ...] = field(default_factory=tuple)


MODULE_SPECS: dict[str, ModuleSpec] = {
    "infra": ModuleSpec(
        name="infra",
        module_id="ZS-MOD-INFRA",
        title="Infrastructure Reconnaissance",
        categories=("network", "dns", "technology", "tls", "exposure"),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description="Ports, service banners, DNS records, CDN/WAF, technology and TLS.",
    ),
    "origin": ModuleSpec(
        name="origin",
        module_id="ZS-MOD-ORIGIN",
        title="Origin IP Discovery",
        categories=("network", "dns", "exposure"),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description=(
            "Finds the address behind a CDN from certificate SANs, MX/SPF records and common "
            "origin hostnames. DNS only unless --osint is given."
        ),
    ),
    "params": ModuleSpec(
        name="params",
        module_id="ZS-MOD-PARAMS",
        title="Hidden Parameter Discovery",
        categories=("discovery", "injection"),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description=(
            "Appends 178 candidate parameter names and keeps the ones that change the response, "
            "so the injection checks cover inputs the crawler never saw."
        ),
    ),
    "files": ModuleSpec(
        name="files",
        module_id="ZS-MOD-FILES",
        title="Sensitive File Discovery",
        categories=("exposure", "secrets", "backup", "configuration"),
        scan_type=PASSIVE,
        impact=IMPACT_LOW,
        description="Configuration, VCS, backup, log, deployment and diagnostic files.",
    ),
    "dirs": ModuleSpec(
        name="dirs",
        module_id="ZS-MOD-DIRS",
        title="Directory and Content Discovery",
        categories=("discovery", "exposure"),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description="Wordlist enumeration with recursion and soft-404 filtering.",
    ),
    "tech": ModuleSpec(
        name="tech",
        module_id="ZS-MOD-TECH",
        title="Technology-Specific Probes",
        categories=("technology", "exposure", "configuration"),
        scan_type=PASSIVE,
        impact=IMPACT_LOW,
        description="Probes that only run for technologies actually fingerprinted on the target.",
    ),
    "vuln": ModuleSpec(
        name="vuln",
        module_id="ZS-MOD-WEB",
        title="Web Security Assessment",
        categories=(
            "injection", "configuration", "session", "authentication",
            "authorisation", "validation", "disclosure", "exposure",
        ),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description="The registered web check catalogue, run against the crawled surface.",
        checks=tuple(sorted(CHECK_INFO)),
    ),
    "arsenal": ModuleSpec(
        name="arsenal",
        module_id="ZS-MOD-ARSENAL",
        title="Probe Arsenal",
        categories=(
            "injection", "discovery", "exposure", "secrets", "configuration",
            "authentication", "authorisation", "validation",
        ),
        scan_type=ACTIVE,
        impact=IMPACT_LOW,
        description=(
            "1 300+ catalogued probes across 28 sections - files, VCS, backups, admin and API "
            "surfaces, XSS, SQLi, LFI, SSRF, redirects, command injection, host header, access "
            "bypass, IDOR, CORS, JWT, GraphQL, smuggling, cache and content-type - with "
            "differential judging and a live per-probe stream."
        ),
    ),
    "code": ModuleSpec(
        name="code",
        module_id="ZS-MOD-SAST",
        title="Source Code Analysis",
        categories=("sast", "secrets", "injection", "cryptography"),
        scan_type=SOURCE,
        impact=IMPACT_NONE,
        requires=("source_path",),
        description="Static analysis of a local source tree, reported by file and line.",
    ),
    "deps": ModuleSpec(
        name="deps",
        module_id="ZS-MOD-SCA",
        title="Dependency Analysis",
        categories=("sca", "supply-chain", "components"),
        scan_type=SOURCE,
        impact=IMPACT_NONE,
        requires=("source_path",),
        description="Parses manifests and lockfiles, matches versions against the bundled advisory map.",
    ),
}

MODULE_ORDER: tuple[str, ...] = (
    "infra", "origin", "files", "dirs", "params", "tech", "vuln", "arsenal", "code", "deps"
)


@dataclass(slots=True)
class Plan:
    selected: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def reasons(self) -> dict[str, str]:
        return dict(self.skipped)


def plan_modules(requested: list[str] | None, options: object) -> Plan:
    """Decide which modules can run, and record why the others cannot.

    Option-based requirements are checked here (a module needing a source tree is
    skipped when none was supplied). Technology-dependent decisions happen inside
    the modules, which report their own skip reason.
    """
    names = list(MODULE_ORDER) if not requested else [n for n in MODULE_ORDER if n in set(requested)]
    plan = Plan()
    for name in names:
        spec = MODULE_SPECS[name]
        missing = [
            requirement
            for requirement in spec.requires
            if not getattr(options, requirement, None)
        ]
        if missing:
            human = {"source_path": "--source <path> is required"}.get(
                missing[0], f"missing option: {missing[0]}"
            )
            plan.skipped.append((name, human))
            continue
        plan.selected.append(name)
    return plan


def check_info(name: str) -> CheckInfo | None:
    return CHECK_INFO.get(name)


def coverage_by_category() -> dict[str, list[str]]:
    """Category -> check names, used by the documentation and the HTML report."""
    grouped: dict[str, list[str]] = {}
    for name, info in sorted(CHECK_INFO.items()):
        grouped.setdefault(info.category, []).append(name)
    return grouped
