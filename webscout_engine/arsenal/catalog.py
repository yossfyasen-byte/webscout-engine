"""Probe catalogue: the probe model, matchers and every catalogued probe."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from ..core.models import Confidence, Finding, HttpResult, Severity, Verification
from . import payloads as P
from . import wordlists as W
from ..core.models import Confidence, Severity


# -------------------------------------------------------------------------
# from models.py
# -------------------------------------------------------------------------

# ---------------------------------------------------------------- matchers
MATCH_STATUS = "status"
MATCH_STATUS_NOT = "status-not"
MATCH_BODY_CONTAINS = "body-contains"
MATCH_BODY_REGEX = "body-regex"
MATCH_BODY_NOT_REGEX = "body-not-regex"
MATCH_HEADER_REGEX = "header-regex"
MATCH_HEADER_CONTAINS = "header-contains"
MATCH_HEADER_NOT_REGEX = "header-not-regex"
MATCH_LENGTH_GT = "length-gt"
MATCH_TIMING_GT = "timing-gt"
MATCH_CONTENT_TYPE = "content-type"


@dataclass(frozen=True, slots=True)
class Matcher:
    """One evidence rule. ``kind`` selects the comparison, ``value`` the operand."""

    kind: str
    value: Any = ""
    # MULTILINE matters: header matchers run against a "key: value\nkey: value"
    # blob, so an anchored pattern must match at the start of any line.
    flags: int = re.IGNORECASE | re.MULTILINE
    note: str = ""

    def evaluate(self, result: HttpResult) -> bool:
        kind = self.kind
        if kind == MATCH_STATUS:
            return result.status in self._codes()
        if kind == MATCH_STATUS_NOT:
            return result.status not in self._codes()
        if kind == MATCH_BODY_CONTAINS:
            return str(self.value).lower() in (result.body or "").lower()
        if kind == MATCH_BODY_REGEX:
            return re.search(str(self.value), result.body or "", self.flags) is not None
        if kind == MATCH_BODY_NOT_REGEX:
            return re.search(str(self.value), result.body or "", self.flags) is None
        if kind == MATCH_HEADER_REGEX:
            return re.search(str(self.value), _header_blob(result), self.flags) is not None
        if kind == MATCH_HEADER_NOT_REGEX:
            return re.search(str(self.value), _header_blob(result), self.flags) is None
        if kind == MATCH_HEADER_CONTAINS:
            return str(self.value).lower() in _header_blob(result).lower()
        if kind == MATCH_LENGTH_GT:
            return result.body_length > float(self.value)
        if kind == MATCH_TIMING_GT:
            return result.elapsed >= float(self.value)
        if kind == MATCH_CONTENT_TYPE:
            return str(self.value).lower() in (result.content_type or "").lower()
        return False

    def _codes(self) -> set[int]:
        if isinstance(self.value, (list, tuple, set)):
            return {int(code) for code in self.value}
        if isinstance(self.value, str) and "," in self.value:
            return {int(part) for part in self.value.split(",") if part.strip().isdigit()}
        try:
            return {int(self.value)}
        except (TypeError, ValueError):
            return set()

    def describe(self) -> str:
        return f"{self.kind}:{self.value}"


def _header_blob(result: HttpResult) -> str:
    return "\n".join(f"{key}: {value}" for key, value in result.headers.items())


@dataclass(frozen=True, slots=True)
class Probe:
    """One HTTP interaction and the rules that make it worth reporting."""

    id: str
    section: str
    title: str
    method: str = "GET"
    path: str = "/"
    query: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    content_type: str | None = None
    matchers: tuple[Matcher, ...] = ()
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    cwe: str | None = None
    impact: str = ""
    remediation: str = ""
    tags: tuple[str, ...] = ()
    follow: bool = False
    # A probe whose truth depends on a comparison against a control request
    # (time-based, boolean-based) is marked differential and judged by the engine.
    differential: str | None = None
    param_name: str | None = None
    control_query: str | None = None
    payload: str | None = None
    verify: bool = True

    # ---------------------------------------------------------------- helpers
    def header_dict(self) -> dict[str, str]:
        return {key: value for key, value in self.headers}

    def describe(self) -> str:
        target = self.path or "/"
        if self.query:
            target = f"{target}?{self.query}"
        return f"{self.method} {target}"


@dataclass
class ProbeHit:
    """A probe that produced evidence, with the response that justified it."""

    probe: Probe
    result: HttpResult
    evidence: str
    matched: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_observation(self, module: str = "arsenal"):
        from ..core.models import Observation

        return Observation(
            kind="arsenal",
            target=self.result.url,
            label=self.probe.title,
            status=str(self.result.status),
            detail=self.evidence,
            metadata={"module": module, "probe": self.probe.id, "section": self.probe.section},
        )

    def to_finding(self, module: str = "arsenal") -> Finding:
        probe = self.probe
        verification = (
            Verification.CONFIRMED
            if probe.confidence.rank <= Confidence.HIGH.rank
            else Verification.INDICATOR
        )
        return Finding(
            title=probe.title,
            severity=probe.severity,
            confidence=probe.confidence,
            module=module,
            check=probe.section,
            endpoint=self.result.url or probe.path,
            method=probe.method,
            parameter=self.extra.get("parameter"),
            status_code=self.result.status or None,
            evidence=self.evidence,
            impact=probe.impact,
            remediation=probe.remediation,
            references=[],
            cwe=probe.cwe,
            scan_type="active",
            verification=verification,
        )


@dataclass(slots=True)
class SectionStat:
    """Per-section counters, used by the live renderer and the report."""

    name: str
    label: str
    total: int = 0
    done: int = 0
    hits: int = 0
    errors: int = 0
    duration: float = 0.0


@dataclass(slots=True)
class ArsenalResult:
    hits: list[ProbeHit] = field(default_factory=list)
    sections: list[SectionStat] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    requests: int = 0
    skipped: int = 0

    @property
    def total_probes(self) -> int:
        return sum(section.total for section in self.sections)


# -------------------------------------------------------------------------
# from catalog.py
# -------------------------------------------------------------------------

SECTION_LABELS: dict[str, str] = {
    "recon": "Reconnaissance",
    "banner": "Server banner",
    "methods": "HTTP methods",
    "headers": "Header disclosure",
    "files": "Sensitive files",
    "vcs": "Version control exposure",
    "backup": "Backup and dump exposure",
    "config": "Configuration exposure",
    "listing": "Directory listings and surfaces",
    "admin": "Administrative surfaces",
    "api": "API surface",
    "tech": "Technology consoles",
    "links": "Links and secrets",
    "xss": "Cross-site scripting",
    "sqli": "SQL injection",
    "lfi": "Path traversal / LFI",
    "ssrf": "Server-side request forgery",
    "redirect": "Open redirect",
    "cmdi": "Command injection",
    "host": "Host header injection",
    "bypass": "Access-control bypass",
    "idor": "IDOR and object access",
    "cors": "CORS policy",
    "jwt": "JWT exposure",
    "graphql": "GraphQL surface",
    "smuggling": "Request smuggling",
    "cache": "Cache poisoning surface",
    "misc": "Content-type and misc",
}

SECTION_ORDER: tuple[str, ...] = tuple(SECTION_LABELS)

_PREFIX: dict[str, str] = {
    "recon": "RC", "banner": "BN", "methods": "MT", "headers": "HD",
    "files": "SF", "vcs": "VC", "backup": "BK", "config": "CF",
    "listing": "DL", "admin": "AD", "api": "AP", "tech": "TP",
    "links": "LK", "xss": "XS", "sqli": "SQ", "lfi": "LF",
    "ssrf": "SR", "redirect": "OR", "cmdi": "CM", "host": "HH",
    "bypass": "AB", "idor": "ID", "cors": "CO", "jwt": "JW",
    "graphql": "GQ", "smuggling": "SM", "cache": "CP", "misc": "MS",
}

SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Sections whose payload is injected into a discovered parameter. The executor
# rewrites the query for every parameter it decides to cover.
PARAMETRIC_SECTIONS: frozenset[str] = frozenset(
    {"xss", "sqli", "lfi", "ssrf", "redirect", "cmdi"}
)

# Backup suffix variants: real deployments leave these behind constantly, and a
# scanner that only tries ".bak" misses most of them.
BACKUP_SUFFIXES: tuple[str, ...] = (
    "", ".bak", ".old", "~", ".save", ".swp", ".orig", ".tmp",
    ".1", ".2", ".copy", ".backup", ".txt", ".dist", ".disabled",
)

CONFIG_BASES: tuple[str, ...] = (
    "config.php", "config.json", "config.yml", "config.yaml", "config.xml",
    "config.ini", "config.js", "settings.py", "settings.json", "app.config",
    "web.config", "application.properties", "application.yml", ".htaccess",
    "wp-config.php", "configuration.php", "parameters.yml", "local.settings.json",
)

MISC_FILES: tuple[tuple[str, str | None, str, str], ...] = (
    (".htaccess", r"(RewriteRule|AuthType|Order )", "medium", "Apache access rules"),
    (".htaccess.bak", r"(RewriteRule|AuthType|Order )", "high", "Apache access rules backup"),
    (".htaccess.old", r"(RewriteRule|AuthType|Order )", "high", "Apache access rules backup"),
    (".htpasswd", r"^[^:]+:", "high", "Password file"),
    (".DS_Store", None, "low", "macOS metadata (path disclosure)"),
    ("Thumbs.db", None, "low", "Windows thumbnail cache"),
    (".editorconfig", r"(root|indent)", "info", "Editor configuration"),
    (".eslintrc", r"(\{|extends)", "info", "Linter configuration"),
    (".babelrc", r"(\{|presets)", "info", "Babel configuration"),
    (".prettierrc", r"(\{|semi)", "info", "Formatter configuration"),
    (".npmignore", r"(?m)^\S+", "info", "npm ignore rules"),
    (".dockerignore", r"(?m)^\S+", "info", "Docker ignore rules"),
    (".gitlab-ci.yml", r"(stages|script)", "medium", "CI pipeline definition"),
    (".travis.yml", r"(language|script)", "low", "CI pipeline definition"),
    (".circleci/config.yml", r"(jobs|workflows)", "medium", "CI pipeline definition"),
    ("azure-pipelines.yml", r"(steps|pool)", "medium", "CI pipeline definition"),
    ("Jenkinsfile", r"(pipeline|agent)", "medium", "Jenkins pipeline"),
    ("bitbucket-pipelines.yml", r"(pipelines)", "medium", "CI pipeline definition"),
    ("Dockerfile", r"^FROM ", "low", "Container definition"),
    ("docker-compose.yml", r"(services|image)", "medium", "Compose definition"),
    ("docker-compose.override.yml", r"(services|image)", "medium", "Compose override"),
    ("k8s.yaml", r"(apiVersion|kind)", "medium", "Kubernetes manifest"),
    ("deployment.yaml", r"(apiVersion|kind)", "medium", "Kubernetes manifest"),
    ("helm/values.yaml", r"(image|replicaCount)", "low", "Helm values"),
    ("serverless.yml", r"(provider|functions)", "medium", "Serverless definition"),
    ("terraform.tfstate", r"(\"version\"|resources)", "critical", "Terraform state (secrets)"),
    ("terraform.tfstate.backup", r"(\"version\"|resources)", "critical", "Terraform state backup"),
    (".terraform/terraform.tfstate", r"(\"version\"|resources)", "critical", "Terraform state"),
    ("ansible.cfg", r"(\[defaults\])", "low", "Ansible configuration"),
    ("inventory.ini", r"(\[all\]|ansible_host)", "high", "Ansible inventory (hosts)"),
    ("hosts", r"127\.0\.0\.1", "medium", "Hosts file"),
    ("php.ini", r"(\[PHP\]|display_errors)", "medium", "PHP configuration"),
    ("my.cnf", r"(\[mysqld\]|password)", "high", "MySQL configuration"),
    ("my.cnf.bak", r"(\[mysqld\]|password)", "critical", "MySQL configuration backup"),
    (".pgpass", r"^[^:]+:[^:]+:", "critical", "PostgreSQL credentials"),
    ("pg_hba.conf", r"(host|local)\s+", "medium", "PostgreSQL access rules"),
    ("redis.conf", r"(requirepass|bind)", "high", "Redis configuration"),
    ("mongod.conf", r"(net|security)", "medium", "MongoDB configuration"),
    ("elasticsearch.yml", r"(cluster|network)", "medium", "Elasticsearch configuration"),
    ("sites-available/default", r"(server_name|root)", "medium", "Nginx site configuration"),
    ("nginx.conf", r"(server|location)", "medium", "Nginx configuration"),
    ("httpd.conf", r"(ServerRoot|DocumentRoot)", "medium", "Apache configuration"),
    ("apache2.conf", r"(ServerRoot|Include)", "medium", "Apache configuration"),
    ("proc/self/environ", r"(PATH=|HTTP_)", "high", "Process environment"),
    ("proc/self/cmdline", r"(/bin/|python|node)", "medium", "Process command line"),
    ("proc/version", r"Linux version", "low", "Kernel version"),
    ("etc/passwd", r"root:.*:0:0:", "critical", "Local file disclosure"),
    ("etc/hostname", r"\w", "low", "Host name disclosure"),
    ("etc/hosts", r"localhost", "low", "Hosts file disclosure"),
    ("var/log/apache2/access.log", r"GET /", "high", "Access log disclosure"),
    ("var/log/nginx/access.log", r"GET /", "high", "Access log disclosure"),
    ("var/log/syslog", r"\w{3}\s+\d+", "medium", "System log disclosure"),
    ("storage/logs/laravel.log", r"(ERROR|production)", "high", "Framework log"),
    ("var/log/mysql/error.log", r"(ERROR|Warning)", "medium", "Database log"),
    ("debug.log", r"(Traceback|ERROR|Warning)", "medium", "Debug log"),
    ("error.log", r"(Traceback|ERROR|Warning)", "medium", "Error log"),
    ("error_log", r"(Traceback|ERROR|Warning)", "medium", "Error log"),
    ("access.log", r"GET /", "medium", "Access log"),
    ("npm-debug.log", r"(error|verbose)", "low", "npm debug log"),
    ("yarn-error.log", r"(error|verbose)", "low", "Yarn error log"),
    ("composer.phar", r"(Composer|phar)", "low", "Composer binary"),
    ("phpunit.xml.dist", r"<phpunit", "low", "Test configuration"),
    ("Makefile.bak", r"(?m)^[\w-]+:", "low", "Build file backup"),
    ("readme.md", r"(#|##)", "info", "Readme (version disclosure)"),
    ("CHANGELOG.md", r"(?m)^#", "info", "Changelog (version disclosure)"),
    ("TODO.md", r"(?m)^#", "info", "Todo list (internal notes)"),
    ("LICENSE.txt", r"(license|License)", "info", "Licence file"),
    (".well-known/assetlinks.json", r"(\[)", "info", "Android asset links"),
    (".well-known/apple-app-site-association", r"(\{)", "info", "Apple app site association"),
    (".well-known/mta-sts.txt", r"(version:|mode:)", "info", "MTA-STS policy"),
    ("sitemap.xml.gz", None, "info", "Compressed sitemap"),
    ("feed.xml", r"<rss|<feed", "info", "Feed"),
    ("atom.xml", r"<feed", "info", "Feed"),
    ("rss.xml", r"<rss", "info", "Feed"),
    ("phpinfo.php", r"PHP Version", "medium", "phpinfo disclosure"),
    ("info.php", r"PHP Version", "medium", "phpinfo disclosure"),
    ("test.php", r"PHP Version", "low", "PHP test page"),
    ("shell.php", None, "critical", "Possible web shell"),
    ("cmd.php", None, "critical", "Possible web shell"),
    ("c99.php", None, "critical", "Known web shell"),
    ("r57.php", None, "critical", "Known web shell"),
    ("wso.php", None, "critical", "Known web shell"),
    ("uploader.php", None, "high", "Uploader script"),
    ("backdoor.php", None, "critical", "Possible backdoor"),
    ("webshell.php", None, "critical", "Possible web shell"),
)


def _sev(name: str) -> Severity:
    return SEVERITY_BY_NAME.get(name, Severity.INFO)


class _Builder:
    """Accumulates probes and hands out stable, section-scoped ids."""

    def __init__(self) -> None:
        self._items: list[Probe] = []
        self._counters: dict[str, int] = {}

    def add(self, probe: Probe) -> None:
        self._items.append(probe)

    def make(self, section: str, title: str, **kwargs: object) -> Probe:
        index = self._counters.get(section, 0) + 1
        self._counters[section] = index
        probe_id = f"{_PREFIX.get(section, 'ZZ')}-{index:04d}"
        return Probe(id=probe_id, section=section, title=title, **kwargs)  # type: ignore[arg-type]

    def path_probe(
        self,
        section: str,
        path: str,
        title: str,
        signature: str | None,
        severity: str,
        note: str,
        *,
        confidence: Confidence = Confidence.HIGH,
        cwe: str = "CWE-200",
        remediation: str = "",
        tags: tuple[str, ...] = (),
    ) -> None:
        matchers: list[Matcher] = [Matcher(MATCH_STATUS, (200, 206))]
        if signature:
            matchers.append(Matcher(MATCH_BODY_REGEX, signature))
        else:
            matchers.append(Matcher(MATCH_LENGTH_GT, 0))
            confidence = Confidence.LOW
        self.add(
            self.make(
                section,
                f"{title}: /{path}",
                path="/" + path.lstrip("/"),
                matchers=tuple(matchers),
                severity=_sev(severity),
                confidence=confidence,
                cwe=cwe,
                impact=note,
                remediation=remediation or "Remove the file from the web root or block it at the edge.",
                tags=tags,
            )
        )

    def build(self) -> list[Probe]:
        return list(self._items)


def _recon(b: _Builder) -> None:
    for path, title in (
        ("/", "Root page"),
        ("/robots.txt", "Robots"),
        ("/sitemap.xml", "Sitemap"),
        ("/.well-known/security.txt", "Security contact"),
    ):
        b.add(
            b.make(
                "recon",
                f"Baseline fetch: {title}",
                path=path,
                matchers=(Matcher(MATCH_STATUS, (200, 301, 302, 401, 403)),),
                severity=Severity.INFO,
                confidence=Confidence.CERTAIN,
                tags=("baseline",),
            )
        )


def _banner(b: _Builder) -> None:
    for header, pattern, title in (
        ("server", r"[A-Za-z]+/[\d.]+", "Server software and version"),
        ("x-powered-by", r".+", "Technology disclosure via X-Powered-By"),
        ("x-aspnet-version", r".+", "ASP.NET version disclosure"),
        ("x-aspnetmvc-version", r".+", "ASP.NET MVC version disclosure"),
        ("x-generator", r".+", "Generator disclosure"),
        ("x-drupal-cache", r".+", "Drupal cache header"),
        ("x-runtime", r".+", "Framework runtime disclosure"),
        ("x-version", r".+", "Version header"),
        ("x-backend-server", r".+", "Backend server disclosure"),
        ("via", r".+", "Proxy disclosure"),
        ("x-varnish", r".+", "Varnish cache disclosure"),
        ("x-cache", r".+", "Cache disclosure"),
    ):
        b.add(
            b.make(
                "banner",
                f"{title} ({header})",
                path="/",
                matchers=(
                    Matcher(MATCH_STATUS, (200, 201, 204, 301, 302, 400, 401, 403, 404, 500)),
                    Matcher(MATCH_HEADER_REGEX, f"^{header}:\\s*{pattern}"),
                ),
                severity=Severity.LOW if header != "x-powered-by" else Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-200",
                impact=f"The response advertises {header}.",
                remediation="Suppress version banners at the reverse proxy or application server.",
                tags=("banner",),
            )
        )


def _methods(b: _Builder) -> None:
    # Safe verbs (GET/HEAD/POST) are always available; probing them proves
    # nothing and only adds noise, so only risky verbs are catalogued.
    for method in ("PUT", "DELETE", "PATCH", "CONNECT"):
        b.add(
            b.make(
                "methods",
                f"Method {method}",
                method=method,
                path="/",
                matchers=(
                    Matcher(MATCH_STATUS_NOT, (405, 501)),
                    Matcher(MATCH_STATUS, (200, 201, 202, 204, 301, 302, 400, 401, 403, 404)),
                ),
                severity=Severity.LOW if method in {"PUT", "DELETE", "PATCH", "CONNECT"} else Severity.INFO,
                confidence=Confidence.MEDIUM,
                cwe="CWE-650",
                impact=f"The server answers {method} requests.",
                remediation="Restrict the accepted method set per route.",
                tags=("method",),
            )
        )
    for method in ("TRACE", "TRACK"):
        b.add(
            b.make(
                "methods",
                f"Cross-site tracing via {method}",
                method=method,
                path="/",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, "TRACE /|TRACK /"),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-693",
                impact="The server echoes the request back, enabling cross-site tracing.",
                remediation="Disable TRACE/TRACK at the web server.",
                tags=("method",),
            )
        )
    b.add(
        b.make(
            "methods",
            "OPTIONS advertises risky methods",
            method="OPTIONS",
            path="/",
            matchers=(
                Matcher(MATCH_HEADER_REGEX, r"^(allow|access-control-allow-methods):.*\b(PUT|DELETE|TRACE|PATCH)\b"),
            ),
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            cwe="CWE-650",
            impact="The Allow header lists state-changing or diagnostic methods.",
            remediation="Reduce the advertised method set.",
            tags=("method",),
        )
    )


def _headers(b: _Builder) -> None:
    for path, pattern, title, severity in (
        ("/", r"(?i)(exception|stack trace|traceback|at [\w.]+\([\w.]+:\d+\))", "Stack trace in the response body", "medium"),
        ("/", r"(?i)(you have an error in your sql syntax|sqlstate|ORA-\d{5})", "Database error leaked to the client", "high"),
        ("/", r"(?i)(warning: |notice: |fatal error: )", "PHP diagnostic output", "medium"),
        ("/", r"(?i)(disallowedhost|debug = true|settings\.debug)", "Framework debug mode enabled", "medium"),
        ("/", r"(?i)(index of /|<title>directory listing)", "Directory listing", "medium"),
        ("/nonexistent-zs-canary-9f3a", r"(?i)(traceback|stack trace|at [\w.]+\([\w.]+:\d+\))", "Error page discloses a stack trace", "medium"),
        ("/nonexistent-zs-canary-9f3a", r"(?i)(nginx/\d|apache/\d|werkzeug|express)", "Error page discloses server software", "low"),
        ("/nonexistent-zs-canary-9f3a", r"(?i)(exception in|line \d+ in|file \"[^\"]+\")", "Error page discloses file paths", "medium"),
    ):
        b.add(
            b.make(
                "headers",
                title,
                path=path,
                matchers=(Matcher(MATCH_STATUS_NOT, (0,)), Matcher(MATCH_BODY_REGEX, pattern)),
                severity=_sev(severity),
                confidence=Confidence.MEDIUM,
                cwe="CWE-209",
                impact="Verbose output gives an attacker implementation detail.",
                remediation="Disable debug mode and return generic error pages.",
                tags=("disclosure",),
            )
        )
    for header, title in (
        ("x-debug-token", "Symfony profiler token"),
        ("x-debug-token-link", "Symfony profiler link"),
        ("x-served-by", "Edge server identity"),
        ("x-timer", "Cache timing disclosure"),
    ):
        b.add(
            b.make(
                "headers",
                title,
                path="/",
                matchers=(Matcher(MATCH_HEADER_CONTAINS, header + ":"),),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-200",
                impact=f"The {header} header discloses infrastructure detail.",
                remediation="Strip diagnostic headers at the edge.",
                tags=("disclosure",),
            )
        )


def _files(b: _Builder) -> None:
    for path, signature, severity, note in W.SECRET_FILES:
        b.path_probe("files", path, "Credential file exposed", signature, severity, note,
                     cwe="CWE-538", tags=("secret", "file"))
    for path, signature, severity, note in W.VCS_FILES:
        b.path_probe("vcs", path, "Version control metadata exposed", signature, severity, note,
                     cwe="CWE-527", tags=("vcs",))
    for path, signature, severity, note in W.BACKUP_FILES:
        b.path_probe("backup", path, "Backup artefact exposed", signature, severity, note,
                     cwe="CWE-530", tags=("backup",))
    for path, signature, severity, note in W.CONFIG_FILES:
        b.path_probe("config", path, "Configuration exposed", signature, severity, note,
                     cwe="CWE-16", tags=("config",))
    for path, signature, severity, note in MISC_FILES:
        b.path_probe("config", path, "Sensitive artefact exposed", signature, severity, note,
                     cwe="CWE-200", tags=("misc",))

    # Generated backup variants of the highest-value configuration names.
    for base in CONFIG_BASES:
        for suffix in BACKUP_SUFFIXES:
            if not suffix:
                continue
            path = base + suffix
            b.add(
                b.make(
                    "config",
                    f"Configuration backup variant: /{path}",
                    path="/" + path,
                    matchers=(
                        Matcher(MATCH_STATUS, (200, 206)),
                        Matcher(MATCH_LENGTH_GT, 40),
                        Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(404 not found|page not found|does not exist)"),
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    cwe="CWE-530",
                    impact="A backup of a configuration file is served as plain text.",
                    remediation="Block backup suffixes at the edge and remove stray files.",
                    tags=("backup", "variant"),
                )
            )

    for path, signature, severity, note in W.DIR_LISTINGS:
        b.path_probe("listing", path, "Exposed directory or surface", signature, severity, note,
                     cwe="CWE-548", tags=("listing",))

    for path in W.ADMIN_PATHS:
        b.add(
            b.make(
                "admin",
                f"Administrative surface: /{path}",
                path="/" + path.lstrip("/"),
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, r"(?i)(admin|dashboard|login|sign in|password|username|logout)"),
                    Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(404 not found|page not found)"),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-284",
                impact="An administrative interface is reachable without authentication.",
                remediation="Put the interface behind authentication and an IP allowlist.",
                tags=("admin",),
            )
        )

    for path in W.API_PATHS:
        b.add(
            b.make(
                "api",
                f"API endpoint: /{path}",
                path="/" + path,
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, r"(?i)(^\s*[\[{]|\"(data|error|message|items|results|user|email|username)\")"),
                ),
                severity=Severity.MEDIUM if "admin" in path or "secret" in path or "backup" in path else Severity.LOW,
                confidence=Confidence.MEDIUM,
                cwe="CWE-200",
                impact="The endpoint returns structured data without authentication.",
                remediation="Require authentication and authorisation on every data endpoint.",
                tags=("api",),
            )
        )

    for name in W.COMMON_DIRS:
        b.add(
            b.make(
                "listing",
                f"Directory present: /{name}/",
                path=f"/{name}/",
                matchers=(
                    Matcher(MATCH_STATUS, (200, 301, 302, 403)),
                    Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(404 not found|page not found)"),
                ),
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                cwe="CWE-200",
                impact="The directory responds differently from a random path.",
                remediation="Return a consistent 404 for non-public directories.",
                tags=("dir",),
            )
        )
    for name in W.COMMON_FILES:
        b.add(
            b.make(
                "listing",
                f"Script present: /{name}",
                path="/" + name,
                matchers=(
                    Matcher(MATCH_STATUS, (200, 401, 403, 500)),
                    Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(404 not found|page not found)"),
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                cwe="CWE-200",
                impact="The script exists and is reachable.",
                remediation="Remove unused scripts and require authorisation.",
                tags=("file",),
            )
        )
    for path in W.WP_PATHS:
        b.add(
            b.make(
                "listing",
                f"WordPress surface: /{path}",
                path="/" + path,
                matchers=(
                    Matcher(MATCH_STATUS, (200, 401, 403)),
                    Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(404 not found|page not found)"),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-200",
                impact="A WordPress management or data surface is reachable.",
                remediation="Restrict wp-admin and the REST API to authenticated users.",
                tags=("wordpress",),
            )
        )
    for tech, path, pattern in W.TECH_PROBES:
        b.add(
            b.make(
                "tech",
                f"{tech} console probe: /{path}",
                path="/" + path,
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, pattern),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-200",
                impact=f"A {tech} diagnostic or management surface is reachable.",
                remediation="Disable management consoles in production or restrict them by network.",
                tags=("tech", tech),
            )
        )


def _links(b: _Builder) -> None:
    patterns: tuple[tuple[str, str, str], ...] = (
        ("aws-access-key", r"AKIA[0-9A-Z]{16}", "AWS access key id in the page"),
        ("aws-secret", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "AWS secret access key"),
        ("google-api-key", r"AIza[0-9A-Za-z_-]{35}", "Google API key"),
        ("firebase", r"(?i)firebaseio\.com|firebase\.google\.com", "Firebase project reference"),
        ("stripe-live", r"sk_live_[0-9a-zA-Z]{20,}", "Stripe live secret key"),
        ("stripe-test", r"sk_test_[0-9a-zA-Z]{20,}", "Stripe test secret key"),
        ("github-token", r"gh[pousr]_[0-9A-Za-z]{30,}", "GitHub token"),
        ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack token"),
        ("private-key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key material"),
        ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", "JWT in the page"),
        ("basic-auth-url", r"[a-z]+://[^/\s:@]+:[^/\s@]+@[^/\s]+", "Credentials embedded in a URL"),
        ("internal-host", r"(?i)(https?://)?[a-z0-9-]+\.(internal|local|corp|lan|intranet)\b", "Internal host name"),
        ("private-ip", r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "Private IP address"),
        ("db-uri", r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s\"'<>]+", "Database connection URI"),
        ("password-field", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]", "Hard-coded password"),
        ("email-list", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email address in the page"),
        ("source-map", r"//# sourceMappingURL=([^\s]+\.map)", "Source map reference"),
        ("api-key-generic", r"(?i)(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}['\"]", "Generic API key"),
        ("s3-bucket", r"[a-z0-9.-]+\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com", "S3 bucket reference"),
        ("debug-comment", r"(?i)<!--[^>]*(todo|fixme|hack|password|secret|remove)[^>]*-->", "Sensitive developer comment"),
    )
    for label, pattern, title in patterns:
        severity = Severity.HIGH if label in {
            "aws-access-key", "aws-secret", "stripe-live", "github-token",
            "private-key", "basic-auth-url", "db-uri", "password-field",
        } else Severity.MEDIUM if label in {
            "google-api-key", "slack-token", "jwt", "api-key-generic", "stripe-test",
        } else Severity.LOW
        b.add(
            b.make(
                "links",
                f"{title} ({label})",
                path="/",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, pattern),
                ),
                severity=severity,
                confidence=Confidence.MEDIUM if severity.rank >= Severity.MEDIUM.rank else Confidence.LOW,
                cwe="CWE-798",
                impact="Client-visible content carries a secret or an internal reference.",
                remediation="Move secrets server-side, rotate anything exposed and strip comments from production builds.",
                tags=("secret", label),
            )
        )


def _xss(b: _Builder) -> None:
    for label, payload, marker in P.XSS:
        b.add(
            b.make(
                "xss",
                f"Reflected XSS via {label}",
                path="/",
                query=f"q={payload}",
                param_name="q",
                payload=payload,
                control_query="q=zs-canary-1",
                differential="control-negative",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_CONTAINS, marker),
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                cwe="CWE-79",
                impact="User input is returned unencoded, so script executes in the victim's browser.",
                remediation="Encode output contextually and enforce a strict CSP.",
                tags=("xss", label),
            )
        )
    for label, payload, marker in P.XSS_JSON:
        b.add(
            b.make(
                "xss",
                f"Reflected XSS in a JSON response via {label}",
                path="/",
                query=f"q={payload}",
                param_name="q",
                payload=payload,
                control_query="q=zs-canary-1",
                differential="control-negative",
                headers=(("Accept", "application/json"),),
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_CONTENT_TYPE, "json"),
                    Matcher(MATCH_BODY_CONTAINS, marker),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                cwe="CWE-79",
                impact="JSON responses are rendered as HTML by some clients.",
                remediation="Serve JSON with the correct content type and X-Content-Type-Options.",
                tags=("xss", "json"),
            )
        )


BOOLEAN_TWINS: dict[str, str] = {
    "' OR '1'='1": "' OR '1'='2",
    "' OR 1=1-- -": "' OR 1=2-- -",
    '" OR "1"="1': '" OR "1"="2',
    "1' AND '1'='1": "1' AND '1'='2",
    "1' AND '1'='2": "1' AND '1'='1",
    "1 OR 1=1": "1 OR 1=2",
    "1 AND 1=2": "1 AND 1=1",
}


def _sqli(b: _Builder) -> None:
    for label, payload, kind in P.SQLI:
        rendered = payload
        control = "q=1"
        if kind == "time":
            rendered = payload.replace("{delay}", "5")
            differential = "time"
            matchers = (
                Matcher(MATCH_TIMING_GT, 4.0),
                Matcher(MATCH_STATUS_NOT, (0,)),
            )
            severity, confidence = Severity.HIGH, Confidence.MEDIUM
        elif kind == "boolean":
            differential = "boolean"
            matchers = (
                Matcher(MATCH_STATUS_NOT, (0,)),
            )
            severity, confidence = Severity.HIGH, Confidence.LOW
            twin = BOOLEAN_TWINS.get(payload, payload)
            control = f"q={twin}"
        else:
            differential = None
            matchers = (
                Matcher(MATCH_STATUS_NOT, (0,)),
                Matcher(MATCH_BODY_REGEX, "|".join(P.SQL_ERROR_SIGNATURES)),
            )
            severity, confidence = Severity.HIGH, Confidence.MEDIUM
        b.add(
            b.make(
                "sqli",
                f"SQL injection via {label}",
                path="/",
                query=f"q={rendered}",
                param_name="q",
                payload=rendered,
                control_query=control,
                differential=differential,
                matchers=matchers,
                severity=severity,
                confidence=confidence,
                cwe="CWE-89",
                impact="Injected SQL reaches the database, allowing data disclosure or modification.",
                remediation="Use parameterised queries and never concatenate input into SQL.",
                tags=("sqli", kind, label),
            )
        )


def _lfi(b: _Builder) -> None:
    for label, payload, signature in P.LFI:
        b.add(
            b.make(
                "lfi",
                f"Local file disclosure via {label}",
                path="/",
                query=f"file={payload}",
                param_name="file",
                payload=payload,
                control_query="file=zs-canary.txt",
                differential="control-negative",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, signature),
                ),
                severity=Severity.HIGH if "passwd" in payload or "shadow" in payload else Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-22",
                impact="Files outside the web root are readable, including configuration and credentials.",
                remediation="Resolve paths against an allowlist and never build file paths from input.",
                tags=("lfi", "traversal", label),
            )
        )


def _ssrf(b: _Builder) -> None:
    for label, url, signature in P.SSRF:
        b.add(
            b.make(
                "ssrf",
                f"Server-side request forgery via {label}",
                path="/",
                query=f"url={url}",
                param_name="url",
                payload=url,
                control_query="url=http://zs-canary.invalid/",
                differential="control-negative",
                matchers=(
                    Matcher(MATCH_STATUS, (200, 500, 502, 503)),
                    Matcher(MATCH_BODY_REGEX, signature),
                ),
                severity=Severity.HIGH if "169.254" in url or "metadata" in url else Severity.MEDIUM,
                confidence=Confidence.LOW,
                cwe="CWE-918",
                impact="The server can be made to fetch internal addresses, including cloud metadata.",
                remediation="Allowlist outbound destinations and block link-local ranges.",
                tags=("ssrf", label),
            )
        )


def _redirect(b: _Builder) -> None:
    for label, payload in P.REDIRECT:
        b.add(
            b.make(
                "redirect",
                f"Open redirect via {label}",
                path="/",
                query=f"next={payload}",
                param_name="next",
                payload=payload,
                control_query="next=/",
                follow=False,
                matchers=(
                    Matcher(MATCH_STATUS, (301, 302, 303, 307, 308)),
                    # The redirect must leave the site: an absolute URL, a
                    # protocol-relative one, or a script/data scheme. A Location
                    # that is a single-slash path stays on the same host.
                    Matcher(MATCH_HEADER_REGEX, r"^location:\s*(?:.*evil\.example|javascript:|data:)"),
                    Matcher(
                        MATCH_HEADER_NOT_REGEX,
                        r"^location:\s*/(?![/\\])",
                    ),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-601",
                impact="Attackers can bounce users to an arbitrary domain from a trusted link.",
                remediation="Resolve redirect targets against an allowlist of paths or hosts.",
                tags=("redirect", label),
            )
        )


def _cmdi(b: _Builder) -> None:
    for label, payload, delay in P.CMDI:
        rendered = payload.replace("{delay}", "5")
        time_based = delay is not None
        matchers = (
            (Matcher(MATCH_TIMING_GT, 4.0), Matcher(MATCH_STATUS_NOT, (0,)))
            if time_based
            else (
                Matcher(MATCH_STATUS_NOT, (0,)),
                Matcher(MATCH_BODY_REGEX, "|".join(P.CMDI_SIGNATURES)),
            )
        )
        b.add(
            b.make(
                "cmdi",
                f"OS command injection via {label}",
                path="/",
                query=f"ip={rendered}",
                param_name="ip",
                payload=rendered,
                control_query="ip=127.0.0.1",
                differential="time" if time_based else "control-negative",
                matchers=matchers,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM if time_based else Confidence.LOW,
                cwe="CWE-78",
                impact="Arbitrary commands run as the web server user.",
                remediation="Never pass input to a shell; use an API with an argument array.",
                tags=("cmdi", label),
            )
        )


def _host(b: _Builder) -> None:
    for header in P.HOST_HEADERS:
        value = "evil.example" if header not in {
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Remote-IP",
            "X-Originating-IP", "Client-IP", "True-Client-IP", "CF-Connecting-IP",
            "Fastly-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-Ip",
            "X-Custom-IP-Authorization", "X-Forwarded",
        } else "127.0.0.1"
        b.add(
            b.make(
                "host",
                f"Host header injection via {header}",
                path="/",
                headers=((header, value),),
                matchers=(
                    Matcher(MATCH_STATUS, (200, 301, 302)),
                    Matcher(MATCH_BODY_REGEX, r"evil\.example"),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-644",
                impact="A spoofed header is reflected into links or redirects, enabling cache poisoning and password-reset theft.",
                remediation="Validate the Host header against a fixed allowlist.",
                tags=("host", header.lower()),
            )
        )
    for label, value in (
        ("crlf-basic", "%0d%0aInjected-Header: zs"),
        ("crlf-lf-only", "%0aInjected-Header: zs"),
        ("crlf-double-encoded", "%250d%250aInjected-Header: zs"),
    ):
        b.add(
            b.make(
                "host",
                f"CRLF injection via {label}",
                path="/",
                query=f"q={value}",
                param_name="q",
                payload=value,
                matchers=(Matcher(MATCH_HEADER_CONTAINS, "injected-header: zs"),),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-113",
                impact="Response headers can be split, enabling cache poisoning and XSS.",
                remediation="Strip CR/LF from any value written into a header.",
                tags=("crlf",),
            )
        )


def _bypass(b: _Builder) -> None:
    targets = ("admin", "api/admin", "admin/users", "dashboard")
    for base in targets:
        upper = base.upper()
        mixed = "".join(ch.upper() if i % 2 else ch for i, ch in enumerate(base))
        encoded = base.replace("a", "%61").replace("d", "%64")
        for label, template in P.BYPASS_PATHS:
            path = template.format(
                path=base, upper=upper, mixed=mixed, encoded=encoded
            )
            b.add(
                b.make(
                    "bypass",
                    f"Access-control bypass ({label}) on /{base}",
                    path=path if path.startswith("/") else "/" + path,
                    follow=False,
                    matchers=(
                        Matcher(MATCH_STATUS, (200,)),
                        Matcher(MATCH_BODY_REGEX, r"(?i)(admin|dashboard|users|logout|password)"),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-284",
                    impact="A protected path is reachable through an alternative encoding.",
                    remediation="Normalise the path before the authorisation decision.",
                    tags=("bypass", label),
                )
            )
        for label, raw in P.BYPASS_HEADERS:
            name, _, value = raw.partition(": ")
            b.add(
                b.make(
                    "bypass",
                    f"Header-based access-control bypass ({label}) on /{base}",
                    path="/" + base,
                    headers=((name, value.format(path=base)),),
                    follow=False,
                    matchers=(
                        Matcher(MATCH_STATUS, (200,)),
                        Matcher(MATCH_BODY_REGEX, r"(?i)(admin|dashboard|users|logout)"),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-284",
                    impact="Trusting a client-supplied address header bypasses access control.",
                    remediation="Never derive authorisation from forwarded headers.",
                    tags=("bypass", "header"),
                )
            )


def _idor(b: _Builder) -> None:
    for template in (
        "/api/users/{id}", "/api/user/{id}", "/api/v1/users/{id}",
        "/api/accounts/{id}", "/api/orders/{id}", "/api/invoices/{id}",
        "/api/documents/{id}", "/api/files/{id}",
    ):
        for ident in ("1", "2", "3"):
            b.add(
                b.make(
                    "idor",
                    f"Object access without ownership check: {template.format(id=ident)}",
                    path=template.format(id=ident),
                    matchers=(
                        Matcher(MATCH_STATUS, (200,)),
                        Matcher(MATCH_BODY_REGEX, r"(?i)(\"?(id|email|username|name|owner|user)\"?\s*[:=])"),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-639",
                    impact="Sequential identifiers return other users' objects.",
                    remediation="Authorise every object access against the session principal.",
                    tags=("idor",),
                )
            )
    for path in ("/download?id={id}", "/file?id={id}", "/invoice?id={id}", "/order?id={id}"):
        for ident in ("1", "2"):
            b.add(
                b.make(
                    "idor",
                    f"Object access via parameter: {path.format(id=ident)}",
                    path=path.split("?")[0],
                    query=path.split("?")[1].format(id=ident),
                    matchers=(
                        Matcher(MATCH_STATUS, (200,)),
                        Matcher(MATCH_BODY_NOT_REGEX, r"(?i)(not found|unauthori[sz]ed|forbidden|denied)"),
                        Matcher(MATCH_LENGTH_GT, 20),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-639",
                    impact="Object identifiers are not bound to the session.",
                    remediation="Authorise every object access against the session principal.",
                    tags=("idor",),
                )
            )


def _cors(b: _Builder) -> None:
    for origin in (
        "https://evil.example",
        "null",
        "https://target.evil.example",
        "http://evil.example",
        "https://evil.example:443",
    ):
        b.add(
            b.make(
                "cors",
                f"CORS reflects the origin: {origin}",
                path="/",
                headers=(("Origin", origin),),
                matchers=(
                    Matcher(MATCH_HEADER_REGEX, r"^access-control-allow-origin:\s*(\*|null|https?://evil\.example|https?://target\.evil\.example)"),
                ),
                severity=Severity.HIGH if origin != "null" else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                cwe="CWE-942",
                impact="Any origin can read authenticated responses.",
                remediation="Echo only known origins and never combine a wildcard with credentials.",
                tags=("cors",),
            )
        )
    b.add(
        b.make(
            "cors",
            "CORS wildcard with credentials",
            path="/",
            headers=(("Origin", "https://evil.example"),),
            matchers=(
                Matcher(MATCH_HEADER_REGEX, r"^access-control-allow-origin:\s*\*"),
                Matcher(MATCH_HEADER_REGEX, r"^access-control-allow-credentials:\s*true"),
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            cwe="CWE-942",
            impact="The wildcard plus credentials combination exposes authenticated data.",
            remediation="Return a specific origin when credentials are allowed.",
            tags=("cors",),
        )
    )


def _jwt(b: _Builder) -> None:
    for path in (
        ".well-known/jwks.json",
        ".well-known/openid-configuration",
        ".well-known/oauth-authorization-server",
        "jwks.json",
        "api/auth/jwks",
        "oauth/token",
    ):
        b.add(
            b.make(
                "jwt",
                f"JWT/OAuth metadata exposed: /{path}",
                path="/" + path,
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, r"(?i)(\"keys\"|issuer|token_endpoint|jwks_uri|access_token)"),
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                cwe="CWE-200",
                impact="Signing key material or OAuth metadata is discoverable.",
                remediation="Publish only what clients need and pin the algorithms you accept.",
                tags=("jwt",),
            )
        )


def _graphql(b: _Builder) -> None:
    queries: tuple[tuple[str, str], ...] = (
        ("introspection", "{__schema{types{name kind fields{name}}}}"),
        ("typename", "{__typename}"),
        ("suggestions", "{usr}"),
        ("deprecated-fields", "{__schema{directives{name}}}"),
        ("mutation-surface", "{__schema{mutationType{name}}}"),
    )
    for label, query in queries:
        b.add(
            b.make(
                "graphql",
                f"GraphQL {label} enabled",
                method="POST",
                path="/graphql",
                body=f'{{"query":"{query}"}}',
                content_type="application/json",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, r"(\"data\"|\"errors\"|__schema|did you mean)"),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                cwe="CWE-200",
                impact="Introspection reveals the whole schema, including administrative mutations.",
                remediation="Disable introspection in production and bound query depth.",
                tags=("graphql", label),
            )
        )


def _smuggling(b: _Builder) -> None:
    variants: tuple[tuple[str, dict[str, str], str | None], ...] = (
        ("cl-te", {"Content-Length": "6", "Transfer-Encoding": "chunked"}, "0\r\n\r\nX"),
        ("te-cl", {"Transfer-Encoding": "chunked", "Content-Length": "6"}, "0\r\n\r\nX"),
        ("te-obfuscated-space", {"Transfer-Encoding": "chunked ", "Content-Length": "6"}, "0\r\n\r\nX"),
        ("te-obfuscated-tab", {"Transfer-Encoding": "\tchunked", "Content-Length": "6"}, "0\r\n\r\nX"),
        ("te-double", {"Transfer-Encoding": "chunked, chunked", "Content-Length": "6"}, "0\r\n\r\nX"),
        ("cl-duplicate", {"Content-Length": "6"}, "0\r\n\r\nX"),
    )
    for label, headers, body in variants:
        b.add(
            b.make(
                "smuggling",
                f"Desync surface ({label})",
                method="POST",
                path="/",
                headers=tuple(headers.items()),
                body=body,
                content_type="application/x-www-form-urlencoded",
                matchers=(
                    # Only acceptance matters: a 400 means the server rejected the
                    # ambiguous framing, which is the correct behaviour.
                    Matcher(MATCH_STATUS, (200, 201, 202, 204, 301, 302)),
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                cwe="CWE-444",
                impact="Conflicting framing headers may let a front-end and back-end disagree about request boundaries.",
                remediation="Reject ambiguous framing at the edge and normalise to HTTP/2 end to end.",
                tags=("smuggling", label),
            )
        )


def _cache(b: _Builder) -> None:
    for header, value in (
        ("X-Forwarded-Host", "evil.example"),
        ("X-Host", "evil.example"),
        ("X-Forwarded-Server", "evil.example"),
        ("X-Original-URL", "/evil.example"),
        ("X-Rewrite-URL", "/evil.example"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto", "http"),
    ):
        b.add(
            b.make(
                "cache",
                f"Unkeyed header reflected for poisoning ({header})",
                path="/",
                headers=((header, value),),
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_REGEX, r"evil\.example"),
                ),
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                cwe="CWE-525",
                impact="A response that varies on an unkeyed header can be cached and served to other users.",
                remediation="Add the header to the cache key or strip it at the edge.",
                tags=("cache", header.lower()),
            )
        )


def _misc(b: _Builder) -> None:
    for label, ctype, body in (
        ("json-to-form", "application/x-www-form-urlencoded", '{"test":"zs"}'),
        ("form-to-json", "application/json", "test=zs"),
        ("xml-body", "application/xml", '<?xml version="1.0"?><zs><test>1</test></zs>'),
        ("text-plain-script", "text/plain", "<script>alert(1)</script>"),
        ("multipart", "multipart/form-data; boundary=zs", "--zs\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\n1\r\n--zs--\r\n"),
    ):
        b.add(
            b.make(
                "misc",
                f"Content-type confusion accepted ({label})",
                method="POST",
                path="/",
                body=body,
                content_type=ctype,
                matchers=(
                    Matcher(MATCH_STATUS, (200, 201, 202, 204)),
                    Matcher(MATCH_CONTENT_TYPE, "json"),
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                cwe="CWE-436",
                impact="The endpoint parses a body type it did not advertise, widening the attack surface.",
                remediation="Reject requests whose content type is not expected.",
                tags=("content-type",),
            )
        )
    for name, raw in P.SHELLSHOCK_HEADERS:
        header, _, value = raw.partition(": ")
        b.add(
            b.make(
                "misc",
                f"Shellshock probe via {name}",
                path="/",
                headers=((header, value),),
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_CONTAINS, "zs-canary"),
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                cwe="CWE-78",
                impact="A CGI environment variable is evaluated by bash.",
                remediation="Patch bash and remove CGI entry points.",
                tags=("shellshock",),
            )
        )
    for label, query, expected in P.SSTI:
        b.add(
            b.make(
                "misc",
                f"Server-side template injection via {label}",
                path="/",
                query=f"q={query}",
                param_name="q",
                payload=query,
                control_query="q=zs-ssti-canary",
                differential="control-negative",
                matchers=(
                    Matcher(MATCH_STATUS, (200,)),
                    Matcher(MATCH_BODY_CONTAINS, expected),
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                cwe="CWE-1336",
                impact="Template expressions are evaluated server-side, which can lead to remote code execution.",
                remediation="Never render user input as a template.",
                tags=("ssti", label),
            )
        )
    for label, payload, signature in P.XXE_PAYLOADS:
        b.add(
            b.make(
                "misc",
                f"XML external entity via {label}",
                method="POST",
                path="/",
                body=payload,
                content_type="application/xml",
                matchers=(
                    Matcher(MATCH_STATUS, (200, 500)),
                    Matcher(MATCH_BODY_REGEX, signature),
                ),
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                cwe="CWE-611",
                impact="The XML parser resolves external entities, exposing local files.",
                remediation="Disable DTDs and external entity resolution.",
                tags=("xxe", label),
            )
        )
    for label, payload, kind in P.NOSQL:
        if kind == "json":
            b.add(
                b.make(
                    "misc",
                    f"NoSQL operator injection via {label}",
                    method="POST",
                    path="/",
                    body=f'{{"username":"admin","password":{payload}}}',
                    content_type="application/json",
                    matchers=(
                        Matcher(MATCH_STATUS, (200, 302)),
                        Matcher(MATCH_BODY_REGEX, r"(?i)(token|session|welcome|dashboard|success)"),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-943",
                    impact="Mongo-style operators are passed straight into the query.",
                    remediation="Cast inputs to scalars and reject object-shaped values.",
                    tags=("nosql", label),
                )
            )
        else:
            b.add(
                b.make(
                    "misc",
                    f"NoSQL parameter injection via {label}",
                    method="POST",
                    path="/",
                    body=payload,
                    content_type="application/x-www-form-urlencoded",
                    matchers=(
                        Matcher(MATCH_STATUS, (200, 302)),
                        Matcher(MATCH_BODY_REGEX, r"(?i)(token|session|welcome|dashboard|success)"),
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    cwe="CWE-943",
                    impact="Array-shaped parameters reach the query engine as operators.",
                    remediation="Reject array parameters where scalars are expected.",
                    tags=("nosql", label),
                )
            )


def re_escape(text: str) -> str:
    import re

    return re.escape(text)


def build_probes(profile: str = "normal") -> list[Probe]:
    """Return the full catalogue, ordered by section.

    ``profile`` narrows the catalogue: ``stealth`` keeps one payload per family,
    ``normal`` is the full set, ``aggressive`` adds nothing today but is accepted
    so the CLI contract is stable.
    """
    builder = _Builder()
    _recon(builder)
    _banner(builder)
    _methods(builder)
    _headers(builder)
    _files(builder)
    _links(builder)
    _xss(builder)
    _sqli(builder)
    _lfi(builder)
    _ssrf(builder)
    _redirect(builder)
    _cmdi(builder)
    _host(builder)
    _bypass(builder)
    _idor(builder)
    _cors(builder)
    _jwt(builder)
    _graphql(builder)
    _smuggling(builder)
    _cache(builder)
    _misc(builder)

    probes = builder.build()
    if profile == "stealth":
        seen: set[tuple[str, str]] = set()
        narrowed: list[Probe] = []
        for probe in probes:
            key = (probe.section, probe.tags[0] if probe.tags else probe.id)
            if probe.section in PARAMETRIC_SECTIONS and key in seen:
                continue
            seen.add(key)
            narrowed.append(probe)
        probes = narrowed
    return probes


def section_counts(probes: list[Probe]) -> dict[str, int]:
    counts: dict[str, int] = {name: 0 for name in SECTION_ORDER}
    for probe in probes:
        counts[probe.section] = counts.get(probe.section, 0) + 1
    return {name: count for name, count in counts.items() if count}


CATALOGUE: list[Probe] = build_probes()
PROBE_COUNT: int = len(CATALOGUE)
