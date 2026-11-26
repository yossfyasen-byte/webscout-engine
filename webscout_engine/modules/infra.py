"""Module 3 - Infrastructure reconnaissance.

Three stages: TCP service discovery, DNS / network metadata, and technology
fingerprinting. Service scanning is limited to addresses the target host actually
resolves to and that pass the scope policy.
"""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlsplit

from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity
from ..recon.dns import DnsEnumerator, DnsResult
from ..recon.dns import PORT_PROFILES, PortResult, resolve_ports, scan_ports
from ..recon.tech import TechFingerprinter
from ..recon.tech import inspect_tls
from .base import BaseModule, ModuleOutcome

# Ports a CDN/WAF edge commonly accepts. A successful connect to one of these on
# a provider address says nothing about the origin server.
CDN_PROXIED_PORTS = {80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443}

# port -> (service label, severity of the exposure, why it matters)
RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    21: ("FTP", Severity.MEDIUM, "Cleartext file transfer with often weak credentials."),
    23: ("Telnet", Severity.HIGH, "Unencrypted remote shell."),
    445: ("SMB", Severity.HIGH, "File sharing exposed beyond the local network."),
    1433: ("Microsoft SQL Server", Severity.HIGH, "Database reachable from the internet."),
    3306: ("MySQL", Severity.HIGH, "Database reachable from the internet."),
    3389: ("RDP", Severity.HIGH, "Remote desktop exposed to credential attacks."),
    5432: ("PostgreSQL", Severity.HIGH, "Database reachable from the internet."),
    5900: ("VNC", Severity.HIGH, "Remote desktop often configured without a password."),
    6379: ("Redis", Severity.CRITICAL, "Redis has no authentication by default and allows arbitrary writes."),
    9200: ("Elasticsearch", Severity.CRITICAL, "Unprotected search index with full document access."),
    11211: ("Memcached", Severity.HIGH, "Unauthenticated cache usable for amplification."),
    2375: ("Docker API", Severity.CRITICAL, "Unauthenticated container control equals host compromise."),
    2376: ("Docker API (TLS)", Severity.HIGH, "Container control plane reachable from the internet."),
    27017: ("MongoDB", Severity.CRITICAL, "Database frequently deployed without authentication."),
    15672: ("RabbitMQ management", Severity.MEDIUM, "Broker management UI with default credentials."),
    5601: ("Kibana", Severity.MEDIUM, "Analytics UI exposing indexed data."),
    6443: ("Kubernetes API", Severity.HIGH, "Cluster control plane exposed."),
    8080: ("HTTP alternate", Severity.LOW, "Secondary HTTP service, often a management console."),
    8443: ("HTTPS alternate", Severity.LOW, "Secondary HTTPS service."),
    22: ("SSH", Severity.INFO, "Expected administrative access point; confirm it is restricted."),
}

SENSITIVE_HEADERS = (
    "x-backend-server",
    "x-served-by",
    "x-cache",
    "via",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-debug-token",
    "x-runtime",
)


class InfraReconModule(BaseModule):
    name = "infra"
    title = "Infrastructure Reconnaissance"
    description = "Port discovery, DNS metadata and evidence-based technology fingerprinting."

    def __init__(self, ctx=None) -> None:
        super().__init__(ctx)
        self._cdn_vendors: list[str] = []

    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        # Technology first: whether a CDN/WAF sits in front changes how the port
        # results must be interpreted, so it has to be known before ports run.
        await self._stage_technology(ctx, outcome)
        await self._stage_ports(ctx, outcome)
        await self._stage_dns(ctx, outcome)
        return outcome

    # ------------------------------------------------------------------ ports
    async def _stage_ports(self, ctx, outcome: ModuleOutcome) -> None:
        host = urlsplit(ctx.base_url).hostname or ""
        if not host:
            return
        ctx.state.set_stage("ports")
        await ctx.emit(EventType.STAGE, "Infrastructure: TCP service discovery")

        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            addresses = await ctx.scope.resolve(host, 443)
        if not addresses:
            outcome.notes.append(f"Could not resolve {host}; port discovery skipped.")
            return

        allowed: list[str] = []
        for address in addresses:
            decision = ctx.scope.check_ip(address)
            if decision.allowed:
                allowed.append(address)
            else:
                outcome.notes.append(f"Address {address} not scanned: {decision.reason}")
        if not allowed:
            return

        ports = resolve_ports(ctx.options.ports or "top100")
        ctx.add_total(len(ports))
        await ctx.emit(
            EventType.OPERATION,
            f"Scanning {len(ports)} TCP ports on {allowed[0]}",
            {"ports": len(ports), "address": allowed[0]},
        )

        def on_progress(result: PortResult) -> None:
            ctx.progress(failed=result.state == "error")

        results = await scan_ports(
            allowed[0],
            ports,
            concurrency=max(20, min(200, ctx.options.threads * 5)),
            timeout=min(3.0, max(0.5, ctx.options.timeout / 3)),
            cancel=ctx.cancel,
            on_progress=on_progress,
        )
        ctx.port_results = results

        cdn_vendors = getattr(self, "_cdn_vendors", [])
        cdn_edge_ports: list[int] = []
        open_ports = [r for r in results if r.state == "open"]
        for result in open_ports:
            risk = RISKY_PORTS.get(result.port)
            service = result.service or (risk[0] if risk else "unknown")
            at_cdn_edge = bool(cdn_vendors) and result.port in CDN_PROXIED_PORTS
            detail = (
                f"{service}"
                + (f" banner: {result.banner}" if result.banner else "")
                + f" ({result.latency_ms} ms)"
            )
            if at_cdn_edge:
                cdn_edge_ports.append(result.port)
                detail += (
                    f" [CDN edge: {cdn_vendors[0]} - this describes the provider's edge,"
                    " not the origin server]"
                )
            outcome.observe(
                Observation(
                    kind="port",
                    target=allowed[0],
                    label=str(result.port),
                    status="open",
                    detail=detail,
                    severity=Severity.INFO if at_cdn_edge else (risk[1] if risk else Severity.INFO),
                    metadata={
                        "module": self.name,
                        "service": service,
                        "tls": result.tls,
                        "latency_ms": result.latency_ms,
                        "cdn_edge": at_cdn_edge,
                    },
                )
            )
            if risk and not at_cdn_edge:
                outcome.add(
                    self.finding(
                        title=f"{risk[0]} service exposed on port {result.port}",
                        severity=risk[1],
                        confidence=Confidence.HIGH,
                        module=self.name,
                        check="exposed-service",
                        endpoint=f"{host}:{result.port}",
                        status_code=None,
                        evidence=(
                            f"TCP connect to {allowed[0]}:{result.port} succeeded"
                            + (f"; banner: {result.banner}" if result.banner else "")
                        ),
                        impact=risk[2],
                        remediation=(
                            "Restrict the port to trusted networks with a firewall or security group, "
                            "require strong authentication and keep the service patched."
                        ),
                        references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                        cwe="CWE-668",
                    )
                )

        outcome.notes.append(
            f"{len(open_ports)} of {len(ports)} ports open on {allowed[0]} "
            f"(profiles available: {', '.join(sorted(PORT_PROFILES))})."
        )
        if cdn_edge_ports:
            outcome.notes.append(
                f"{allowed[0]} belongs to {cdn_vendors[0]}: ports "
                f"{', '.join(str(port) for port in sorted(cdn_edge_ports))} were accepted by the "
                "CDN edge, so they are recorded as observations rather than exposed services."
            )

    # -------------------------------------------------------------------- dns
    async def _stage_dns(self, ctx, outcome: ModuleOutcome) -> None:
        host = urlsplit(ctx.base_url).hostname or ""
        try:
            ipaddress.ip_address(host)
            outcome.notes.append("Target is an IP address; DNS enumeration skipped.")
            return
        except ValueError:
            pass

        ctx.state.set_stage("dns")
        await ctx.emit(EventType.STAGE, "Infrastructure: DNS and network metadata")
        ctx.add_total(1)
        try:
            result: DnsResult = await asyncio.wait_for(
                DnsEnumerator(timeout=4.0).enumerate(host), timeout=20.0
            )
        except TimeoutError:
            outcome.notes.append("DNS enumeration timed out after 20s; records were skipped.")
            ctx.progress(failed=True)
            return
        except Exception as exc:
            outcome.notes.append(f"DNS enumeration unavailable: {type(exc).__name__}: {exc}")
            ctx.progress(failed=True)
            return
        finally:
            ctx.progress()

        ctx.dns_result = result
        outcome.notes.extend(result.notes)
        for record_type, value in result.flattened():
            outcome.observe(
                Observation(
                    kind="dns",
                    target=host,
                    label=record_type,
                    status="record",
                    detail=value[:300],
                    metadata={"module": self.name, "record_type": record_type},
                )
            )

        if not result.has_records:
            errors = ", ".join(f"{k}: {v[:40]}" for k, v in list(result.errors.items())[:3])
            outcome.notes.append(f"No DNS records retrieved ({errors or 'no response'}).")
            return

        if "CAA" not in result.records:
            outcome.add(
                self.finding(
                    title="No CAA record restricts certificate issuance",
                    severity=Severity.INFO,
                    confidence=Confidence.CERTAIN,
                    module=self.name,
                    check="dns-caa-missing",
                    endpoint=host,
                    evidence="No CAA RRset returned for the apex domain.",
                    impact="Any public CA may issue a certificate for this name, which weakens brand protection.",
                    remediation="Publish a CAA record naming your certificate authority.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                    cwe="CWE-16",
                )
            )

        for txt in result.records.get("TXT", []):
            lowered = txt.lower()
            if lowered.startswith("v=spf1") and "+all" in lowered:
                outcome.add(
                    self.finding(
                        title="SPF record permits any sender (+all)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        module=self.name,
                        check="dns-spf-permissive",
                        endpoint=host,
                        evidence=f"TXT: {txt[:200]}",
                        impact="Attackers can send mail that appears to originate from this domain.",
                        remediation="Replace +all with -all or ~all and list only authorised senders.",
                        references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                        cwe="CWE-290",
                    )
                )

        private_addresses = [
            address
            for address in result.records.get("A", []) + result.records.get("AAAA", [])
            if _is_private(address)
        ]
        if private_addresses:
            outcome.observe(
                Observation(
                    kind="dns",
                    target=host,
                    label="private-address",
                    status="observed",
                    detail=f"Public DNS name resolves to private address(es): {', '.join(private_addresses)}",
                    severity=Severity.INFO,
                    metadata={"module": self.name},
                )
            )

        await self._header_disclosures(ctx, outcome)

    async def _header_disclosures(self, ctx, outcome: ModuleOutcome) -> None:
        response = await ctx.http.head(ctx.base_url, allow_redirects=True, retries=0)
        if response.error:
            return
        for header in SENSITIVE_HEADERS:
            value = response.header(header)
            if not value:
                continue
            outcome.observe(
                Observation(
                    kind="header",
                    target=ctx.base_url,
                    label=header,
                    status="disclosed",
                    detail=value[:200],
                    metadata={"module": self.name},
                )
            )

    # ------------------------------------------------------------- technology
    async def _stage_technology(self, ctx, outcome: ModuleOutcome) -> None:
        ctx.state.set_stage("technology")
        await ctx.emit(EventType.STAGE, "Infrastructure: technology fingerprinting")
        ctx.add_total(2)

        response = await ctx.http.get(ctx.base_url, allow_redirects=True)
        ctx.progress(failed=bool(response.error))
        if response.error:
            outcome.notes.append(f"Technology fingerprinting skipped: {response.error}")
            return

        fingerprinter = TechFingerprinter.from_data()
        cookies = _cookie_names(response.headers.get("set-cookie", ""))
        matches = fingerprinter.analyse(
            response.headers,
            response.body,
            cookies=cookies,
            server=response.header("server"),
        )
        ctx.tech_matches = matches
        for match in matches:
            outcome.observe(
                Observation(
                    kind="technology",
                    target=ctx.base_url,
                    label=match.name,
                    status=match.category,
                    detail=(f"version {match.version}; " if match.version else "") + match.evidence,
                    metadata={
                        "module": self.name,
                        "category": match.category,
                        "version": match.version,
                        "confidence": match.confidence.value,
                    },
                )
            )

        self._cdn_vendors = fingerprinter.detect_cdn_waf(response.headers, cookies)
        for vendor in self._cdn_vendors:
            outcome.observe(
                Observation(
                    kind="technology",
                    target=ctx.base_url,
                    label="CDN / WAF",
                    status="detected",
                    detail=vendor,
                    metadata={"module": self.name, "category": "cdn-waf"},
                )
            )

        parts = urlsplit(ctx.base_url)
        if parts.scheme == "https":
            tls_info = await inspect_tls(parts.hostname or "", parts.port or 443, timeout=6.0)
            ctx.tls_info = tls_info
            if tls_info.enabled:
                outcome.observe(
                    Observation(
                        kind="technology",
                        target=ctx.base_url,
                        label="TLS",
                        status="negotiated",
                        detail=(
                            f"{tls_info.version} / {tls_info.cipher}; subject={tls_info.subject or 'n/a'}; "
                            f"issuer={tls_info.issuer or 'n/a'}; expires in {tls_info.days_remaining} day(s)"
                        ),
                        metadata={"module": self.name, "category": "tls"},
                    )
                )
        ctx.progress()

        for hint in fingerprinter.correlate_cves(matches):
            severity = _severity_from(hint.severity)
            outcome.add(
                self.finding(
                    title=f"Potential exposure: {hint.technology} {hint.version} matches {hint.cve_id}",
                    severity=severity,
                    confidence=Confidence.LOW,
                    module=self.name,
                    check="cve-correlation",
                    endpoint=ctx.base_url,
                    evidence=(
                        f"Version {hint.version} was fingerprinted and the local CVE map lists "
                        f"{hint.cve_id} for versions {hint.affected}. The version banner is "
                        f"self-reported and has not been verified against the binary."
                    ),
                    impact=hint.summary,
                    remediation=(
                        "Confirm the exact installed version, review the advisory and upgrade. "
                        "This is a version-based correlation, not a confirmed vulnerability."
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{hint.cve_id}"],
                    cwe="CWE-1104",
                )
            )

        if not matches:
            outcome.notes.append("No technology fingerprints matched the configured rules.")

    # ---------------------------------------------------------------- helpers


def _is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _cookie_names(raw: str) -> dict[str, str]:
    names: dict[str, str] = {}
    for line in raw.split("\n"):
        if "=" in line:
            name = line.split("=", 1)[0].strip()
            if name:
                names[name] = ""
    return names


def _severity_from(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM
