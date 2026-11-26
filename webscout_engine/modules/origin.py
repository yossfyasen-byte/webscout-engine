"""Origin (real IP) discovery behind a CDN or WAF.

When a target is fronted by Cloudflare and friends, every web check sees the
provider's edge, not the application. This module tries to find the address that
actually serves the application, using passive techniques first:

1. resolve the apex and check whether the answers belong to a known CDN;
2. harvest candidate hostnames from the certificate SAN list, MX records, SPF
   includes and a short list of common origin-style prefixes;
3. resolve each candidate (DNS only - no HTTP unless ``--osint`` is set);
4. classify every address as edge or non-edge;
5. with ``--osint``, request the candidate with the target's ``Host`` header and
   compare a fingerprint against the edge response.

Only DNS is queried by default, and HTTP is only sent to hosts that pass the
scope policy. Nothing here bypasses authorisation: use it on infrastructure you
own or are contracted to test.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..core.events import EventType
from ..core.models import Confidence, Observation, Severity
from ..recon.dns import DnsEnumerator, DnsResult
from .base import BaseModule, ModuleOutcome

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Common names that point at an origin rather than the edge.
ORIGIN_PREFIXES = (
    "direct", "origin", "origin-www", "www2", "backend", "web", "web1", "node1",
    "app", "api", "admin", "portal", "dev", "staging", "test", "uat", "beta",
    "ftp", "mail", "smtp", "webmail", "cpanel", "server", "host", "vpn",
)


@dataclass(slots=True)
class OriginCandidate:
    host: str
    addresses: list[str] = field(default_factory=list)
    source: str = ""
    edge: bool = False
    provider: str = ""
    matches_edge: bool = False
    detail: str = ""


def load_subdomain_names(path: Path | None = None) -> list[str]:
    source = path or (DATA_DIR / "subdomains.txt")
    if not source.exists():
        return list(ORIGIN_PREFIXES)
    names: dict[str, None] = {}
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#"):
            names.setdefault(clean, None)
    return list(names) or list(ORIGIN_PREFIXES)


def load_cdn_ranges(path: Path | None = None) -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    source = path or (DATA_DIR / "cdn_ranges.json")
    ranges: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    if not source.exists():
        return ranges
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return ranges
    for provider, block in (payload.get("providers") or {}).items():
        for cidr in list(block.get("ipv4", [])) + list(block.get("ipv6", [])):
            try:
                ranges.append((provider, ipaddress.ip_network(cidr, strict=False)))
            except ValueError:
                continue
    return ranges


def classify_address(
    address: str, ranges: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]
) -> str:
    """Return the CDN provider that owns ``address``, or an empty string."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return ""
    for provider, network in ranges:
        if ip.version == network.version and ip in network:
            return provider
    return ""


def _fingerprint(body: str, headers: dict[str, str]) -> str:
    material = "|".join(
        [
            headers.get("server", ""),
            headers.get("x-powered-by", ""),
            str(len(body or "")),
            hashlib.sha1(" ".join((body or "").split())[:2000].encode("utf-8", "replace")).hexdigest(),
        ]
    )
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]


class OriginDiscoveryModule(BaseModule):
    name = "origin"
    title = "Origin IP Discovery"
    description = "Finds the address behind a CDN using DNS, certificates and a short host list."

    def __init__(self, ctx=None, resolver=None) -> None:
        super().__init__(ctx)
        self._resolver = resolver

    # ------------------------------------------------------------- candidates
    def _candidate_hosts(self, host: str, dns: DnsResult | None, san: list[str]) -> dict[str, str]:
        """host -> where the candidate came from."""
        candidates: dict[str, str] = {}
        for name in san:
            clean = name.strip().lower().lstrip("*.")
            if clean and clean.endswith(host) and clean != host:
                candidates.setdefault(clean, "certificate SAN")
        if dns is not None:
            for record_type in ("MX", "CNAME"):
                for value in dns.records.get(record_type, []):
                    name = value.split()[-1].strip(".").lower()
                    if name and name.endswith(host) and name != host:
                        candidates.setdefault(name, f"{record_type} record")
            for txt in dns.records.get("TXT", []):
                for token in txt.split():
                    lowered = token.lower()
                    if lowered.startswith(("include:", "a:", "ip4:")):
                        value = token.split(":", 1)[1].strip(".")
                        if value.endswith(host) and value != host:
                            candidates.setdefault(value, "SPF record")
        for prefix in load_subdomain_names():
            candidates.setdefault(f"{prefix}.{host}", "common subdomain prefix")
        return candidates

    # ------------------------------------------------------------------- run
    async def run(self, ctx) -> ModuleOutcome:
        outcome = self.new_outcome(ctx)
        host = (urlsplit(ctx.base_url).hostname or "").lower()
        try:
            ipaddress.ip_address(host)
            ctx.skip_module(self.name, "target is an IP address, there is no hostname to resolve")
            return outcome
        except ValueError:
            pass

        ctx.state.set_stage("origin discovery")
        await ctx.emit(EventType.STAGE, "Origin discovery: resolving edge and candidate hosts")
        ranges = load_cdn_ranges()
        enumerator = DnsEnumerator(timeout=3.0, resolver=self._resolver)

        ctx.add_total(2)
        try:
            apex = await enumerator.enumerate(host)
        except Exception:
            apex = DnsResult(domain=host)
        ctx.progress()

        apex_addresses = apex.records.get("A", []) + apex.records.get("AAAA", [])
        providers = sorted({classify_address(address, ranges) for address in apex_addresses} - {""})
        behind_cdn = bool(providers)

        for address in apex_addresses:
            provider = classify_address(address, ranges)
            outcome.observe(
                Observation(
                    kind="origin",
                    target=host,
                    label=address,
                    status="edge" if provider else "direct",
                    detail=f"{provider or 'not a known CDN range'}",
                    metadata={"module": self.name, "provider": provider},
                )
            )

        if not behind_cdn:
            outcome.notes.append(
                f"{host} resolves to {', '.join(apex_addresses) or 'nothing'}, which is not a known "
                "CDN range; the address is already the origin."
            )
            ctx.progress()
            return outcome

        san = list(ctx.tls_info.san) if ctx.tls_info is not None else []
        candidates = self._candidate_hosts(host, apex, san)
        ctx.add_total(len(candidates))
        await ctx.emit(
            EventType.OPERATION,
            f"{host} is behind {', '.join(providers)}; resolving {len(candidates)} candidate host(s)",
            {"candidates": len(candidates)},
        )

        semaphore = asyncio.Semaphore(max(4, min(20, ctx.options.threads)))

        async def resolve_candidate(name: str, source: str) -> OriginCandidate | None:
            async with semaphore:
                try:
                    addresses = await ctx.scope.resolve(name, 443)
                except Exception:
                    addresses = []
                finally:
                    ctx.progress()
                if not addresses:
                    return None
                candidate = OriginCandidate(host=name, addresses=addresses, source=source)
                non_edge = [a for a in addresses if not classify_address(a, ranges)]
                candidate.edge = not non_edge
                candidate.provider = classify_address(addresses[0], ranges)
                return candidate

        results = await asyncio.gather(
            *(resolve_candidate(name, source) for name, source in candidates.items())
        )
        resolved = [candidate for candidate in results if candidate is not None]
        direct = [candidate for candidate in resolved if not candidate.edge]

        edge_fingerprint = ""
        if ctx.options.osint:
            edge_fingerprint = await self._fingerprint_edge(ctx)
            for candidate in direct[:5]:
                await self._probe_candidate(ctx, candidate, host, edge_fingerprint)

        for candidate in resolved:
            outcome.observe(
                Observation(
                    kind="origin",
                    target=host,
                    label=candidate.host,
                    status="edge" if candidate.edge else "non-edge",
                    detail=(
                        f"{', '.join(candidate.addresses[:3])}"
                        + (f" ({candidate.provider})" if candidate.edge else " - not a known CDN range")
                        + f" | source: {candidate.source}"
                        + (f" | {candidate.detail}" if candidate.detail else "")
                    ),
                    severity=Severity.INFO,
                    metadata={"module": self.name, "source": candidate.source},
                )
            )

        for candidate in direct:
            confirmed = candidate.matches_edge
            outcome.add(
                self.finding(
                    title=(
                        f"Origin address confirmed behind {', '.join(providers)}: {candidate.host}"
                        if confirmed
                        else f"Candidate origin address outside {', '.join(providers)}: {candidate.host}"
                    ),
                    severity=Severity.HIGH if confirmed else Severity.INFO,
                    confidence=Confidence.HIGH if confirmed else Confidence.LOW,
                    module=self.name,
                    check="origin-ip",
                    endpoint=f"{candidate.host} ({', '.join(candidate.addresses[:3])})",
                    evidence=(
                        f"Resolved from {candidate.source}. "
                        + (
                            "The host answered with the same fingerprint as the edge, so it is "
                            "almost certainly the application origin."
                            if confirmed
                            else "The address is not in a published CDN range. Confirm manually "
                            "that it serves the same application before treating it as the origin."
                        )
                    ),
                    impact=(
                        "An exposed origin bypasses the CDN/WAF entirely: rate limits, bot rules "
                        "and DDoS protection no longer apply, and firewall rules that trust the "
                        "CDN can be spoofed."
                    ),
                    remediation=(
                        "Restrict the origin firewall to the CDN's published ranges, require a "
                        "shared secret header from the CDN, and keep internal hostnames out of "
                        "public DNS."
                    ),
                    references=["https://developers.cloudflare.com/fundamentals/concepts/restrict-origin-access/"],
                    cwe="CWE-668",
                )
            )

        outcome.notes.append(
            f"{host} is served by {', '.join(providers)}; {len(resolved)} candidate host(s) resolved, "
            f"{len(direct)} outside the CDN ranges"
            + (" (fingerprint comparison enabled)" if ctx.options.osint else
               ". Re-run with --osint to compare fingerprints against the edge")
            + "."
        )
        if not direct:
            ctx.note(
                "origin discovery: every candidate still resolves into a CDN range, so no origin "
                "address was exposed by DNS"
            )
        ctx.progress()
        return outcome

    # ---------------------------------------------------------------- probing
    async def _fingerprint_edge(self, ctx) -> str:
        response = await ctx.http.get(ctx.base_url, allow_redirects=True, retries=0)
        if response.error:
            return ""
        return _fingerprint(response.body, response.headers)

    async def _probe_candidate(self, ctx, candidate: OriginCandidate, host: str, edge: str) -> None:
        """Request the candidate with the target's Host header and compare."""
        for address in candidate.addresses[:2]:
            decision = ctx.scope.check_ip(address)
            if not decision.allowed:
                candidate.detail = f"not probed: {decision.reason}"
                return
            scheme = "https" if urlsplit(ctx.base_url).scheme == "https" else "http"
            url = f"{scheme}://{address}/"
            try:
                response = await ctx.http.get(
                    url, headers={"Host": host}, allow_redirects=False, retries=0
                )
            except Exception:
                continue
            if response.error or not response.status:
                continue
            local = _fingerprint(response.body, response.headers)
            candidate.matches_edge = bool(edge) and local == edge
            candidate.detail = (
                "fingerprint matches the edge" if candidate.matches_edge else "fingerprint differs"
            )
            return
