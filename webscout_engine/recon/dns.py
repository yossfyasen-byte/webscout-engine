"""DNS resolution and TCP port discovery."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
import contextlib
import time
from dataclasses import dataclass
from ..core.net import CancellationToken


# -------------------------------------------------------------------------
# from dns.py
# -------------------------------------------------------------------------

RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA")


class DnsUnavailable(Exception):
    """No usable resolver configuration exists on this host."""


class ResolverLike(Protocol):
    async def resolve(self, name: str, rdtype: str) -> Any: ...


@dataclass(slots=True)
class DnsResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def flattened(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for rtype in RECORD_TYPES:
            for value in self.records.get(rtype, []):
                pairs.append((rtype, value))
        return pairs

    @property
    def has_records(self) -> bool:
        return any(self.records.values())


def _format(rtype: str, rdata: Any) -> str:
    """Turn a dnspython rdata object (or a plain string) into report text."""
    if isinstance(rdata, str):
        return rdata
    if rtype in ("A", "AAAA"):
        return str(getattr(rdata, "address", rdata))
    if rtype in ("CNAME", "NS", "PTR"):
        return str(getattr(rdata, "target", rdata)).rstrip(".")
    if rtype == "MX":
        preference = getattr(rdata, "preference", "")
        exchange = str(getattr(rdata, "exchange", "")).rstrip(".")
        return f"{preference} {exchange}".strip()
    if rtype == "TXT":
        chunks = getattr(rdata, "strings", None)
        if chunks:
            return "".join(
                chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
                for chunk in chunks
            )
        return str(rdata)
    if rtype == "SOA":
        return (
            f"mname={getattr(rdata, 'mname', '')} rname={getattr(rdata, 'rname', '')} "
            f"serial={getattr(rdata, 'serial', '')}"
        )
    if rtype == "CAA":
        return f"flags={getattr(rdata, 'flags', '')} {getattr(rdata, 'tag', '')} {getattr(rdata, 'value', '')}"
    return str(rdata)


class DnsEnumerator:
    def __init__(self, timeout: float = 5.0, resolver: ResolverLike | None = None) -> None:
        self.timeout = timeout
        self._resolver = resolver

    def _build_resolver(self) -> ResolverLike:
        if self._resolver is not None:
            return self._resolver
        import dns.asyncresolver  # imported lazily so the tool runs without DNS deps

        try:
            resolver = dns.asyncresolver.Resolver()
        except Exception:
            # Termux/Android and minimal containers have no resolv.conf.
            servers = discover_nameservers()
            if not servers:
                raise DnsUnavailable(
                    "no resolver configuration and no nameserver could be discovered "
                    "(set webscout_engine_DNS=1.1.1.1 to supply one)"
                ) from None
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = servers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        self._resolver = resolver
        return resolver

    @staticmethod
    async def _system_addresses(domain: str) -> list[str]:
        """A/AAAA through the operating system resolver (works on Android)."""
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, type=socket.SOCK_STREAM), timeout=3.0
            )
        except (TimeoutError, OSError):
            return []
        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        return addresses

    async def query(self, name: str, rtype: str) -> list[str]:
        resolver = self._build_resolver()
        try:
            answer = await resolver.resolve(name, rtype)
        except Exception as exc:  # NXDOMAIN, NoAnswer, Timeout, no network...
            raise DnsLookupError(rtype, str(exc)) from exc
        values: list[str] = []
        for rdata in answer:  # type: ignore[union-attr]
            values.append(_format(rtype, rdata))
        return values

    async def enumerate(self, domain: str) -> DnsResult:
        result = DnsResult(domain=domain)
        try:
            self._build_resolver()
        except DnsUnavailable as exc:
            addresses = await self._system_addresses(domain)
            if not addresses:
                result.errors["A"] = str(exc)
                result.notes.append(f"DNS enumeration unavailable: {exc}")
                return result
            ipv4 = [address for address in addresses if ":" not in address]
            ipv6 = [address for address in addresses if ":" in address]
            if ipv4:
                result.records["A"] = ipv4
            if ipv6:
                result.records["AAAA"] = ipv6
            result.notes.append(
                "Resolved through the system resolver: only A/AAAA are available on this "
                "host, so CNAME, MX, TXT, NS, SOA and CAA were not checked."
            )
            return result

        transport_failed = False
        for rtype in RECORD_TYPES:
            try:
                values = await self.query(domain, rtype)
            except DnsLookupError as exc:
                result.errors[rtype] = exc.detail
                if _is_transport_error(exc.detail):
                    # The resolver is unreachable (blocked port 53, no route):
                    # stop early instead of waiting out every record type.
                    transport_failed = True
                    break
                continue
            if values:
                result.records[rtype] = values

        if transport_failed:
            addresses = await self._system_addresses(domain)
            if addresses:
                ipv4 = [address for address in addresses if ":" not in address]
                ipv6 = [address for address in addresses if ":" in address]
                if ipv4:
                    result.records["A"] = ipv4
                if ipv6:
                    result.records["AAAA"] = ipv6
                result.notes.append(
                    "DNS resolver unreachable; fell back to the system resolver, so only "
                    "A/AAAA are available (CNAME, MX, TXT, NS, SOA and CAA were not checked)."
                )
            else:
                result.notes.append(
                    "DNS resolver unreachable and the system resolver returned no addresses."
                )
        return result


class DnsLookupError(Exception):
    def __init__(self, rtype: str, detail: str) -> None:
        super().__init__(f"{rtype}: {detail}")
        self.rtype = rtype
        self.detail = detail


def discover_nameservers() -> list[str]:
    """Best-effort nameserver discovery for hosts without resolv.conf."""
    candidates: list[str] = []

    env = os.environ.get("webscout_engine_DNS", "")
    candidates.extend(item.strip() for item in env.split(",") if item.strip())

    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                candidates.append(parts[1])
    except OSError:
        pass

    if not candidates:
        import subprocess

        for prop in ("net.dns1", "net.dns2", "net.dns3", "net.dns4"):
            try:
                completed = subprocess.run(  # noqa: S603 - fixed argv, read-only property
                    ["getprop", prop], capture_output=True, text=True, timeout=2.0, check=False
                )
            except (OSError, subprocess.SubprocessError):
                break
            value = completed.stdout.strip()
            if value:
                candidates.append(value)

    servers: list[str] = []
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            continue
        if candidate not in servers:
            servers.append(candidate)
    return servers


_TRANSPORT_MARKERS = (
    "timed out",
    "timeout",
    "no nameservers",
    "connection refused",
    "network is unreachable",
    "temporary failure",
    "all nameservers failed",
)


def _is_transport_error(detail: str) -> bool:
    """True when the failure is about reaching the resolver, not the name."""
    lowered = detail.lower()
    return any(marker in lowered for marker in _TRANSPORT_MARKERS)


# -------------------------------------------------------------------------
# from ports.py
# -------------------------------------------------------------------------

# Port profiles. "top100" is a curated subset of the most frequently exposed
# services; nothing here implies exploitation - we only connect and read.
PORT_PROFILES: dict[str, list[int]] = {
    "web": [80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443],
    "db": [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
    "remote": [22, 23, 3389, 5900, 5985, 5986],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "top100": [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 179, 389,
        443, 445, 465, 512, 513, 514, 515, 548, 554, 587, 623, 631, 636, 646, 873,
        990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1433, 1434, 1521,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2222, 2375, 2376, 2483,
        2484, 3000, 3128, 3268, 3306, 3389, 4000, 4242, 4444, 4567, 4848, 5000,
        5001, 5060, 5061, 5222, 5353, 5432, 5555, 5601, 5631, 5666, 5672, 5800,
        5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7002, 7070,
        8000, 8008, 8009, 8010, 8080, 8081, 8086, 8088, 8090, 8123, 8161, 8181,
        8200, 8443, 8500, 8529, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9100,
        9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672, 27017, 27018,
        28017, 50000, 50070, 61616,
    ],
    "top20": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389,
              5432, 5900, 6379, 8080, 8443, 27017],
}

SERVICE_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgres",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 8000: "http-alt", 8080: "http-alt", 8081: "http-alt",
    8086: "influxdb", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9042: "cassandra", 9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9443: "https-alt", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 50070: "hdfs-namenode",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 2376, 5986}

# A single benign probe used only to elicit a banner from HTTP-like services.
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: webscout_engine/1.0\r\n\r\n"

BANNER_SIGNATURES: list[tuple[str, str]] = [
    ("SSH-", "ssh"),
    ("HTTP/", "http"),
    ("220 ", "ftp"),
    ("+OK", "pop3"),
    ("* OK", "imap"),
    ("RFB ", "vnc"),
    ("-ERR", "unknown"),
    ("AMQP", "amqp"),
    ("MongoDB", "mongodb"),
    ("$", "unknown"),
]


@dataclass(slots=True)
class PortResult:
    port: int
    state: str  # open | closed | filtered | error
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0
    error: str = ""
    tls: bool = False


def resolve_ports(spec: str | None) -> list[int]:
    """Parse ``top100``, ``web``, ``22,80,443`` or ``1-1024`` into a port list."""
    if not spec:
        return list(PORT_PROFILES["top100"])
    text = str(spec).strip().lower()
    if text in PORT_PROFILES:
        return sorted(set(PORT_PROFILES[text]))
    ports: set[int] = set()
    for chunk in text.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start, end = chunk.split("-", 1)
                low, high = int(start), int(end)
            except ValueError:
                continue
            if low <= high and high - low <= 65535:
                ports.update(range(max(1, low), min(65535, high) + 1))
        else:
            try:
                value = int(chunk)
            except ValueError:
                continue
            if 0 < value < 65536:
                ports.add(value)
    return sorted(ports)


def _identify(banner: str) -> str:
    upper = banner.upper()
    for signature, service in BANNER_SIGNATURES:
        if upper.startswith(signature.upper()):
            return service
    if "server:" in banner.lower() or "http/" in banner.lower():
        return "http"
    return ""


async def probe_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    grab_banner: bool = True,
) -> PortResult:
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        latency = (time.perf_counter() - started) * 1000
        result = PortResult(
            port=port,
            state="open",
            service=SERVICE_HINTS.get(port, ""),
            latency_ms=round(latency, 1),
            tls=port in TLS_PORTS,
        )
        if grab_banner and writer is not None:
            try:
                writer.write(_HTTP_PROBE if port in (80, 8000, 8080, 8888, 3000, 5000) else b"\r\n")
                await writer.drain()
            except (OSError, ConnectionError):
                pass
            try:
                raw = await asyncio.wait_for(reader.read(256), timeout=min(1.5, timeout))
            except (TimeoutError, OSError):
                raw = b""
            if raw:
                banner = raw.decode("utf-8", "replace")
                result.banner = " ".join(banner.split())[:160]
                detected = _identify(result.banner)
                if detected:
                    result.service = detected
        return result
    except TimeoutError:
        return PortResult(port=port, state="filtered", error="timeout",
                          latency_ms=round((time.perf_counter() - started) * 1000, 1))
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except OSError as exc:
        return PortResult(port=port, state="error", error=str(exc))
    finally:
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()


async def scan_ports(
    host: str,
    ports: list[int],
    concurrency: int = 100,
    timeout: float = 2.0,
    cancel: CancellationToken | None = None,
    on_progress: object = None,
) -> list[PortResult]:
    """Scan ``ports`` with bounded concurrency, preserving input order."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results: dict[int, PortResult] = {}
    token = cancel or CancellationToken()

    async def _one(port: int) -> None:
        async with semaphore:
            if token.is_cancelled:
                return
            result = await probe_port(host, port, timeout=timeout)
            results[port] = result
            if callable(on_progress):
                on_progress(result)  # type: ignore[operator]

    await asyncio.gather(*(_one(port) for port in ports))
    return [results[p] for p in ports if p in results]
