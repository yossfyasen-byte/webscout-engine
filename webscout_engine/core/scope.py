"""Scope enforcement.

Every outbound request - including each redirect hop and every address a host
name resolves to - passes through :class:`Scope` before a socket is opened.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Cloud metadata endpoints are blocked even in lab mode: they are never a
# legitimate assessment target and reaching them is an exfiltration risk.
_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}

DEFAULT_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000}


@dataclass(slots=True)
class ScopeDecision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - convenience only
        return self.allowed


def normalize_target(target: str) -> str:
    """Turn ``example.com`` / ``example.com/app`` into a full URL."""
    text = (target or "").strip()
    if not text:
        raise ValueError("target must not be empty")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError(f"target has no host: {target!r}")
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def origin(url: str) -> str:
    """Scheme + host + port of ``url`` (no trailing slash)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")


def join_url(base: str, path: str) -> str:
    """Join a base URL and a relative path without dropping base path segments."""
    if not path:
        return base
    if path.startswith(("http://", "https://")):
        return path
    root = base if base.endswith("/") else base + "/"
    return root + path.lstrip("/")


def classify_ip(value: str) -> str:
    """Return a coarse classification used by the scope policy and reports."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return "invalid"
    if ip in _METADATA_IPS:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return "public"


class Scope:
    """Allow-list of hosts plus a network-destination policy."""

    def __init__(
        self,
        lab_mode: bool = False,
        include_subdomains: bool = False,
        max_redirects: int = 5,
        verify_resolved: bool = True,
        extra_hosts: set[str] | None = None,
    ) -> None:
        self.lab_mode = lab_mode
        self.include_subdomains = include_subdomains
        self.max_redirects = max_redirects
        self.verify_resolved = verify_resolved
        self.allowed_hosts: set[str] = {h.lower() for h in (extra_hosts or set())}
        self.base_url: str = ""
        self.blocked_events: list[str] = []
        self._resolved: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ setup
    @classmethod
    def for_target(
        cls,
        target: str,
        lab_mode: bool = False,
        include_subdomains: bool = False,
        extra_hosts: set[str] | None = None,
        verify_resolved: bool = True,
    ) -> Scope:
        scope = cls(
            lab_mode=lab_mode,
            include_subdomains=include_subdomains,
            extra_hosts=extra_hosts,
            verify_resolved=verify_resolved,
        )
        url = normalize_target(target)
        scope.base_url = url
        scope.add_host(urlsplit(url).hostname or "")
        return scope

    def add_host(self, host: str) -> None:
        clean = (host or "").strip().lower().rstrip(".")
        if clean:
            self.allowed_hosts.add(clean)

    def add_url(self, url: str) -> None:
        host = urlsplit(url).hostname
        if host:
            self.add_host(host)

    # ----------------------------------------------------------------- policy
    def is_host_allowed(self, host: str) -> bool:
        clean = (host or "").strip().lower().rstrip(".")
        if not clean:
            return False
        if clean in self.allowed_hosts:
            return True
        if self.include_subdomains:
            return any(clean.endswith("." + allowed) for allowed in self.allowed_hosts)
        return False

    def check_ip(self, value: str) -> ScopeDecision:
        kind = classify_ip(value)
        if kind == "invalid":
            return ScopeDecision(False, f"unparseable address {value!r}")
        if kind == "metadata":
            return ScopeDecision(False, f"cloud metadata address blocked ({value})")
        if kind == "public":
            return ScopeDecision(True)
        if self.lab_mode:
            return ScopeDecision(True)
        return ScopeDecision(
            False,
            f"{kind} address blocked ({value}); use lab mode for local testing",
        )

    def check_url(self, url: str) -> ScopeDecision:
        try:
            parts = urlsplit(url)
        except ValueError:
            return ScopeDecision(False, f"malformed URL {url!r}")
        if parts.scheme not in ("http", "https"):
            return ScopeDecision(False, f"scheme {parts.scheme!r} not allowed")
        host = parts.hostname
        if not host:
            return ScopeDecision(False, "URL has no host")
        try:
            port = parts.port
        except ValueError:
            return ScopeDecision(False, "invalid port in URL")
        if port is not None and not (0 < port < 65536):
            return ScopeDecision(False, f"port {port} out of range")
        if not self.is_host_allowed(host):
            return ScopeDecision(False, f"host {host!r} is outside the configured scope")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return ScopeDecision(True)  # hostname: address policy applied on resolve
        return self.check_ip(host)

    async def resolve(self, host: str, port: int = 443) -> list[str]:
        cached = self._resolved.get(host)
        if cached is not None:
            return cached
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=4.0
            )
        except (TimeoutError, OSError):
            self._resolved[host] = []
            return []
        addresses: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if addr not in addresses:
                addresses.append(addr)
        self._resolved[host] = addresses
        return addresses

    async def ensure_allowed(self, url: str) -> ScopeDecision:
        """Full check: host allow-list, then every resolved address."""
        decision = self.check_url(url)
        if not decision.allowed:
            self._record_block(decision.reason)
            return decision
        if not self.verify_resolved:
            return decision
        host = urlsplit(url).hostname or ""
        try:
            ipaddress.ip_address(host)
            return decision  # literal address already validated in check_url
        except ValueError:
            pass
        port = urlsplit(url).port or (443 if urlsplit(url).scheme == "https" else 80)
        addresses = await self.resolve(host, port)
        for address in addresses:
            ip_decision = self.check_ip(address)
            if not ip_decision.allowed:
                self._record_block(f"{host} resolves to {address}: {ip_decision.reason}")
                return ScopeDecision(
                    False, f"{host} resolves to {address}: {ip_decision.reason}"
                )
        return decision

    def _record_block(self, reason: str) -> None:
        if len(self.blocked_events) < 200:
            self.blocked_events.append(reason)

    def describe(self) -> dict[str, object]:
        return {
            "base_url": self.base_url,
            "allowed_hosts": sorted(self.allowed_hosts),
            "include_subdomains": self.include_subdomains,
            "lab_mode": self.lab_mode,
            "verify_resolved": self.verify_resolved,
        }
