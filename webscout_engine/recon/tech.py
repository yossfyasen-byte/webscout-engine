"""Technology fingerprinting and TLS inspection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field
from ..core.models import Confidence
import asyncio
import contextlib
import ssl
from datetime import UTC, datetime


# -------------------------------------------------------------------------
# from tech.py
# -------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class FingerprintRule(BaseModel):
    name: str
    category: str = "other"
    headers: dict[str, list[str]] = Field(default_factory=dict)
    body: list[str] = Field(default_factory=list)
    cookies: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    cve: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class TechMatch:
    name: str
    category: str
    version: str = ""
    evidence: str = ""
    confidence: Confidence = Confidence.HIGH
    cve_hints: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CveHint:
    technology: str
    version: str
    cve_id: str
    severity: str
    summary: str
    affected: str


CDN_WAF_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"]},
    "Akamai": {"headers": ["x-akamai-transformed", "akamai-grn", "x-cache-remote"], "server": ["akamaighost"]},
    "Fastly": {"headers": ["x-fastly-request-id", "fastly-io-info", "x-served-by"], "server": ["fastly"]},
    "Amazon CloudFront": {"headers": ["x-amz-cf-id", "x-amz-cf-pop", "via"]},
    "Azure Front Door": {"headers": ["x-azure-ref", "x-fd-int-roxy-purgeid"]},
    "Google Cloud CDN": {"headers": ["x-cloud-trace-context"], "server": ["gws", "google frontend"]},
    "Imperva Incapsula": {"headers": ["x-iinfo"], "cookies": ["incap_ses", "visid_incap"]},
    "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"], "server": ["sucuri"]},
    "AWS WAF": {"headers": ["x-amzn-requestid"], "server": ["awselb"]},
    "ModSecurity": {"headers": ["x-mod-security"], "server": ["mod_security"]},
}


def _version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[.\-_]", value):
        digits = re.match(r"(\d+)", chunk)
        if digits:
            parts.append(int(digits.group(1)))
    return tuple(parts)


def version_less_than(candidate: str, limit: str) -> bool:
    """Compare dotted versions; returns False when either side is unparseable."""
    left = _version_tuple(candidate)
    right = _version_tuple(limit)
    if not left or not right:
        return False
    length = max(len(left), len(right))
    left += (0,) * (length - len(left))
    right += (0,) * (length - len(right))
    return left < right


class TechFingerprinter:
    def __init__(self, rules: list[FingerprintRule], cve_map: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.rules = rules
        self.cve_map = cve_map or {}

    @classmethod
    def from_data(cls, path: Path | None = None, cve_path: Path | None = None) -> TechFingerprinter:
        rules_path = path or (DATA_DIR / "fingerprints.json")
        rules: list[FingerprintRule] = []
        if rules_path.exists():
            payload = json.loads(rules_path.read_text(encoding="utf-8"))
            for entry in payload.get("fingerprints", payload if isinstance(payload, list) else []):
                rules.append(FingerprintRule(**entry))
        cve_map: dict[str, list[dict[str, Any]]] = {}
        cve_file = cve_path or (DATA_DIR / "cve_map.json")
        if cve_file.exists():
            cve_map = json.loads(cve_file.read_text(encoding="utf-8"))
        return cls(rules=rules, cve_map=cve_map)

    # ------------------------------------------------------------------ match
    def analyse(
        self,
        headers: dict[str, str],
        body: str,
        cookies: dict[str, str] | None = None,
        server: str = "",
    ) -> list[TechMatch]:
        lowered_headers = {k.lower(): v for k, v in headers.items()}
        cookie_names = {k.lower() for k in (cookies or {})}
        matches: dict[str, TechMatch] = {}

        for rule in self.rules:
            version = ""
            evidence = ""
            confidence = Confidence.HIGH

            for header_name, patterns in rule.headers.items():
                value = lowered_headers.get(header_name.lower(), "")
                if not value:
                    continue
                for pattern in patterns:
                    found = re.search(pattern, value, re.IGNORECASE)
                    if found:
                        evidence = f"header {header_name}: {value[:120]}"
                        if found.groups():
                            version = found.group(1) or ""
                        confidence = Confidence.CERTAIN
                        break
                if evidence:
                    break

            if not evidence and rule.cookies:
                for cookie in rule.cookies:
                    if cookie.lower() in cookie_names:
                        evidence = f"cookie {cookie}"
                        confidence = Confidence.CERTAIN
                        break

            if not evidence and rule.body and body:
                for pattern in rule.body:
                    found = re.search(pattern, body, re.IGNORECASE)
                    if found:
                        evidence = f"body pattern /{pattern}/"
                        if found.groups():
                            version = found.group(1) or ""
                        confidence = Confidence.MEDIUM
                        break

            if evidence:
                existing = matches.get(rule.name)
                if existing is None or (not existing.version and version):
                    matches[rule.name] = TechMatch(
                        name=rule.name,
                        category=rule.category,
                        version=version,
                        evidence=evidence,
                        confidence=confidence,
                        cve_hints=list(rule.cve),
                    )

        if server and not matches:
            # Only fall back when no rule recognised the server header, otherwise the
            # same product would be reported twice under two names.
            matches["unidentified-server"] = TechMatch(
                name=server.split("/")[0] or "Unidentified server",
                category="web-server",
                version=server.split("/")[1] if "/" in server else "",
                evidence=f"Server header: {server}",
                confidence=Confidence.LOW,
            )
        return sorted(matches.values(), key=lambda m: (m.category, m.name))

    # ---------------------------------------------------------------- helpers
    def detect_cdn_waf(self, headers: dict[str, str], cookies: dict[str, str] | None = None) -> list[str]:
        lowered = {k.lower(): v for k, v in headers.items()}
        cookie_names = {k.lower() for k in (cookies or {})}
        hits: list[str] = []
        for vendor, signals in CDN_WAF_SIGNATURES.items():
            for header in signals.get("headers", []):
                if header.lower() in lowered:
                    hits.append(f"{vendor} (header {header})")
                    break
            else:
                for cookie in signals.get("cookies", []):
                    if cookie.lower() in cookie_names:
                        hits.append(f"{vendor} (cookie {cookie})")
                        break
                else:
                    for pattern in signals.get("server", []):
                        if re.search(pattern, lowered.get("server", ""), re.IGNORECASE):
                            hits.append(f"{vendor} (server header)")
                            break
        return hits

    def correlate_cves(self, matches: list[TechMatch]) -> list[CveHint]:
        """Return *potential* CVEs for versioned technologies."""
        hints: list[CveHint] = []
        for match in matches:
            if not match.version:
                continue
            entries = self.cve_map.get(match.name.lower(), [])
            for entry in entries:
                affected = str(entry.get("affected", ""))
                if affected.startswith("<") and version_less_than(match.version, affected[1:].strip()):
                    hints.append(
                        CveHint(
                            technology=match.name,
                            version=match.version,
                            cve_id=str(entry.get("id", "")),
                            severity=str(entry.get("severity", "medium")),
                            summary=str(entry.get("summary", "")),
                            affected=affected,
                        )
                    )
        return hints


# -------------------------------------------------------------------------
# from tls.py
# -------------------------------------------------------------------------

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass(slots=True)
class TlsInfo:
    enabled: bool = False
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    self_signed: bool = False
    trusted: bool = False
    days_remaining: int | None = None
    error: str = ""


def _parse_cert_time(value: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except (ValueError, TypeError):
            continue
    return None


def _flatten_name(name: object) -> str:
    """Turn dnspython-style ``((('commonName','x'),),)`` into ``CN=x``."""
    parts: list[str] = []
    if isinstance(name, (tuple, list)):
        for entry in name:
            if isinstance(entry, (tuple, list)) and entry and len(entry) >= 2:
                key = str(entry[0])
                value = str(entry[1])
                short = {
                    "commonName": "CN",
                    "organizationName": "O",
                    "organizationalUnitName": "OU",
                    "countryName": "C",
                }.get(key, key)
                parts.append(f"{short}={value}")
    return ", ".join(parts)


def parse_certificate(cert: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Extract report fields from an ``ssl.getpeercert()`` dictionary."""
    reference = now or datetime.now(UTC)
    subject = _flatten_name(cert.get("subject", ()))
    issuer = _flatten_name(cert.get("issuer", ()))
    not_after_raw = str(cert.get("notAfter", ""))
    not_before_raw = str(cert.get("notBefore", ""))
    not_after = _parse_cert_time(not_after_raw)
    san: list[str] = []
    san_pairs = cert.get("subjectAltName") or ()
    if isinstance(san_pairs, (list, tuple)):
        for pair in san_pairs:
            if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] == "DNS":
                san.append(str(pair[1]))
    days_remaining: int | None = None
    if not_after is not None:
        days_remaining = int((not_after - reference).total_seconds() // 86400)
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before_raw,
        "not_after": not_after_raw,
        "san": san,
        "self_signed": bool(subject) and subject == issuer,
        "days_remaining": days_remaining,
    }


def _context(verify: bool, hostname: str) -> ssl.SSLContext:
    if verify:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(Exception):
        context.set_ciphers("DEFAULT@SECLEVEL=1")
    return context


async def _handshake(host: str, port: int, timeout: float, verify: bool) -> tuple[ssl.SSLObject, dict]:
    context = _context(verify, host)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host),
        timeout=timeout,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object is not None else {}
        return ssl_object, cert or {}
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def inspect_tls(host: str, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    """Inspect the certificate chain. Falls back to an unverified handshake.

    A self-signed or expired certificate still tells us the protocol version and
    cipher, so the fallback keeps the report useful while marking the cert as
    untrusted instead of guessing.
    """
    try:
        ssl_object, cert = await _handshake(host, port, timeout, verify=True)
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        try:
            ssl_object, cert = await _handshake(host, port, timeout, verify=False)
        except Exception as inner:  # noqa: BLE001
            return TlsInfo(enabled=False, error=f"{type(inner).__name__}: {inner}")
        info = TlsInfo(enabled=True, trusted=False, error=f"certificate verification failed: {exc.verify_message}")
        _fill_from_object(info, ssl_object, cert)
        return info
    except TimeoutError:
        return TlsInfo(enabled=False, error="connection timeout")
    except (OSError, ssl.SSLError) as exc:
        return TlsInfo(enabled=False, error=f"{type(exc).__name__}: {exc}")

    info = TlsInfo(enabled=True, trusted=trusted)
    _fill_from_object(info, ssl_object, cert)
    return info


def _fill_from_object(info: TlsInfo, ssl_object: ssl.SSLObject, cert: dict) -> None:
    with contextlib.suppress(Exception):
        info.version = ssl_object.version() or ""
    with contextlib.suppress(Exception):
        cipher = ssl_object.cipher()
        info.cipher = cipher[0] if cipher else ""
    if cert:
        parsed = parse_certificate(cert)
        info.subject = str(parsed["subject"])
        info.issuer = str(parsed["issuer"])
        info.not_before = str(parsed["not_before"])
        info.not_after = str(parsed["not_after"])
        info.san = [str(item) for item in parsed["san"]]
        info.self_signed = bool(parsed["self_signed"])
        remaining = parsed["days_remaining"]
        info.days_remaining = int(remaining) if isinstance(remaining, int) else None
