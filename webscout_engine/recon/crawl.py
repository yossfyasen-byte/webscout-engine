"""Crawling and parameter extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit
from ..core.net import CancellationToken
from ..core.scope import origin
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


# -------------------------------------------------------------------------
# from crawl.py
# -------------------------------------------------------------------------

HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#][^"']*)["']""", re.IGNORECASE)
SRC_RE = re.compile(r"""src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
JS_ENDPOINT_RE = re.compile(
    r"""["']((?:/|\.\.?/|https?://)[A-Za-z0-9_\-./?=&%#:+~]{2,160})["']"""
)
ROBOTS_RE = re.compile(r"(?im)^\s*(?:Disallow|Allow)\s*:\s*(\S+)\s*$")
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".webm", ".pdf", ".zip", ".gz", ".exe",
)


@dataclass(slots=True)
class FormInfo:
    action: str
    method: str
    fields: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    robots_paths: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    script_bodies: dict[str, str] = field(default_factory=dict)

    @property
    def all_urls(self) -> list[str]:
        seen: dict[str, None] = {}
        for url in [*self.pages, *self.links, *self.scripts, *self.sitemap_urls]:
            seen.setdefault(url, None)
        return list(seen)


def extract_links(html: str) -> list[str]:
    found = [match.strip() for match in HREF_RE.findall(html or "")]
    return [item for item in found if item and not item.lower().startswith(("javascript:", "mailto:", "tel:"))]


def extract_scripts(html: str) -> list[str]:
    return [m.strip() for m in SRC_RE.findall(html or "") if m.strip()]


def extract_forms(html: str) -> list[FormInfo]:
    forms: list[FormInfo] = []
    for attributes, body in FORM_RE.findall(html or ""):
        action_match = ACTION_RE.search(attributes + " " + body)
        method_match = METHOD_RE.search(attributes)
        fields = [name for name in NAME_RE.findall(body) if name]
        forms.append(
            FormInfo(
                action=action_match.group(1).strip() if action_match else "",
                method=(method_match.group(1).lower() if method_match else "get"),
                fields=fields,
            )
        )
    return forms


def extract_comments(html: str) -> list[str]:
    return [" ".join(c.split())[:200] for c in COMMENT_RE.findall(html or "") if c.strip()]


def extract_js_endpoints(text: str) -> list[str]:
    found: list[str] = []
    for candidate in JS_ENDPOINT_RE.findall(text or ""):
        if candidate.startswith(("//", "http://", "https://")) or candidate.startswith("/"):
            found.append(candidate)
    return list(dict.fromkeys(found))[:100]


def parse_robots(text: str) -> list[str]:
    return [m for m in ROBOTS_RE.findall(text or "") if m and m != "/"]


def parse_sitemap(text: str) -> list[str]:
    return SITEMAP_LOC_RE.findall(text or "")


class Crawler:
    def __init__(
        self,
        client: object,
        base_url: str,
        max_pages: int = 6,
        max_scripts: int = 6,
        cancel: CancellationToken | None = None,
    ) -> None:
        self.client = client
        self.base_url = base_url
        self.base_origin = origin(base_url)
        self.max_pages = max_pages
        self.max_scripts = max_scripts
        self.cancel = cancel or CancellationToken()

    def _normalise(self, link: str) -> str | None:
        if not link:
            return None
        absolute = urljoin(self.base_url, link.strip())
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            return None
        if origin(absolute) != self.base_origin:
            return None
        if parts.path.lower().endswith(SKIP_EXTENSIONS):
            return None
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        queue: list[str] = [self.base_url]
        visited: set[str] = set()
        script_count = 0

        while queue and len(visited) < self.max_pages:
            if self.cancel.is_cancelled:
                break
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                response = await self.client.get(url, allow_redirects=True)  # type: ignore[attr-defined]
            except Exception:
                continue
            if response.error or response.status >= 400:
                continue
            if "html" not in response.content_type and url != self.base_url:
                continue
            result.pages.append(url)
            html = response.body

            for link in extract_links(html):
                normalised = self._normalise(link)
                if normalised and normalised not in visited and normalised not in queue:
                    queue.append(normalised)
                    result.links.append(normalised)
            for script in extract_scripts(html):
                normalised = self._normalise(script)
                if normalised:
                    result.scripts.append(normalised)
            result.forms.extend(extract_forms(html))
            result.comments.extend(extract_comments(html))

        # Bounded JavaScript fetch: static analysis only, never executed.
        for script_url in dict.fromkeys(result.scripts):
            if script_count >= self.max_scripts or self.cancel.is_cancelled:
                break
            script_count += 1
            try:
                response = await self.client.get(script_url)  # type: ignore[attr-defined]
            except Exception:
                continue
            if response.error or response.status >= 400 or not response.body:
                continue
            result.script_bodies[script_url] = response.body
            result.js_endpoints.extend(extract_js_endpoints(response.body))

        # robots.txt and sitemap.xml often reveal the application's own paths.
        for name, collector in (("robots.txt", result.robots_paths), ("sitemap.xml", result.sitemap_urls)):
            try:
                response = await self.client.get(self._normalise(name) or "")  # type: ignore[attr-defined]
            except Exception:
                continue
            if response.error or response.status >= 400 or not response.body:
                continue
            if name == "robots.txt":
                collector.extend(parse_robots(response.body))
            else:
                collector.extend(parse_sitemap(response.body))

        result.links = list(dict.fromkeys(result.links))
        result.scripts = list(dict.fromkeys(result.scripts))
        result.js_endpoints = list(dict.fromkeys(result.js_endpoints))[:100]
        return result


# -------------------------------------------------------------------------
# from params.py
# -------------------------------------------------------------------------

INTERESTING_NAMES = {
    "q", "s", "search", "query", "id", "page", "lang", "redirect", "url", "next",
    "return", "returnurl", "callback", "file", "path", "name", "user", "email",
    "message", "comment", "template", "view", "debug", "format", "type",
}


@dataclass(slots=True)
class Parameter:
    name: str
    value: str
    source: str  # query | form
    url: str = ""  # endpoint that actually accepts this parameter

    @property
    def interesting(self) -> bool:
        return self.name.lower() in INTERESTING_NAMES


def extract_query_params(url: str) -> list[Parameter]:
    parts = urlsplit(url)
    return [
        Parameter(name=name, value=value, source="query", url=url)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]


def extract_form_params(html: str) -> list[Parameter]:
    from .crawl import extract_forms

    params: list[Parameter] = []
    for form in extract_forms(html):
        for field in form.fields:
            params.append(Parameter(name=field, value="", source="form"))
    return params


def set_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with one query parameter replaced (or added)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    updated = False
    new_pairs: list[tuple[str, str]] = []
    for key, existing in pairs:
        if key == name and not updated:
            new_pairs.append((key, value))
            updated = True
        else:
            new_pairs.append((key, existing))
    if not updated:
        new_pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_pairs), parts.fragment))


def canary(prefix: str = "zs") -> str:
    """A unique, harmless marker used to detect reflection."""
    return f"{prefix}{secrets.token_hex(4)}"


def dedupe_parameters(params: list[Parameter]) -> list[Parameter]:
    """De-duplicate by name *and* endpoint.

    The same parameter name appears on many endpoints; collapsing them by name
    alone would mean only the first endpoint is ever tested.
    """
    seen: dict[tuple[str, str, str], Parameter] = {}
    for param in params:
        seen.setdefault((param.source, param.name, param.url), param)
    return list(seen.values())
