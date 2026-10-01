"""Dumb reader foundation.

A platform reader reads and returns data. That is the whole job. It does not
reason about security, decide authorization, run tools, submit findings,
comment on findings, or touch program state.

Read-only is a property of the code, not a property of a prompt. The
transport in this module physically cannot issue a request that modifies
anything:

*   There is no public method that accepts an HTTP verb.
*   The only verb it will build is GET.
*   Every request is pinned to the provider's own host allowlist, so a
    hostile engagement URL cannot redirect the reader at internal services.
*   Redirects that would change the request are refused.

A module-level `FORBIDDEN_VERBS` marker is asserted by the test suite.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from html import unescape as html_unescape
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..core.config import ProviderConfig
from ..core.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderSchemaError,
    ProviderUnavailableError,
    ReadOnlyViolation,
)
from ..core.util import utcnow_iso

#: Marker consumed by tests/test_write_protection.py.
FORBIDDEN_VERBS = ("POST", "PUT", "PATCH", "DELETE")

USER_AGENT = "SRO/0.1 (security-research-orchestrator; read-only)"

DEFAULT_TIMEOUT = 15


@dataclass(slots=True)
class RawResponse:
    """Exactly what the platform returned, with no interpretation."""

    url: str
    status: int
    headers: dict[str, str]
    body: str
    retrieved_at: str = field(default_factory=utcnow_iso)
    from_cache: bool = False

    def json(self) -> Any:
        if not self.body.strip():
            return None
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise ProviderSchemaError(f"{self.url}: response body is not valid JSON ({exc})") from exc

    def meta_link(self) -> str | None:
        """Parse RFC 5988 Link headers for next-page cursors."""
        link = self.headers.get("link") or self.headers.get("Link") or ""
        for part in link.split(","):
            match = re.search(r'<([^>]+)>\s*;\s*rel="?next"?', part)
            if match:
                return match.group(1)
        return None

    def truncate(self, limit: int = 4096) -> "RawResponse":
        if len(self.body) <= limit:
            return self
        return RawResponse(
            url=self.url,
            status=self.status,
            headers=self.headers,
            body=self.body[:limit] + f"\n...[truncated {len(self.body) - limit} chars]",
            retrieved_at=self.retrieved_at,
            from_cache=self.from_cache,
        )


class ReadOnlyTransport:
    """GET-only HTTP client pinned to a fixed set of hosts.

    There is deliberately no method signature that accepts a verb. To send
    anything other than a GET you would have to edit this file, and the test
    suite fails if the forbidden verbs appear here.
    """

    def __init__(
        self,
        allowed_hosts: set[str],
        *,
        token: str = "",
        token_hosts: set[str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self._allowed_hosts = {h.lower() for h in allowed_hosts}
        self._token = token
        # The credential is only ever attached to the platform's API host. A
        # reader's allowlist also contains the public web host, because public
        # pages are the zero-credential path, and shipping an API token there
        # would hand it to whatever the page serves.
        self._token_hosts = (
            {h.lower() for h in token_hosts} if token_hosts is not None else set(self._allowed_hosts)
        )
        self._timeout = timeout
        self._max_bytes = max_bytes

    # -- internal build ----------------------------------------------------

    def _assert_host_allowed(self, url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise ProviderError(f"reader transport refused a malformed URL: {exc}") from exc
        if parts.scheme != "https":
            raise ProviderError(f"reader transport only speaks https, refused: {parts.scheme!r}")
        host = (parts.hostname or "").lower()
        if host not in self._allowed_hosts:
            raise ProviderError(
                f"reader transport refused off-allowlist host {host!r}; "
                f"allowed: {sorted(self._allowed_hosts)}"
            )
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ProviderUnavailableError(f"could not resolve {host}: {exc}") from exc
        for info in infos:
            address = info[4][0]
            if _is_private_address(address):
                raise ProviderError(
                    f"reader transport refused {host} -> {address}: "
                    "provider hosts must not resolve to private addresses"
                )

    def _build(self, url: str) -> urllib.request.Request:
        request = urllib.request.Request(url=url, method="GET")
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", "application/json, text/html;q=0.9, */*;q=0.5")
        request.add_header("Accept-Encoding", "identity")
        host = (urlsplit(url).hostname or "").lower()
        if self._token and host in self._token_hosts:
            request.add_header("Authorization", f"Token token=\"{self._token}\"")
        return request

    def _get(self, url: str) -> RawResponse:
        self._assert_host_allowed(url)
        request = self._build(url)
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            _AllowlistRedirect(self._allowed_hosts),
            urllib.request.HTTPSHandler(context=context),
        )
        try:
            with opener.open(request, timeout=self._timeout) as response:
                body = response.read(self._max_bytes + 1).decode("utf-8", errors="replace")
                if len(body) > self._max_bytes:
                    raise ProviderSchemaError(
                        f"{url}: response exceeded {self._max_bytes} bytes; refusing to buffer"
                    )
                return RawResponse(
                    url=response.geturl(),
                    status=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read(65536).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - best effort only
                pass
            if exc.code in (401, 403):
                raise ProviderAuthError(
                    f"{url}: platform refused the request ({exc.code}). "
                    "Configure optional read-only credentials or import the brief manually.",
                    body_preview=_meaningful_preview(body),
                ) from exc
            raise ProviderUnavailableError(
                f"{url}: HTTP {exc.code}", body_preview=_meaningful_preview(body)
            ) from exc
        except urllib.error.URLError as exc:
            raise ProviderUnavailableError(f"{url}: {exc.reason}") from exc
        except http.client.HTTPException as exc:
            # A truncated or malformed response body raises IncompleteRead here,
            # after do_open already returned, so it is not wrapped in URLError.
            raise ProviderUnavailableError(f"{url}: {type(exc).__name__}: {exc}") from exc
        except socket.timeout as exc:  # pragma: no cover - timing dependent
            raise ProviderUnavailableError(f"{url}: timed out after {self._timeout}s") from exc

    # -- the entire public surface -----------------------------------------

    def get(self, url: str) -> RawResponse:
        """Perform a GET. This is the only network call the reader can make."""
        return self._get(url)

    def get_json(self, url: str) -> Any:
        return self._get(url).json()

    def get_text(self, url: str) -> str:
        return self._get(url).body


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only inside the provider allowlist, and never off https.

    A redirect is the cheapest way to turn a reader into a confused deputy, so
    an off-host redirect is refused rather than followed, and a scheme
    downgrade is refused because the Authorization header would go in cleartext.
    """

    def __init__(self, allowed: set[str]) -> None:
        super().__init__()
        self._allowed = {h.lower() for h in allowed}

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        parts = urlsplit(newurl)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https":
            # A downgrade would send the Authorization header in cleartext.
            raise ProviderError(
                f"reader transport refused a {parts.scheme!r} redirect; only https is permitted"
            )
        if host not in self._allowed:
            raise ProviderError(
                f"reader transport refused redirect to off-allowlist host {host!r}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def scheme_of(url: str) -> str:
    return urlsplit(url).scheme or ""


#: Fields that only a real program page carries. A page whose extractable
#: content is a name, a description and a title is a client-rendered shell, and
#: reading one as a program is how a portal's own name becomes a "program" with
#: script text as its policy — text that then reaches a model through the
#: untrusted fence. Measured against live Bugcrowd and HackerOne in September
#: 2026: both render program pages client-side, so the anonymous path returns a
#: shell for essentially every program.
#:
# `name`, `description` and `policy` are deliberately NOT here, because every
# extractor fabricates them as a fallback — `name` from the <title>,
# `description` and `policy` from `strip_html(page)`. A shell check that counts
# any of them as evidence is circular: it looks for proof in fields the extractor
# has just invented, so a client-rendered frame always passes. That is not
# hypothetical; it is how HackerOne's own name became a program whose policy was
# the whole page.
PROGRAM_EVIDENCE_FIELDS = frozenset(
    {
        "handle", "code", "url", "program_url", "launch_date", "submission_state",
        "structured_scopes", "targets", "scope", "scope_text",
        "rules", "instructions", "safe_harbor", "disclosure_policy",
        "restrictions", "known_issues", "known_issues_text", "categories", "groups",
    }
)


#: A segment that looks like a program code or handle rather than a path part.
_CODE_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{1,64}$")


def extract_program_code(
    text: str,
    *,
    provider: str,
    kind: str = "program",
    anchors: tuple[str, ...] = (),
    noise: frozenset[str] = frozenset(),
) -> str:
    """Pull a program code or handle out of whatever the researcher typed.

    Shared by all three readers because they were three copies of this function,
    and a bug fixed in one of them leaves the other two broken — which is how a
    bare code like `zendesk` came to fail on all three while the code that
    accepts it was obviously right there.

    The bare-code case is handled first, because it is the one a path-only scan
    cannot see: `urlsplit("https://zendesk")` puts the whole string in `netloc`
    and leaves `path` empty, so scanning the path finds nothing. The resulting
    error was worse than the failure — it claimed it could not determine a code
    from an input that *was* the code, which sends the researcher looking for a
    URL problem they do not have.

    Only applied when the input carried no scheme. `https://zendesk` names a
    host, and treating a host as a program code would be a guess.
    """
    from ..core.errors import ProviderError

    original = (text or "").strip()
    if not original:
        raise ProviderError(f"no {provider} {kind} code or URL supplied")

    had_scheme = "://" in original
    parts = urlsplit(original if had_scheme else f"https://{original}")

    if not had_scheme and _CODE_SHAPE.match(parts.netloc) and "." not in parts.netloc:
        return parts.netloc

    segments = [s for s in parts.path.split("/") if s]
    for anchor in anchors:
        for index, segment in enumerate(segments):
            if segment.lower() != anchor:
                continue
            # The code is the segment after the anchor; a trailing anchor like
            # ".../engagements" has none, which is not an error by itself.
            if index + 1 < len(segments) and _CODE_SHAPE.match(segments[index + 1]):
                return segments[index + 1]
            break

    # First match forward, not last. HackerOne URLs put the handle early and the
    # page name late — hackerone.com/<handle>/policy — so a reverse scan returns
    # "policy". The two readers disagreed here before this was shared, and
    # picking the wrong one is a silent wrong answer rather than a failure.
    for segment in segments:
        if segment.lower() in noise:
            continue
        if _CODE_SHAPE.match(segment):
            return segment

    raise ProviderError(
        f"could not determine a {provider} {kind} code from {original!r}.\n\n"
        f"Accepted forms: a bare code ({kind} codes have no dots), a full program URL, "
        f"or a program URL with a path. Got netloc={parts.netloc!r} and "
        f"path={parts.path!r}, so there was no code segment to read."
    )


def is_program_shell(fields: dict[str, object]) -> bool:
    """True when this looks like a rendered app shell rather than a program.

    Name, title, description and a URL are not evidence: every site has those,
    including the site itself. Anything from `PROGRAM_EVIDENCE_FIELDS` is.
    """
    for key, value in fields.items():
        if key in PROGRAM_EVIDENCE_FIELDS and value:
            return False
    return True


def _meaningful_preview(body: str, limit: int = 200) -> str:
    """A preview worth reading inside an error message.

    A 404 from a JavaScript app returns a page whose first 500 characters are
    doctype, meta tags and stylesheet links. Dumping that into a warning buries
    the one fact that matters — the URL answered, and with what. Keeps the title,
    otherwise the visible text, and always states the real size.
    """
    import re

    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    if title:
        return f"<title>{re.sub(chr(92)+'s+', ' ', title.group(1)).strip()[:limit]}> +{len(body)} bytes"
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
    return text[:limit] + (f" +{len(body)} bytes" if len(text) > limit else "")


def _is_private_address(address: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def normalize_url(url: str, *, scheme: str = "https", default_path: str = "/") -> str:
    parts = urlsplit(url.strip())
    if not parts.netloc:
        parts = parts._replace(netloc=parts.path, path=default_path)
    path = parts.path or default_path
    return urlunsplit((scheme, parts.netloc.lower(), path, parts.query, ""))


_SCRIPT_STYLE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")
_ANY_TAG = re.compile(r"(?s)<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def strip_html(value: str) -> str:
    """Flatten a platform HTML fragment to plain text.

    Scripts and styles are dropped entirely rather than unwrapped, so inline
    payloads in a page never reach a downstream parser as text.
    """
    # An unterminated <script> means the regex below does not match, and raw
    # script text then flows out as prose. Scrape targets reach a model through
    # the untrusted fence, so malformed markup must not be able to inject text
    # into a field that looks like the platform's own prose. Close the tag first,
    # or drop the remainder.
    value = value or ""
    value = re.sub(r"<(script|style)\b[^>]*>[\s\S]*$", r"<\1></\1>", value, flags=re.I)
    text = _SCRIPT_STYLE.sub(" ", value)
    text = _ANY_TAG.sub(" ", text)
    text = html_unescape(text)
    return _WHITESPACE.sub(" ", text).strip()


@dataclass(slots=True)
class ReaderCapabilities:
    """What a concrete reader can do. Advertised so agents cannot guess."""

    provider: str
    reads: tuple[str, ...] = ()
    authenticated_reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    import_supported: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "reads": list(self.reads),
            "authenticated_reads": list(self.authenticated_reads),
            "writes": list(self.writes),
            "import_supported": self.import_supported,
            "notes": self.notes,
        }


def forbid_write(operation: str) -> None:
    """The write path does not exist.

    Any code that reaches for platform mutation ends up here. It raises
    instead of performing an action, which means a regression shows up as a
    loud failure rather than a silent submission.
    """
    raise ReadOnlyViolation(
        f"SRO platform connectors are read-only by construction. "
        f"Refused operation: {operation!r}. "
        "SRO never creates, edits, comments on, or submits reports to a bounty platform."
    )


class BaseReader:
    """Common reader plumbing. Subclasses only implement `capabilities`.

    A reader declares its hosts in `default_hosts` and `api_hosts`. That is the
    one place a provider's surface is defined, which is deliberate: a reader that
    could widen its own allowlist at runtime could be pointed at any host on the
    internet by a config value. The allowlist is therefore part of the class, and
    a test asserts every reader's hosts are exactly what it declares.
    """

    provider: str = "base"
    default_hosts: tuple[str, ...] = ()
    #: Hosts that may receive the API credential. A subset of default_hosts.
    api_hosts: tuple[str, ...] = ()
    #: Default API origin. Declared per provider rather than derived by string
    #: concatenation, so a config without an explicit base_url still resolves to
    #: a host that is both real and on this reader's allowlist.
    api_origin: str = ""

    def __init__(self, config: ProviderConfig, *, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.config = config
        self._token = config.resolve_token() if config.credentials != "none" else ""
        self.transport = ReadOnlyTransport(
            set(self.default_hosts),
            token=self._token,
            token_hosts=set(self.api_hosts or self.default_hosts),
            timeout=timeout,
        )

    def capabilities(self) -> ReaderCapabilities:
        return ReaderCapabilities(provider=self.provider)

    # -- helpers for subclasses -------------------------------------------

    @property
    def has_credentials(self) -> bool:
        return bool(self._token)

    def base_url(self) -> str:
        """The configured API origin, or the provider's own default."""
        configured = (self.config.base_url or "").strip().rstrip("/")
        if configured:
            return configured
        if self.api_origin:
            return self.api_origin
        raise ProviderError(
            f"provider {self.provider!r} has no api_origin and no base_url configured in sro.json"
        )

    def require_public_mode(self) -> None:
        if self.config.mode == "off":
            raise ProviderError(
                f"provider {self.provider!r} is disabled in sro.json; set "
                f"providers.{self.provider}.mode to \"public\" or \"readonly\" to enable reads"
            )
