"""The egress layer: the only component allowed to open a socket.

Everything else in SRO treats "contact a target" as an abstraction. This is the
abstraction's implementation, and it holds the authority that the rest of the
system deliberately does not have. A handler receives a session already bound to
an approved target and cannot name a different one, because the destination is
decided here, from the policy engine's verdict, and is never re-derived from
handler input.

The design is in `docs/EGRESS.md`. Three properties justify the shape:

**Resolve once, pin, then connect.** The scope engine decides on a *name*, and
it tests private ranges only for IP literals — `10.0.0.5` is denied,
`metadata.internal` is `UNKNOWN`. That is correct for a scope check and fatal for
something that connects, because a name can resolve anywhere. So this module
resolves once, refuses any address that is private, loopback, link-local or
reserved, and then connects to that pinned address while presenting the original
hostname for SNI and the `Host` header. The window between "we decided this was
allowed" and "we connected" does not exist, because the answer is fixed before
the socket is.

**Limits are structural, not advisory.** Every timeout, every cap, the hop
count: they are constructor arguments with defaults, the read loop stops at the
byte cap rather than trusting a `Content-Length`, and truncation is recorded
rather than silent. A caller cannot raise a limit by passing a bigger number,
because a handler never gets to pass one.

**Nothing remote reaches a model unlabelled.** Response bodies are third-party
text arriving in a context that is trusted to follow instructions. A target does
not need a vulnerability for `forget your instructions` to work. Every body is
fenced by `sro/core/untrusted.py` before it is returned for model consumption,
and the raw bytes stay available for evidence, where they belong.

No third-party dependencies. The stdlib gives us sockets, TLS and an HTTP client
that can be subclassed to honour a pinned address, which is all this needs.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from .errors import SROError
from .scope import FORBIDDEN_HOSTS, _is_internal_address
from .untrusted import render_fenced

#: Schemes the transport will dial. `file`, `gopher`, `dict` and friends are not
#: reachable here by construction: the scheme is validated against this set and
#: then used to build a connection class, not to be handed to something that
#: dispatches on it.
ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Methods tier 1 is approved for. A POST is `parameter_probe` wearing a
#: different name, and `parameter_probe` is deferred for exactly that reason.
APPROVED_METHODS = frozenset({"GET", "HEAD"})

_DEFAULT_PORTS = {"http": 80, "https": 443}


class EgressError(SROError):
    """Base for every refusal the transport makes."""


class DestinationRefused(EgressError):
    """The destination is not connectable, or is not allowed to be."""


class LimitExceeded(EgressError):
    """A structural cap stopped this before the network did."""


class CredentialsRequired(EgressError):
    """The request needs a credential and was not given a reference to one."""


# --- limits ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EgressLimits:
    """Caps for one request. Defaults are the conservative end of every range.

    Frozen, so nothing downstream can widen them. A handler receives a session,
    not a limits object, and `Transport.send` will not accept overrides — a cap
    that a caller can raise is not a cap.
    """

    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 30.0
    max_response_bytes: int = 1 << 20
    max_header_bytes: int = 32 << 10
    max_header_count: int = 100
    max_redirects: int = 0
    max_hops_resolved: int = 4

    def __post_init__(self) -> None:
        for name in ("connect_timeout", "read_timeout", "total_timeout"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        for name in (
            "max_response_bytes", "max_header_bytes",
            "max_header_count", "max_redirects", "max_hops_resolved",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must not be negative")


# --- credentials ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """A handle to a secret, not the secret.

    A handler is given one of these and cannot read it. Resolution happens here,
    at the moment of use, and the value goes into a header and nowhere else: not
    into the evidence store, not into a log, not into a `repr`, not into an error
    message. `secret` is excluded from `repr` and `str` for the same reason the
    transport never returns one.
    """

    label: str
    header: str
    _secret: str = field(repr=False, default="")

    @property
    def secret(self) -> str:
        if not self._secret:
            raise CredentialsRequired(
                f"credential {self.label!r} was declared but carries no value; "
                "supply it at resolve time, not in a file"
            )
        return self._secret

    def apply(self, headers: dict[str, str]) -> dict[str, str]:
        return {**headers, self.header: self.secret}


class CredentialResolver(Protocol):
    """Supplies secrets at the moment of use. Implementations must not log."""

    def __call__(self, ref: CredentialRef) -> str: ...


def static_resolver(secrets: Mapping[str, str]) -> CredentialResolver:
    """A resolver backed by a mapping. For tests and single-operator sessions."""

    def resolve(ref: CredentialRef) -> str:
        try:
            return secrets[ref.label]
        except KeyError:
            raise CredentialsRequired(
                f"no secret is held for credential {ref.label!r}; "
                "SRO will not read one from disk or the environment on its own"
            ) from None

    return resolve


# --- destination ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PinnedDestination:
    """A host and the single address it resolved to.

    The whole point is that this is decided before the socket exists and never
    revisited. `host` stays the name so TLS gets the right SNI and the origin
    server gets the right `Host` header; `address` is what the socket dials.
    """

    scheme: str
    host: str
    port: int
    address: str
    family: int
    #: Addresses the name also resolved to that were refused. A host resolving to
    #: both a public address and a metadata endpoint is either misconfigured or an
    #: attack, and connecting to the good one silently would hide which it was.
    rejected: tuple[str, ...] = ()

    @property
    def authority(self) -> str:
        default = _DEFAULT_PORTS[self.scheme]
        return self.host if self.port == default else f"{self.host}:{self.port}"


Resolver = Callable[[str, int], "list[tuple[str, int]]"]


def system_resolver(host: str, port: int) -> list[tuple[str, int]]:
    """The real resolver. Wrapped so tests can replace it at one seam."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise DestinationRefused(f"{host!r} does not resolve: {exc.strerror or exc}") from exc
    return [(info[4][0], info[4][1]) for info in infos]


def pin_destination(
    target: str,
    *,
    scheme: str = "https",
    port: int | None = None,
    limits: EgressLimits | None = None,
    resolver: Resolver | None = None,
) -> PinnedDestination:
    """Resolve `target` once and refuse anything that is not a public address.

    This is the function that makes a hostname safe to connect to. The scope
    engine has already ruled on the name; this rules on where the name goes, and
    the two answers are different questions. A name the program authorizes can
    still point at a metadata endpoint, and only the resolved address reveals it.
    """
    limits = limits or EgressLimits()
    resolve = resolver or system_resolver

    scheme = scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise DestinationRefused(
            f"scheme {scheme!r} is not permitted; only {sorted(ALLOWED_SCHEMES)} are"
        )

    parts = urlsplit(target if "://" in target else f"{scheme}://{target}")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise DestinationRefused(f"{target!r} has no host")
    if host in FORBIDDEN_HOSTS:
        raise DestinationRefused(
            f"{host!r} is a reserved loopback or metadata endpoint and is never contacted"
        )

    resolved_port = port or (parts.port or _DEFAULT_PORTS[scheme])

    # An IP literal is already the destination; nothing to resolve, and the
    # literal check below is the whole authorization for it.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        candidates = [(str(literal), resolved_port)]
    else:
        candidates = resolve(host, resolved_port)[: limits.max_hops_resolved]
        if not candidates:
            raise DestinationRefused(f"{host!r} resolved to no addresses")

    usable: list[tuple[str, int]] = []
    rejected: list[str] = []
    for address, address_port in candidates:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            rejected.append(f"{address} (not an address)")
            continue
        if _is_internal_address(parsed):
            # The measured gap in docs/EGRESS.md: the scope engine only tests IP
            # literals, so a name resolving inward arrives here as UNKNOWN and
            # would otherwise be connected to.
            rejected.append(f"{address} (private, loopback, link-local or reserved)")
            continue
        usable.append((str(parsed), address_port or resolved_port))

    if not usable:
        detail = "; ".join(rejected) or "no usable address"
        raise DestinationRefused(
            f"{host!r} resolves only to addresses SRO will not connect to: {detail}. "
            f"This is refused rather than attempted: a hostname the program authorizes "
            f"can still point at a host nobody authorized."
        )

    address, chosen_port = usable[0]
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    return PinnedDestination(
        scheme=scheme,
        host=host,
        port=chosen_port,
        address=address,
        family=family,
        rejected=tuple(rejected),
    )


# --- request and response -------------------------------------------------


@dataclass(frozen=True, slots=True)
class EgressRequest:
    """A request the transport has agreed to send.

    `target` is the approved destination and the transport dials it. A `path`
    cannot change where the connection goes, only what is asked for on it,
    which is the distinction the `url_target_mismatch` fix exists to protect.
    """

    target: str
    method: str = "GET"
    path: str = "/"
    scheme: str = "https"
    headers: Mapping[str, str] = field(default_factory=dict)
    credential: CredentialRef | None = None
    accept_compression: bool = False

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in APPROVED_METHODS:
            raise DestinationRefused(
                f"{method} is not an approved method for tier 1 egress. "
                f"Approved: {sorted(APPROVED_METHODS)}. A POST is a state-changing "
                f"action and belongs to a tool that goes through the approval flow."
            )
        if not self.path.startswith("/"):
            raise DestinationRefused(f"path {self.path!r} must be absolute")

        for name in self.headers:
            lowered = name.lower()
            if lowered in {"host", "content-length", "transfer-encoding", "connection"}:
                raise DestinationRefused(
                    f"header {name!r} is set by the transport; a caller cannot override it"
                )
            if lowered in {"authorization", "cookie", "proxy-authorization"}:
                raise DestinationRefused(
                    f"header {name!r} carries a credential value. Use a CredentialRef so "
                    f"SRO resolves it at the moment of use instead of holding it."
                )


@dataclass(slots=True)
class EgressResponse:
    """What came back, and what may be shown to a model.

    `body` is raw and belongs in evidence. `fenced_body` is what any tool result
    should carry, because it labels the content as third-party text. Handing a
    model `body` directly is the failure in docs/EGRESS.md threat 2.
    """

    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    truncated: bool
    destination: PinnedDestination
    elapsed_ms: int
    redirects: tuple[str, ...] = ()
    pinned: bool = True

    @property
    def size(self) -> int:
        return len(self.body)

    def text(self, *, limit: int | None = None) -> str:
        raw = self.body[: limit if limit is not None else len(self.body)]
        return raw.decode("utf-8", errors="replace")

    def fenced_body(self, *, field_name: str = "http_response", limit: int | None = None) -> str:
        """The body, fenced for a model. Truncation is stated, not silent."""
        text = self.text(limit=limit)
        return render_fenced(
            field_name,
            text,
            provenance=f"HTTP response body from {self.destination.authority} "
            f"(status {self.status})",
            truncated=self.truncated,
        )

    def to_dict(self, *, include_body: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "status": self.status,
            "reason": self.reason,
            "headers": self.headers,
            "bytes": self.size,
            "truncated": self.truncated,
            "destination": {
                "scheme": self.destination.scheme,
                "host": self.destination.host,
                "port": self.destination.port,
                "address": self.destination.address,
                "rejected_addresses": list(self.destination.rejected),
            },
            "elapsed_ms": self.elapsed_ms,
            "redirects": list(self.redirects),
        }
        if include_body:
            data["body"] = self.text()
        return data


# --- transport ------------------------------------------------------------


class _PinnedConnection(http.client.HTTPConnection):
    """An HTTP connection that dials a pinned address, not a name.

    `http.client` resolves `self.host` inside `connect()`, which is exactly the
    second resolution this design forbids. Overriding `connect` keeps `self.host`
    as the name — so the `Host` header is right — while the socket goes to the
    address that was authorized.
    """

    def __init__(self, destination: PinnedDestination, timeout: float) -> None:
        self._destination = destination
        super().__init__(destination.host, destination.port, timeout=timeout)

    def connect(self) -> None:  # noqa: D102 - stdlib contract
        sock = socket.socket(self._destination.family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self._destination.address, self._destination.port))
        except OSError as exc:
            sock.close()
            raise ConnectionRefusedError(
                f"cannot connect to {self._destination.address}:"
                f"{self._destination.port}: {exc}"
            ) from exc
        if self._destination.scheme == "https":
            context = ssl.create_default_context()
            try:
                # server_hostname is the name, not the address, or certificate
                # validation checks the wrong identity.
                sock = context.wrap_socket(sock, server_hostname=self._destination.host)
            except (ssl.SSLError, OSError) as exc:
                sock.close()
                raise ConnectionRefusedError(f"TLS handshake failed: {exc}") from exc
        self.sock = sock


class _PinnedHTTPSConnection(_PinnedConnection):
    pass


class Transport:
    """Opens sockets. Decides nothing.

    Construct it with an approved target already decided by the policy engine.
    It will refuse a request whose path or headers try to redirect the
    connection, and it will refuse to connect to an address the resolver returns
    that the program never authorized.
    """

    def __init__(
        self,
        *,
        limits: EgressLimits | None = None,
        resolver: Resolver | None = None,
        credentials: CredentialResolver | None = None,
    ) -> None:
        self.limits = limits or EgressLimits()
        self._resolver = resolver or system_resolver
        self._credentials = credentials

    def send(self, request: EgressRequest) -> EgressResponse:
        """Send one request. Redirects are refused unless limits allow them."""
        started = time.monotonic()
        deadline = started + self.limits.total_timeout

        headers = dict(request.headers)
        headers.setdefault("User-Agent", "opencode-sro (+security research; contact via program)")
        headers.setdefault("Accept", "*/*")
        headers.setdefault("Accept-Encoding", "identity" if request.accept_compression else "identity")
        headers["Host"] = request.target
        headers["Connection"] = "close"
        if request.credential is not None:
            if self._credentials is None:
                raise CredentialsRequired(
                    f"request needs credential {request.credential.label!r} but the "
                    "transport was built without a credential resolver"
                )
            secret = self._credentials(request.credential)
            headers[request.credential.header] = secret
            del secret

        current = request
        redirects: list[str] = []
        for hop in range(self.limits.max_redirects + 1):
            response = self._one(current, deadline)
            if not self._is_redirect(response.status) or hop >= self.limits.max_redirects:
                response.redirects = tuple(redirects)
                response.elapsed_ms = int((time.monotonic() - started) * 1000)
                if self._is_redirect(response.status):
                    response.headers.setdefault(
                        "x-sro-note",
                        f"redirect to {response.headers.get('location', '?')} not followed: "
                        "each hop needs its own scope decision",
                    )
                return response

            location = response.headers.get("location", "")
            redirects.append(location)
            current = self._redirect_target(current, location)

        raise LimitExceeded("redirect limit reached without a final response")

    @staticmethod
    def _is_redirect(status: int) -> bool:
        return status in {301, 302, 303, 307, 308}

    def _redirect_target(self, request: EgressRequest, location: str) -> EgressRequest:
        """A redirect is a new destination and gets a new pin, not a re-dial."""
        if not location:
            raise DestinationRefused("redirect with no Location header")
        if "://" in location:
            target, scheme = location, location.split("://", 1)[0]
        else:
            target, scheme = f"{request.scheme}://{request.target}{location}", request.scheme
        parts = urlsplit(target)
        return EgressRequest(
            target=parts.netloc,
            method=request.method,
            path=parts.path or "/",
            scheme=scheme,
            headers=request.headers,
        )

    def _one(self, request: EgressRequest, deadline: float) -> EgressResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LimitExceeded(
                f"total timeout of {self.limits.total_timeout}s exhausted before the "
                f"request to {request.target} was sent"
            )

        destination = pin_destination(
            request.target,
            scheme=request.scheme,
            limits=self.limits,
            resolver=self._resolver,
        )

        connection_class = (
            _PinnedHTTPSConnection if destination.scheme == "https" else _PinnedConnection
        )
        connection = connection_class(destination, timeout=min(self.limits.connect_timeout, remaining))
        try:
            connection.request(request.method, request.path, headers=dict(request.headers))
            raw = connection.getresponse()
            headers = self._collect_headers(raw)
            body = self._read_body(raw, deadline)
            return EgressResponse(
                status=raw.status,
                reason=raw.reason or "",
                headers=headers,
                body=body[0],
                truncated=body[1],
                destination=destination,
                elapsed_ms=0,
            )
        except (socket.timeout, TimeoutError) as exc:
            raise LimitExceeded(
                f"timeout talking to {destination.authority}: {exc}"
            ) from exc
        except (ConnectionRefusedError, http.client.HTTPException, OSError) as exc:
            raise DestinationRefused(f"request to {destination.authority} failed: {exc}") from exc
        finally:
            connection.close()

    def _collect_headers(self, response: Any) -> dict[str, str]:
        headers: dict[str, str] = {}
        total = 0
        for name, value in response.getheaders():
            if len(headers) >= self.limits.max_header_count:
                headers["x-sro-note"] = (
                    f"header count exceeded {self.limits.max_header_count}; remainder dropped"
                )
                break
            total += len(name) + len(value)
            if total > self.limits.max_header_bytes:
                headers["x-sro-note"] = (
                    f"header bytes exceeded {self.limits.max_header_bytes}; remainder dropped"
                )
                break
            headers[name] = value
        return headers

    def _read_body(self, response: Any, deadline: float) -> tuple[bytes, bool]:
        """Read to the cap, and never trust a declared length.

        `Content-Length` from a third party is a claim, not a fact, so the read
        stops on the cap rather than on what the header says. Truncation is
        reported because a silently shortened body is one a researcher will later
        describe as having read in full.
        """
        chunks: list[bytes] = []
        received = 0
        while True:
            if time.monotonic() > deadline:
                raise LimitExceeded(
                    f"total timeout of {self.limits.total_timeout}s exhausted while reading "
                    "the response body"
                )
            try:
                chunk = response.read(8192)
            except (socket.timeout, TimeoutError) as exc:
                raise LimitExceeded(f"timeout reading the response body: {exc}") from exc
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if received >= self.limits.max_response_bytes:
                kept = b"".join(chunks)[: self.limits.max_response_bytes]
                return kept, True
        return b"".join(chunks), False
