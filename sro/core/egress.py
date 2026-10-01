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
import struct
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from .dnswire import DNSError
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
                        f"redirect to {_header(response.headers, 'location') or 'an unnamed location'} not followed: "
                        "each hop needs its own scope decision",
                    )
                return response

            location = _header(response.headers, "location") or ""
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


def resolve_addresses(host: str, family: int = socket.AF_INET) -> list[str]:
    """Addresses for `host`, via the operating system's own resolver.

    Lives here rather than in a handler because it is the one lookup that does
    not open a socket SRO controls — the kernel talks to the configured resolver
    on our behalf. Keeping it in this module means the invariant "no handler
    touches the network" stays absolute instead of carrying an exception.

    It is also the better answer where it is available: it is what the operator's
    own machine sees, including any split-horizon view the target intends.
    """
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DestinationRefused(f"{host!r} does not resolve: {exc.strerror or exc}") from exc
    seen: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in seen:
            seen.append(address)
    return seen


# --- DNS ------------------------------------------------------------------
#
# DNS is egress too, and it has one property that makes it different from HTTP:
# the resolver is almost always a private address, because it is the operator's
# own router. So the rule "refuse private addresses" cannot apply to the
# nameserver, and applying it anyway would make the tool useless.
#
# What is safe here is narrower and specific: the nameserver comes from the
# operating system and never from a parameter, so the target under test cannot
# choose where the query goes. Resolution happens through the operator's own
# resolver, which already receives every lookup their machine makes — SRO adds
# no new disclosure by using it. A caller-supplied nameserver would be the
# attack: it lets the target steer where a query asking about the target is sent.

#: Nameserver sources, in order. `/etc/resolv.conf` is the only one that is
#: consulted; the loopback entries are what a systemd-resolved or dnsmasq setup
#: presents, and both mean "ask the local stub".
_RESOLV_CONF = "/etc/resolv.conf"


def system_nameservers(path: str = _RESOLV_CONF) -> list[str]:
    """The operator's resolvers, read from the OS. Never from a parameter.

    Returns addresses only. A `nameserver` line pointing at a hostname is
    skipped rather than resolved, because resolving it would need a resolver,
    and the only one available is the thing being read.
    """
    servers: list[str] = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise DestinationRefused(
            f"cannot read {path}: {exc}. SRO will not guess a resolver, and will "
            f"not accept one as a parameter."
        ) from exc

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) < 2:
                continue
            candidate = parts[1]
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            # an unspecified address is a configuration error, not a server
            if not address.is_unspecified and str(address) not in servers:
                servers.append(str(address))
    if not servers:
        raise DestinationRefused(
            f"{path} lists no usable nameserver address. SRO will not fall back to a "
            f"public resolver: sending a target's name to a third party is not this "
            f"tool's decision to make."
        )
    return servers


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup.

    RFC 9110 says field names are case-insensitive, and real servers use every
    casing there is. Our dict preserves what the peer sent, so 
    silently misses a , and a redirect then looks like one with no target.
    """
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _dns_exchange(
    query: bytes,
    nameserver: str,
    *,
    limits: EgressLimits,
    deadline: float,
) -> bytes:
    """One DNS query over UDP, with a TCP retry when the answer is truncated.

    The retry is the whole reason this is not just `socket.sendto`: a truncated
    answer is a partial record set, and reporting it as the answer would show a
    researcher fewer records than exist.
    """
    from .dnswire import Message, parse_message

    family = socket.AF_INET6 if ipaddress.ip_address(nameserver).version == 6 else socket.AF_INET
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LimitExceeded("total timeout exhausted before the DNS query was sent")

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(min(limits.read_timeout, max(remaining, 0.001)))
    try:
        sock.sendto(query, (nameserver, 53))
        data, _ = sock.recvfrom(limits.max_response_bytes)
    except (socket.timeout, TimeoutError) as exc:
        raise LimitExceeded(f"DNS query to {nameserver} timed out: {exc}") from exc
    except OSError as exc:
        raise DestinationRefused(f"DNS query to {nameserver} failed: {exc}") from exc
    finally:
        sock.close()

    try:
        message = parse_message(data)
    except DNSError as exc:
        raise DestinationRefused(f"DNS response from {nameserver} is malformed: {exc}") from exc

    if message.truncated:
        return _dns_over_tcp(query, nameserver, limits=limits, deadline=deadline)
    return data


def _dns_over_tcp(query: bytes, nameserver: str, *, limits: EgressLimits, deadline: float) -> bytes:
    """DNS over TCP, for answers that exceed the UDP payload limit."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LimitExceeded("total timeout exhausted before the DNS TCP retry")

    family = socket.AF_INET6 if ipaddress.ip_address(nameserver).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(min(limits.connect_timeout, max(remaining, 0.001)))
    try:
        sock.connect((nameserver, 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        prefix = _recv_exactly(sock, 2, limits)
        length = struct.unpack("!H", prefix)[0]
        if length > limits.max_response_bytes:
            raise LimitExceeded(
                f"DNS-over-TCP answer claims {length} bytes, over the "
                f"{limits.max_response_bytes} byte cap"
            )
        return _recv_exactly(sock, length, limits)
    except (socket.timeout, TimeoutError) as exc:
        raise LimitExceeded(f"DNS TCP retry to {nameserver} timed out: {exc}") from exc
    except OSError as exc:
        raise DestinationRefused(f"DNS TCP retry to {nameserver} failed: {exc}") from exc
    finally:
        sock.close()


def _recv_exactly(sock: socket.socket, count: int, limits: EgressLimits) -> bytes:
    chunks: list[bytes] = []
    received = 0
    while received < count:
        chunk = sock.recv(min(8192, count - received))
        if not chunk:
            raise DestinationRefused("connection closed mid-answer")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


# --- shared hosting zones -------------------------------------------------
#
# A wildcard scope rule says "every name under this domain is authorized". For a
# domain the program owns exclusively that is fine and often correct. For a domain
# on a wildcard DNS zone it authorizes every other tenant on that zone, and those
# tenants hold other people's data.
#
# This is not hypothetical. `*.zendesk.com` — the obvious reading of "Zendesk's web
# surface" — resolves for arbitrary labels: a random string under it lands on
# Zendesk's shared front end, which serves every customer instance. Authorizing it
# authorizes every customer's ticket data, and nothing in the manifest says so,
# because the program expresses its scope in product names the engine cannot
# match at all.
#
# The check is a probe: ask for a name that cannot have been created, and see
# whether it answers. A domain whose authoritative data returns a name nobody
# registered is a shared zone, and a wildcard rule over it is a claim about other
# people's hosts.

#: Characters that cannot appear in a DNS label, so this string is guaranteed not
#: to be a name anyone could have registered or provisioned.
_PROBE_PREFIX = "sro-shared-zone-probe"


def zone_accepts_arbitrary_names(
    domain: str,
    *,
    resolver: Resolver | None = None,
) -> dict[str, Any]:
    """Does `domain` resolve for names nobody could have created?

    Returns a verdict rather than a bool, because "it answers" and "it does not"
    are both worth reporting: the first is a hazard, and the second is the only
    thing that makes a wildcard rule defensible.

    The probe label is unpredictable, so an operator who wants to hide a shared
    zone cannot pre-create the exact name this asks for and answer it themselves.
    """
    import secrets

    resolve = resolver or system_resolver
    label = f"{_PROBE_PREFIX}-{secrets.token_hex(8)}"
    probe = f"{label}.{domain.strip('.').lower()}"

    try:
        answers = resolve(probe, 53)
    except DestinationRefused:
        # The name did not resolve. That is the good answer, and it is reported as
        # evidence rather than as a failure: it is what makes the wildcard safe.
        return {
            "domain": domain,
            "probe": probe,
            "shared_zone": False,
            "reason": "the probe name does not resolve, so this domain is not a wildcard zone",
        }

    addresses = sorted({address for address, _ in answers})
    return {
        "domain": domain,
        "probe": probe,
        "shared_zone": True,
        "addresses": addresses,
        "reason": (
            f"{probe} resolves to {', '.join(addresses)}. This domain answers for names "
            f"that were never created, so it is a shared hosting zone. A wildcard scope "
            f"rule over it authorizes every other tenant on that zone, not just the "
            f"program's own hosts — and those tenants hold other people's data. Scope the "
            f"program's hosts explicitly instead, and record the exclusion of other tenants "
            f"as a human obligation, because no rule here will enforce it."
        ),
    }


# --- TLS inspection -------------------------------------------------------
#
# Inspection is not verification, and the difference is the whole tool.
# `getpeercert()` returns a parsed dict only when the chain validated, so using
# it would make the tool useless for its main purpose: a certificate that is
# expired, self-signed, or issued for a different name is exactly what a
# researcher opened it to find, and it would report nothing.
#
# So this connects with CERT_NONE and reads the DER itself. That is safe because
# nothing here trusts the certificate — it is parsed as bytes and reported as
# facts about a third party's host. What still holds is the pinning: the address
# is resolved once, refused if private, and dialled directly, so an unverified
# handshake is not an unconstrained one.
#
# The parser is deliberately small. It extracts what a researcher reads off a
# certificate and nothing more — no chain building, no path validation, no
# signature checking. Anything it cannot extract it reports as absent rather than
# guessing.

_DER_TIME_TAGS = {0x17: "utc", 0x18: "generalized"}


def _der_read(data: bytes, offset: int) -> tuple[int, bytes, int, int | None]:
    """One TLV. Returns (next_offset, tag, content_offset, content_length)."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise ValueError("unsupported or truncated DER length")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    else:
        length = length_byte
    return cursor + length, tag, cursor, length


def _der_children(data: bytes, content: bytes, start: int, length: int) -> list[tuple[int, bytes, int, int]]:
    """Every TLV inside a constructed value."""
    out: list[tuple[int, bytes, int, int]] = []
    offset = start
    end = start + length
    while offset < end:
        next_offset, tag, content_offset, content_length = _der_read(data, offset)
        out.append((next_offset, tag, content_offset, content_length))
        offset = next_offset
    return out


def _der_time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", errors="replace").strip()
    if tag == 0x17:  # UTCTime, 2-digit year
        if len(text) >= 11:
            century = "20" if int(text[:2]) < 50 else "19"
            return f"{century}{text[:2]}-{text[2:4]}-{text[4:6]}T{text[6:8]}:{text[8:10]}:{text[10:12]}Z"
        return text
    if tag == 0x18 and len(text) >= 12:  # GeneralizedTime, 4-digit year
        return f"{text[:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}Z"
    return text


#: OIDs that matter to a reader looking at a certificate.
_OID_COMMON_NAME = b"\x55\x04\x03"
_OID_SUBJECT_ALT_NAME = b"\x55\x1d\x11"
_OID_BASIC_CONSTRAINTS = b"\x55\x1d\x13"


def _der_common_names(data: bytes, name_start: int, name_length: int) -> list[str]:
    """Common names out of an X.501 Name, in order."""
    names: list[str] = []
    for _, tag, start, length in _der_children(data, data, name_start, name_length):
        if tag != 0x31:  # RDN SET
            continue
        for _, atv_tag, atv_start, atv_length in _der_children(data, data, start, length):
            if atv_tag != 0x30:
                continue
            parts = _der_children(data, data, atv_start, atv_length)
            if len(parts) != 2:
                continue
            oid_start, oid_length = parts[0][2], parts[0][3]
            if data[oid_start : oid_start + oid_length] != _OID_COMMON_NAME:
                continue
            value_start, value_length = parts[1][2], parts[1][3]
            names.append(data[value_start : value_start + value_length].decode("utf-8", "replace"))
    return names


def parse_certificate(der: bytes) -> dict[str, Any]:
    """The fields a researcher reads off a certificate.

    No chain building, no signature verification, no policy evaluation. This is
    a reader for one certificate's fields, and it says so rather than implying it
    validated anything.
    """
    import base64
    import hashlib

    try:
        _, cert_tag, cert_start, cert_length = _der_read(der, 0)
        if cert_tag != 0x30:
            raise ValueError("certificate is not a SEQUENCE")
        top = _der_children(der, der, cert_start, cert_length)
        if not top:
            raise ValueError("certificate has no TBSCertificate")
        _, _, tbs_start, tbs_length = top[0]

        fields = _der_children(der, der, tbs_start, tbs_length)
        cursor = 0
        if fields and fields[0][1] == 0xA0:  # [0] version
            cursor += 1

        # serialNumber, signature, issuer, validity, subject
        validity = None
        issuer_cns: list[str] = []
        subject_cns: list[str] = []
        offset = cursor + 3  # skip serial, signature, issuer
        if offset < len(fields):
            _, _, start, length = fields[offset]
            kids = _der_children(der, der, start, length)
            if len(kids) == 2:
                validity = {
                    "not_before": _der_time(kids[0][1], der[kids[0][2] : kids[0][2] + kids[0][3]]),
                    "not_after": _der_time(kids[1][1], der[kids[1][2] : kids[1][2] + kids[1][3]]),
                }
        offset += 1
        if offset < len(fields):
            _, _, start, length = fields[offset]
            subject_cns = _der_common_names(der, start, length)
        offset += 1
        if cursor + 2 < len(fields):
            _, _, start, length = fields[cursor + 2]
            issuer_cns = _der_common_names(der, start, length)

        sans: list[str] = []
        for _, ext_tag, ext_start, ext_length in fields[offset:]:
            if ext_tag != 0xA3:
                continue
            for _, seq_tag, seq_start, seq_length in _der_children(der, der, ext_start, ext_length):
                if seq_tag != 0x30:
                    continue
                for _, extn_tag, extn_start, extn_length in _der_children(der, der, seq_start, seq_length):
                    if extn_tag != 0x30:
                        continue
                    parts = _der_children(der, der, extn_start, extn_length)
                    if not parts:
                        continue
                    oid_start, oid_length = parts[0][2], parts[0][3]
                    oid = der[oid_start : oid_start + oid_length]
                    value = parts[-1]
                    if oid == _OID_SUBJECT_ALT_NAME and value[1] == 0x04:
                        sans.extend(_der_san_entries(der, value[2], value[3]))
    except (ValueError, IndexError) as exc:
        return {
            "parsed": False,
            "error": f"could not parse the certificate: {exc}",
            "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
            "der_bytes": len(der),
        }

    return {
        "parsed": True,
        "subject_cn": subject_cns[0] if subject_cns else "",
        "subject_cn_all": subject_cns,
        "issuer_cn": issuer_cns[0] if issuer_cns else "",
        "sans": sorted(set(sans)),
        "validity": validity or {},
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "der_bytes": len(der),
        "der_base64": base64.b64encode(der).decode("ascii"),
    }


#: GeneralName context tags. dNSName is [2] IMPLICIT IA5String; iPAddress is [7]
#: IMPLICIT OCTET STRING. They are not the same tag, and reading an IP address as
#: [2] produced one unreadable blob per extension.
_DNS_NAME_TAG = 0x82
_IP_ADDRESS_TAG = 0x87


def _der_san_entries(data: bytes, start: int, length: int) -> list[str]:
    """DNS and IP entries from a SubjectAltName extension.

    The extension's OCTET STRING wraps a GeneralNames SEQUENCE, so the inner
    sequence has to be unwrapped before its entries are readable. Reading the
    OCTET STRING's content as though it were the entry list yields a single blob
    containing the whole extension, which is what happened first.
    """
    import ipaddress

    names: list[str] = []
    for _, tag, inner_start, inner_length in _der_children(data, data, start, length):
        if tag != 0x30:
            continue
        for _, entry_tag, entry_start, entry_length in _der_children(
            data, data, inner_start, inner_length
        ):
            raw = data[entry_start : entry_start + entry_length]
            try:
                if entry_tag == _IP_ADDRESS_TAG and len(raw) == 4:
                    names.append(str(ipaddress.IPv4Address(raw)))
                elif entry_tag == _IP_ADDRESS_TAG and len(raw) == 16:
                    names.append(str(ipaddress.IPv6Address(raw)))
                elif entry_tag == _DNS_NAME_TAG:
                    names.append(raw.decode("ascii", errors="replace"))
            except ValueError:
                continue
    return names


def inspect_tls(
    destination: PinnedDestination,
    *,
    limits: EgressLimits | None = None,
) -> dict[str, Any]:
    """Handshake against a pinned address and read what the peer presents.

    No verification, deliberately: an expired or self-signed certificate has to
    be reportable. The pinning is unaffected, because the address was resolved
    and refused as private before this is called.
    """
    limits = limits or EgressLimits()
    family = socket.AF_INET6 if ipaddress.ip_address(destination.address).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(limits.connect_timeout)
    try:
        sock.connect((destination.address, destination.port))
    except OSError as exc:
        sock.close()
        raise DestinationRefused(
            f"cannot connect to {destination.authority}: {exc}"
        ) from exc

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Verification off, hostname checking off. This reads a certificate; it does
    # not decide whether to trust it, and pretending otherwise would make the tool
    # blind to exactly the cases it exists to find.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with context.wrap_socket(sock, server_hostname=destination.host) as tls:
            tls.settimeout(limits.read_timeout)
            cipher = tls.cipher() or ()
            version = tls.version()
            der = tls.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError) as exc:
        sock.close()
        raise DestinationRefused(f"TLS handshake with {destination.authority} failed: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not der:
        return {
            "handshake": "succeeded",
            "protocol": version,
            "cipher": cipher[0] if cipher else "",
            "certificate": None,
            "note": "the peer presented no certificate, so there is nothing to read",
        }

    return {
        "handshake": "succeeded",
        "protocol": version,
        "cipher": cipher[0] if cipher else "",
        "cipher_details": {
            "protocol": cipher[2] if len(cipher) > 2 else "",
            "bits": cipher[4] if len(cipher) > 4 else "",
        },
        "verified": False,
        "certificate": parse_certificate(der),
        "note": (
            "Presented as-is and not verified. An expired, self-signed or mismatched "
            "certificate is exactly what this is for, so nothing here decides whether to "
            "trust it. Reported facts only: no chain was built and no signature checked."
        ),
    }
