"""DNS wire-format encoding and decoding. No sockets, no I/O.

Separated from `sro/core/egress.py` for one reason: this module is pure
arithmetic on bytes, so it can be tested exhaustively without a network, and the
component that is allowed to open a socket stays small enough to review.

Only the record types a researcher actually reads are decoded. A tool that
returns a hex blob for a type it does not understand is worse than one that says
which type it skipped, because the hex blob looks like data and the omission
looks like an absence.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

# --- record types ---------------------------------------------------------

A = 1
NS = 2
CNAME = 5
SOA = 6
PTR = 12
MX = 15
TXT = 16
AAAA = 28
SRV = 33
OPT = 41
CAA = 257

TYPE_NAMES = {
    A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR",
    MX: "MX", TXT: "TXT", AAAA: "AAAA", SRV: "SRV", CAA: "CAA",
}
TYPE_BY_NAME = {name: code for code, name in TYPE_NAMES.items()}

#: Types this module will decode. Anything else is reported by number.
DECODED = frozenset(TYPE_NAMES)

CLASS_IN = 1

#: A UDP DNS response without EDNS0 is capped at 512 bytes. Larger answers set TC
#: and are retried over TCP. The cap is a protocol constant, not a preference.
UDP_PAYLOAD_LIMIT = 512

#: EDNS0 buffer we advertise. 4096 is the conventional maximum and keeps a large
#: TXT or MX set in one datagram instead of forcing a TCP retry.
EDNS0_PAYLOAD = 4096

#: Refuse absurd answers rather than allocating on a stranger's say-so. A
#: response claiming 65535 records is either broken or hostile; either way it is
#: not worth the memory.
MAX_NAME_LENGTH = 255
MAX_LABELS = 127
MAX_POINTER_HOPS = 32


class DNSError(ValueError):
    """A message that cannot be parsed, or a query that cannot be built."""


# --- names ----------------------------------------------------------------


def encode_name(name: str) -> bytes:
    """Encode a hostname as length-prefixed labels terminated by a zero byte.

    Rejects rather than truncates. A query for a name we mangled returns an
    answer about a different name, and an NXDOMAIN for the mangled version looks
    identical to a host that does not exist.
    """
    if not name or name == ".":
        return b"\x00"
    if name.endswith("."):
        name = name[:-1]

    out = bytearray()
    for label in name.split("."):
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not encoded:
            raise DNSError(f"{name!r} has an empty label")
        if len(encoded) > 63:
            raise DNSError(f"label {label!r} exceeds the 63-byte limit")
        out.append(len(encoded))
        out += encoded
    if len(out) + 1 > MAX_NAME_LENGTH:
        raise DNSError(f"name {name!r} exceeds {MAX_NAME_LENGTH} bytes")
    out.append(0)
    return bytes(out)


def decode_name(message: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a possibly-compressed name, returning it and the next offset.

    `depth` guards against a compression pointer loop. A pointer that points at
    itself is a real thing a hostile resolver will send, and following it without
    a bound is an infinite loop inside a security tool.
    """
    if depth > MAX_POINTER_HOPS:
        raise DNSError("compression pointer chain is too deep; probable pointer loop")

    labels: list[str] = []
    cursor = offset
    end_offset: int | None = None

    while True:
        if cursor >= len(message):
            raise DNSError("name runs past the end of the message")
        length = message[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                raise DNSError(f"compression pointer {pointer} is past the end of the message")
            if end_offset is None:
                end_offset = cursor + 2
            suffix, _ = decode_name(message, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return (".".join(labels), end_offset)

        if length == 0:
            cursor += 1
            return (".".join(labels), end_offset if end_offset is not None else cursor)

        cursor += 1
        if cursor + length > len(message):
            raise DNSError("label runs past the end of the message")
        labels.append(message[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length
        if len(labels) > MAX_LABELS:
            raise DNSError("name has too many labels")


# --- messages -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN


@dataclass(slots=True)
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: Any = None
    raw: bytes = b""

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "type": self.type_name,
            "ttl": self.ttl,
        }
        if self.rtype in (A, AAAA):
            out["address"] = self.data
        elif self.rtype in (NS, CNAME, PTR):
            out["target"] = self.data
        elif self.rtype == MX:
            out["preference"] = self.data[0]
            out["exchange"] = self.data[1]
        elif self.rtype == TXT:
            out["text"] = self.data
        elif self.rtype == SRV:
            out["priority"], out["weight"], out["port"] = self.data[0], self.data[1], self.data[2]
            out["target"] = self.data[3]
        elif self.rtype == CAA:
            out["flags"], out["tag"], out["value"] = self.data
        else:
            out["raw"] = self.raw.hex()
        return out


@dataclass(slots=True)
class Message:
    """A decoded DNS message."""

    txid: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return {
            0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
            4: "NOTIMP", 5: "REFUSED",
        }.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rcode": self.rcode_name,
            "truncated": self.truncated,
            "authoritative": self.authoritative,
            "questions": [{"name": q.name, "type": TYPE_NAMES.get(q.qtype, str(q.qtype))} for q in self.questions],
            "answers": [r.to_dict() for r in self.answers],
            "authority": [r.to_dict() for r in self.authority],
        }


def build_query(
    name: str,
    rtype: int,
    *,
    txid: int | None = None,
    recursion_desired: bool = True,
    edns0: bool = True,
) -> bytes:
    """Build a standard recursive query, optionally advertising EDNS0.

    A query id is not a secret and DNS does not authenticate it, but a fixed id
    makes off-path spoofing trivial and costs nothing to vary.
    """
    import os

    txid = txid if txid is not None else (os.urandom(2)[0] << 8 | os.urandom(2)[1]) & 0xFFFF
    flags = 0x0100 if recursion_desired else 0x0000

    arcount = 1 if edns0 else 0
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, arcount)
    question = encode_name(name) + struct.pack("!HH", rtype, CLASS_IN)

    additional = b""
    if edns0:
        # root name, OPT(41), UDP payload size, extended rcode/version/flags
        additional = b"\x00" + struct.pack("!HHIH", OPT, UDP_PAYLOAD_LIMIT, 0, 0)

    return header + question + additional


def parse_message(message: bytes) -> Message:
    """Parse a DNS response. Raises `DNSError` rather than returning partial data."""
    if len(message) < 12:
        raise DNSError(f"message is {len(message)} bytes; a DNS header is 12")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", message[:12])
    if flags & 0x8000 == 0:
        raise DNSError("this is a query, not a response")

    offset = 12
    questions: list[Question] = []
    for _ in range(qdcount):
        qname, offset = decode_name(message, offset)
        if offset + 4 > len(message):
            raise DNSError("question section is truncated")
        qtype, qclass = struct.unpack("!HH", message[offset : offset + 4])
        offset += 4
        questions.append(Question(qname, qtype, qclass))

    def read_records(count: int) -> list[Record]:
        nonlocal offset
        records: list[Record] = []
        for _ in range(count):
            rname, offset = decode_name(message, offset)
            if offset + 10 > len(message):
                raise DNSError("resource record header is truncated")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(message):
                raise DNSError(f"record data claims {rdlength} bytes but the message ends")
            rdata = message[offset : offset + rdlength]
            records.append(
                Record(
                    name=rname,
                    rtype=rtype,
                    rclass=rclass,
                    ttl=ttl,
                    data=_decode_rdata(message, rtype, rdata, offset),
                    raw=rdata,
                )
            )
            offset += rdlength
        return records

    return Message(
        txid=txid,
        flags=flags,
        questions=questions,
        answers=read_records(ancount),
        authority=read_records(nscount),
        additional=read_records(arcount),
    )


def _decode_rdata(message: bytes, rtype: int, rdata: bytes, rdata_offset: int) -> Any:
    """Decode record data, following the compression rules for name-bearing types.

    Names inside RDATA may be compressed, and the pointer is relative to the
    start of the *message*, not to the record — which is why the whole message
    and the record's own offset are both needed here.
    """
    if rtype == A:
        if len(rdata) != 4:
            raise DNSError(f"A record data is {len(rdata)} bytes, expected 4")
        return str(ipaddress.IPv4Address(rdata))
    if rtype == AAAA:
        if len(rdata) != 16:
            raise DNSError(f"AAAA record data is {len(rdata)} bytes, expected 16")
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (NS, CNAME, PTR):
        return decode_name(message, rdata_offset)[0]
    if rtype == MX:
        if len(rdata) < 3:
            raise DNSError("MX record data is too short")
        preference = struct.unpack("!H", rdata[:2])[0]
        return (preference, decode_name(message, rdata_offset + 2)[0])
    if rtype == TXT:
        strings: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            length = rdata[cursor]
            cursor += 1
            if cursor + length > len(rdata):
                raise DNSError("TXT character-string runs past the record")
            strings.append(rdata[cursor : cursor + length].decode("utf-8", errors="replace"))
            cursor += length
        return strings
    if rtype == SRV:
        if len(rdata) < 7:
            raise DNSError("SRV record data is too short")
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        return (priority, weight, port, decode_name(message, rdata_offset + 6)[0])
    if rtype == CAA:
        if len(rdata) < 2:
            raise DNSError("CAA record data is too short")
        flags = rdata[0]
        tag_length = rdata[1]
        tag = rdata[2 : 2 + tag_length].decode("ascii", errors="replace")
        value = rdata[2 + tag_length :].decode("ascii", errors="replace")
        return (flags, tag, value)
    return None
