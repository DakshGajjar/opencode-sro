"""Tests for the DNS wire codec.

No sockets. These are byte-level tests against hand-assembled messages, so they
cover the cases that a live resolver would never produce on demand: a
compression pointer loop, a record claiming more data than the message holds, a
name that runs off the end. All three are things a hostile resolver will send.

`test_a_compression_pointer_loop_terminates` is the one that matters most: a
pointer loop followed without a depth bound is an infinite loop inside a security
tool, and it arrives from the party least able to be trusted.
"""

from __future__ import annotations

import struct

import pytest

from sro.core import dnswire
from sro.core.dnswire import (
    DNSError,
    Message,
    Record,
    build_query,
    decode_name,
    encode_name,
    parse_message,
)


def header(txid=0x1234, flags=0x8180, qd=1, an=0, ns=0, ar=0) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qd, an, ns, ar)


# --- names ----------------------------------------------------------------


class TestNameEncoding:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("example.com", b"\x07example\x03com\x00"),
            ("a", b"\x01a\x00"),
            ("example.com.", b"\x07example\x03com\x00"),
        ],
    )
    def test_labels_are_length_prefixed(self, name, expected) -> None:
        assert encode_name(name) == expected

    def test_the_root_is_a_single_zero_byte(self) -> None:
        assert encode_name(".") == b"\x00"

    def test_idna_names_are_encoded_as_punycode(self) -> None:
        encoded = encode_name("exämple.com")
        # 0x0e = 14 bytes, the length of "xn--exmple-cua"; the point is that a
        # non-ASCII label becomes ASCII and stays under 63 bytes.
        assert encoded.startswith(b"\x0exn--")
        assert all(byte < 128 for byte in encoded)

    @pytest.mark.parametrize("name", ["example..com", ".example.com", ""])
    def test_malformed_names_are_refused_not_truncated(self, name) -> None:
        """A mangled name returns an answer about a different name, and the
        NXDOMAIN for the mangled version is indistinguishable from a host that
        does not exist."""
        if name == "":
            assert encode_name(name) == b"\x00"
            return
        with pytest.raises(DNSError):
            encode_name(name)

    def test_an_oversized_label_is_refused(self) -> None:
        with pytest.raises(DNSError, match="63-byte"):
            encode_name("a" * 64 + ".com")

    def test_an_oversized_name_is_refused(self) -> None:
        with pytest.raises(DNSError, match="255 bytes"):
            encode_name(".".join(["abcdefghij"] * 26) + ".com")


class TestNameDecoding:
    def test_a_plain_name(self) -> None:
        assert decode_name(b"\x07example\x03com\x00", 0) == ("example.com", 13)

    def test_a_compression_pointer_is_followed(self) -> None:
        # name at offset 0, then a pointer back to it
        message = b"\x07example\x03com\x00" + b"\xc0\x00"
        assert decode_name(message, 13) == ("example.com", 15)

    def test_a_pointer_chain_is_followed(self) -> None:
        # the pointed-to name must come first, or the pointer aims at itself
        message = b"\x07example\x03com\x00" + b"\x03www\xc0\x00"
        assert decode_name(message, 13) == ("www.example.com", 19)

    def test_a_self_referential_pointer_terminates(self) -> None:
        """The case that hangs an implementation without a depth bound."""
        loop = b"\xc0\x00"
        with pytest.raises(DNSError, match="too deep|pointer"):
            decode_name(loop, 0)

    def test_a_pointer_past_the_end_is_refused(self) -> None:
        with pytest.raises(DNSError, match="past the end"):
            decode_name(b"\xc0\xff", 0)

    def test_a_name_running_past_the_end_is_refused(self) -> None:
        with pytest.raises(DNSError, match="past the end"):
            decode_name(b"\x07exam", 0)


# --- queries --------------------------------------------------------------


class TestQueryBuilding:
    def test_a_query_has_the_right_shape(self) -> None:
        raw = build_query("example.com", dnswire.A, txid=0xBEEF, edns0=False)
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[:12])
        assert (txid, flags, qd, an, ns, ar) == (0xBEEF, 0x0100, 1, 0, 0, 0)
        assert raw[12:] == b"\x07example\x03com\x00" + struct.pack("!HH", dnswire.A, 1)

    def test_recursion_is_requested_by_default(self) -> None:
        assert struct.unpack("!H", build_query("a.com", 1, edns0=False)[2:4])[0] & 0x0100

    def test_edns0_is_advertised_so_large_answers_fit_one_datagram(self) -> None:
        raw = build_query("example.com", dnswire.TXT)
        assert struct.unpack("!HHHHHH", raw[:12])[5] == 1
        assert struct.pack("!H", dnswire.EDNS0_PAYLOAD) in raw

    def test_the_query_id_varies(self) -> None:
        ids = {build_query("a.com", 1)[:2] for _ in range(8)}
        assert len(ids) > 1, "a fixed transaction id makes off-path spoofing trivial"


# --- responses ------------------------------------------------------------


def a_response(*records: bytes, txid=0x1234, rcode=0, flags_extra=0x8180) -> bytes:
    flags = (flags_extra & ~0x000F) | rcode
    return header(txid=txid, flags=flags, qd=1, an=len(records)) + (
        b"\x07example\x03com\x00" + struct.pack("!HH", dnswire.A, 1)
    ) + b"".join(records)


def rr(name: bytes, rtype: int, ttl: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


class TestRecordDecoding:
    def test_an_a_record(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.A, 300, bytes([93, 184, 216, 34])))
        )
        assert message.answers[0].data == "93.184.216.34"
        assert message.answers[0].name == "example.com"

    def test_an_aaaa_record(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.AAAA, 300, bytes.fromhex("2606" + "2800" * 7)))
        )
        assert message.answers[0].data.startswith("2606:")

    def test_a_cname_record(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.CNAME, 60, b"\x03cdn\xc0\x0c"))
        )
        assert message.answers[0].data == "cdn.example.com"

    def test_an_mx_record(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.MX, 3600, struct.pack("!H", 10) + b"\x01m\xc0\x0c"))
        )
        assert message.answers[0].data == (10, "m.example.com")
        assert message.answers[0].to_dict()["exchange"] == "m.example.com"

    def test_a_txt_record_with_multiple_strings(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.TXT, 60, b"\x03abc\x03def"))
        )
        assert message.answers[0].data == ["abc", "def"]

    def test_an_srv_record(self) -> None:
        message = parse_message(
            a_response(
                rr(b"\xc0\x0c", dnswire.SRV, 60,
                   struct.pack("!HHH", 1, 2, 443) + b"\x04mail\xc0\x0c")
            )
        )
        assert message.answers[0].data == (1, 2, 443, "mail.example.com")

    def test_a_caa_record(self) -> None:
        message = parse_message(
            a_response(rr(b"\xc0\x0c", dnswire.CAA, 60, b"\x00\x05issueletsencrypt.org"))
        )
        assert message.answers[0].data == (0, "issue", "letsencrypt.org")
        assert message.answers[0].to_dict()["tag"] == "issue"

    def test_an_unknown_type_is_reported_by_number_not_dropped(self) -> None:
        """Silently skipping a record looks like the record not existing."""
        message = parse_message(a_response(rr(b"\xc0\x0c", 99, 60, b"\x01\x02")))
        assert message.answers[0].type_name == "TYPE99"
        assert "raw" in message.answers[0].to_dict()

    def test_an_a_record_of_the_wrong_length_is_refused(self) -> None:
        with pytest.raises(DNSError, match="expected 4"):
            parse_message(a_response(rr(b"\xc0\x0c", dnswire.A, 60, b"\x01\x02\x03")))


class TestMessageParsing:
    def test_a_short_message_is_refused(self) -> None:
        with pytest.raises(DNSError, match="header is 12"):
            parse_message(b"\x00\x01")

    def test_a_query_is_not_parsed_as_a_response(self) -> None:
        with pytest.raises(DNSError, match="query, not a response"):
            parse_message(build_query("a.com", 1, edns0=False))

    def test_rcode_is_named(self) -> None:
        assert parse_message(a_response(rcode=3)).rcode_name == "NXDOMAIN"
        assert parse_message(a_response(rcode=2)).rcode_name == "SERVFAIL"

    def test_the_truncation_bit_is_read(self) -> None:
        """A truncated answer must be retried over TCP, not reported as the
        complete record set."""
        assert parse_message(a_response(flags_extra=0x8380)).truncated is True
        assert parse_message(a_response(flags_extra=0x8180)).truncated is False

    def test_record_data_claiming_more_than_the_message_holds_is_refused(self) -> None:
        # ancount must actually be 1, or the bogus record is never read
        raw = (
            header(qd=1, an=1)
            + b"\x07example\x03com\x00" + struct.pack("!HH", dnswire.A, 1)
            + b"\xc0\x0c" + struct.pack("!HHIH", dnswire.A, 1, 60, 999) + b"\x01\x02"
        )
        with pytest.raises(DNSError, match="message ends"):
            parse_message(raw)

    def test_a_truncated_question_section_is_refused(self) -> None:
        with pytest.raises(DNSError, match="truncated|question|runs past"):
            parse_message(header(qd=1) + b"\x07exam")

    def test_the_authority_section_is_parsed(self) -> None:
        """NXDOMAIN puts the SOA in authority, and that SOA is the evidence."""
        raw = (
            header(flags=0x8183, qd=1, an=0, ns=1)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", dnswire.A, 1)
            + rr(b"\xc0\x0c", dnswire.SOA, 60, b"\x00" * 20)
        )
        message = parse_message(raw)
        assert message.rcode_name == "NXDOMAIN"
        assert len(message.authority) == 1
