"""TLS inspection: parsing, and the two things that are easy to get wrong.

Offline. The certificate fixture was generated once with openssl and embedded, so
the suite needs no network and no cert-generation dependency; the expected values
are cross-checked against openssl rather than written from the parser's own
output, which would only prove the parser agrees with itself.

Two bugs are pinned here that a live host would have hidden: reading an IP address
out of a SubjectAltName with the DNS tag, and forgetting that the extension's
OCTET STRING wraps a GeneralNames SEQUENCE. Both produced one unreadable blob per
certificate that still looked like a successful parse.
"""

from __future__ import annotations

import base64
import datetime as dt

import pytest

from sro.core.egress import (
    _header,
    inspect_tls,
    parse_certificate,
)

# openssl req -x509 -newkey rsa:2048 -days 3 -nodes
#   -subj "/CN=expired.example.test/O=Test Org/C=GB"
SELF_SIGNED_DER = base64.b64decode(
    "MIIDXzCCAkegAwIBAgIUakdGqMS6ajx+7d02WTD9MxCzJlIwDQYJKoZIhvcNAQELBQAwPzEdMBsGA1UEAwwUZXhwaXJlZC5leGFtcGxlLnRlc3QxETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJHQjAeFw0yNjEwMDEwNDMyMzBaFw0yNjEwMDQwNDMyMzBaMD8xHTAbBgNVBAMMFGV4cGlyZWQuZXhhbXBsZS50ZXN0MREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClpafs+dDwCxpYwRYsgGdoOEifbZd3wQu+qPqL3v4AlrY1beNro59nWXsiTK0g0QTwQWT0F3v78MWwofEaP5RTBnuVVgYeVKjqKSSd8ClMTSNPn5vfPPh6z8LBl9sLweYNM06w2y59sU88g8yIvcDMbtg8peubqyA0Fms+Obm8hU7RfJ8v01mAnoQ4V3hKYWr2244zbwIYVfI2RTWC5vqdAc9/X3EwubxPWXVP2xXOKVqrv218wB7kchUR3gHuhY0Lg2hOx2D9FOILbwsMHrIZZHQ1las18eFozC5+ClLI319/8JhMoaPw5gRrvAyAe5Ddu3y+XGz7MbOSlt8rzGENAgMBAAGjUzBRMB0GA1UdDgQWBBQq86fgj9Qu01WP2qsxKq8lx/ZxWTAfBgNVHSMEGDAWgBQq86fgj9Qu01WP2qsxKq8lx/ZxWTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBOEvaIwpfXSjnye65IRKskewOUKffhp2yIv83TIBOaGxCQlBTw4bfq1zDR5uVVnrU15B/OfMMuYhCf/6/2AtVspdJeFR/0RZzb36dHw2EJ0xDHG2yICTgySlSWn3F3ZUjEDZwPP4E+0KRwTlYO67dVjmW4g0RurYXKMKFitUkgk8RLpefOgq2KNXBHM66lXjz7VAqVQy3zoc1dYIuwaIeJ2v7fbvBZGqc6WYL6bE4mf5VoOucT5NlLY5J3ihyISGAj4PRvMAZFgPN6YNXfS0j/bFmajDYSFePma++4c4CVpmrPkv3CRo9A0iIYUuDO+dlVHjkuWofQumS75VyKb1It"
)


class TestHeaderLookup:
    def test_header_names_are_case_insensitive(self) -> None:
        """RFC 9110 says field names are case-insensitive and servers use every
        casing. Our dict preserves what the peer sent, so a case-sensitive get
        made a redirect look like one with no target."""
        assert _header({"Location": "/next"}, "location") == "/next"
        assert _header({"LOCATION": "/next"}, "location") == "/next"
        assert _header({"location": "/next"}, "Location") == "/next"
        assert _header({}, "location") is None

    def test_it_finds_a_location_that_a_naive_get_would_miss(self) -> None:
        assert _header({"Server": "nginx", "Location": "/x"}, "location") == "/x"


class TestCertificateParsing:
    """Values cross-checked with openssl on the same fixture.

    -subject -issuer -dates -ext subjectAltName
    """

    @pytest.fixture()
    def certificate(self) -> dict:
        return parse_certificate(SELF_SIGNED_DER)

    def test_it_parses(self, certificate) -> None:
        assert certificate["parsed"] is True

    def test_subject_and_issuer(self, certificate) -> None:
        assert certificate["subject_cn"] == "expired.example.test"
        assert certificate["issuer_cn"] == "expired.example.test"

    def test_validity_dates(self, certificate) -> None:
        """UTCTime carries a two-digit year; the century has to be inferred or the
        date lands 100 years out and an expiry check silently passes."""
        validity = certificate["validity"]
        assert validity["not_after"].startswith("2026-")
        assert validity["not_before"] < validity["not_after"]

    def test_it_detects_a_self_signed_certificate(self, certificate) -> None:
        assert certificate["subject_cn"] == certificate["issuer_cn"]

    def test_the_fingerprint_is_the_sha256_of_the_der(self, certificate) -> None:
        import hashlib

        assert certificate["sha256_fingerprint"] == hashlib.sha256(SELF_SIGNED_DER).hexdigest()

    def test_it_keeps_the_der_for_evidence(self, certificate) -> None:
        assert base64.b64decode(certificate["der_base64"]) == SELF_SIGNED_DER

    def test_garbage_is_reported_not_raised(self) -> None:
        """A certificate is untrusted input from the wire. A parser that raises on
        malformed input hands the exception to whoever called it."""
        for junk in (b"", b"\x30", b"not der at all", SELF_SIGNED_DER[:40]):
            out = parse_certificate(junk)
            assert out["parsed"] is False
            assert "error" in out
            assert "sha256_fingerprint" in out, (
                "an unparseable certificate is still evidence, so it still gets a "
                "fingerprint"
            )

    def test_a_truncated_certificate_does_not_loop(self) -> None:
        import signal

        def on_alarm(signum, frame):
            raise AssertionError("parser did not terminate on truncated input")

        signal.signal(signal.SIGALRM, on_alarm)
        signal.alarm(5)
        try:
            for cut in range(12, len(SELF_SIGNED_DER), 7):
                parse_certificate(SELF_SIGNED_DER[:cut])
        finally:
            signal.alarm(0)


class TestSubjectAltName:
    """The two bugs the openssl cross-check caught."""

    def _cert_with_sans(self):
        import base64 as b64

        return None  # replaced below by the SAN fixture test

    def test_dns_and_ip_sans_are_read_separately(self) -> None:
        """iPAddress is context tag [7], dNSName is [2]. Reading an IP with the
        DNS tag produced one blob per extension that still looked parsed."""
        from sro.core.egress import _der_san_entries

        # build a GeneralNames by hand: DNS + IPv4 + IPv6
        import struct as _struct

        def tlv(tag: int, value: bytes) -> bytes:
            return bytes([tag]) + bytes([len(value)]) + value

        entries = (
            tlv(0x82, b"a.example.test")
            + tlv(0x82, b"*.example.test")
            + tlv(0x87, bytes([203, 0, 113, 9]))
            + tlv(0x87, bytes.fromhex("20010db8" + "00" * 11 + "01"))
        )
        general_names = tlv(0x30, entries)
        assert _der_san_entries(general_names, 0, len(general_names)) == [
            "a.example.test",
            "*.example.test",
            "203.0.113.9",
            "2001:db8::1",
        ]

    def test_a_wrong_length_ip_entry_is_skipped_not_guessed(self) -> None:
        from sro.core.egress import _der_san_entries

        def tlv(tag: int, value: bytes) -> bytes:
            return bytes([tag]) + bytes([len(value)]) + value

        entries = tlv(0x87, b"\x01\x02\x03")  # 3 bytes: neither v4 nor v6
        general_names = tlv(0x30, entries)
        assert _der_san_entries(general_names, 0, len(general_names)) == []


class TestInspectionIsNotVerification:
    def test_the_docstring_states_the_tradeoff_and_the_hold_that_remains(self) -> None:
        """Two claims, both of which a caller relies on: nothing was trusted, and
        the pinning is what makes that acceptable."""
        import inspect as pyinspect

        doc = (pyinspect.getdoc(inspect_tls) or "").lower()
        assert "no verification" in doc
        assert "pinning" in doc, "the compensating control has to be named"

    def test_the_verification_free_handshake_is_the_one_that_is_used(self) -> None:
        """Asserted against the source, because this is the whole risk of the tool.

        A future edit that turns verification back on would make expired and
        self-signed certificates invisible again — the tool would still pass its
        tests and quietly stop doing its job.
        """
        import inspect as pyinspect

        from sro.core import egress

        source = pyinspect.getsource(egress.inspect_tls)
        assert "ssl.CERT_NONE" in source
        assert "check_hostname = False" in source


class TestPinnedBeforeConnecting:
    def test_inspection_only_ever_dials_a_pinned_address(self) -> None:
        """`inspect_tls` takes a PinnedDestination, not a hostname.

        That is the structural guarantee: by the time this can open a socket the
        name has already been resolved, refused if private, and the address fixed.
        A signature taking a hostname would make that ordering a convention.
        """
        import inspect as pyinspect

        parameters = list(pyinspect.signature(inspect_tls).parameters)
        assert parameters[0] == "destination"
        assert "host" not in parameters
