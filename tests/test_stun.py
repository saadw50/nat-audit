"""Tests for the STUN message parser.

These run entirely offline: STUN messages are built byte by byte and fed
to the parser, which is the only way to test the cases that matter -- a
hostile or unusual server is not something you can arrange on demand.
"""

import struct
import unittest

from nat_audit.stun import (
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    BINDING_ERROR,
    BINDING_SUCCESS,
    FAMILY_IPV4,
    FAMILY_IPV6,
    MAGIC_COOKIE,
    StunError,
    build_binding_request,
    iter_attributes,
    parse_binding_response,
)

TID = b"\xaa\xbb\xcc\xdd\x11\x22\x33\x44\x55\x66\x77\x88"


def attribute(attr_type, value):
    """Encode one attribute with its 4-byte alignment padding."""
    padding = b"\x00" * (-len(value) % 4)
    return struct.pack("!HH", attr_type, len(value)) + value + padding


def mapped_value(ip_bytes, port, family=FAMILY_IPV4):
    return struct.pack("!BBH", 0, family, port) + ip_bytes


def xor_mapped_value(ip_bytes, port, tid=TID, family=FAMILY_IPV4):
    key = struct.pack("!I", MAGIC_COOKIE) + tid
    xored = bytes(a ^ b for a, b in zip(ip_bytes, key))
    return struct.pack("!BBH", 0, family, port ^ (MAGIC_COOKIE >> 16)) + xored


def message(msg_type, body, tid=TID, cookie=MAGIC_COOKIE):
    return struct.pack("!HHI12s", msg_type, len(body), cookie, tid) + body


class BindingRequestTests(unittest.TestCase):
    def test_request_is_well_formed(self):
        packet, tid = build_binding_request()
        self.assertEqual(len(packet), 20)
        msg_type, length, cookie = struct.unpack("!HHI", packet[:8])
        self.assertEqual(msg_type, 0x0001)
        self.assertEqual(length, 0)
        self.assertEqual(cookie, MAGIC_COOKIE)
        self.assertEqual(packet[8:], tid)

    def test_transaction_ids_are_random(self):
        _, first = build_binding_request()
        _, second = build_binding_request()
        self.assertNotEqual(first, second)

    def test_rejects_wrong_length_transaction_id(self):
        with self.assertRaises(ValueError):
            build_binding_request(b"tooshort")


class AttributeWalkTests(unittest.TestCase):
    def test_walks_padded_attributes(self):
        body = attribute(0x8022, b"demo") + attribute(0x0020, b"\x00\x01\x02\x03\x04\x05\x06\x07")
        attrs = list(iter_attributes(message(BINDING_SUCCESS, body)))
        self.assertEqual([a[0] for a in attrs], [0x8022, 0x0020])

    def test_odd_length_attribute_padding_is_skipped(self):
        # A 5-byte value is followed by 3 bytes of padding that are not
        # counted in the declared length. Mishandling this desynchronises
        # the whole walk.
        body = attribute(0x8022, b"abcde") + attribute(0x0020, b"\x00" * 8)
        attrs = list(iter_attributes(message(BINDING_SUCCESS, body)))
        self.assertEqual([a[0] for a in attrs], [0x8022, 0x0020])
        self.assertEqual(attrs[0][1], b"abcde")

    def test_truncated_attribute_does_not_over_read(self):
        body = struct.pack("!HH", 0x0020, 40) + b"\x00\x00"
        self.assertEqual(list(iter_attributes(message(BINDING_SUCCESS, body))), [])


class ParseBindingResponseTests(unittest.TestCase):
    def test_mapped_address_first_still_parses_correctly(self):
        """The regression this project exists for.

        Several public servers emit MAPPED-ADDRESS before
        XOR-MAPPED-ADDRESS. A parser that reads a fixed offset picks up the
        un-obfuscated port, XORs it anyway, and returns a wrong number that
        still looks like a plausible port.
        """
        ip = bytes([203, 0, 113, 45])
        port = 54321
        body = attribute(ATTR_MAPPED_ADDRESS, mapped_value(ip, port)) + attribute(
            ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value(ip, port)
        )
        address, source = parse_binding_response(message(BINDING_SUCCESS, body), TID)
        self.assertEqual(address.port, port)
        self.assertEqual(address.ip, "203.0.113.45")
        self.assertEqual(source, "XOR-MAPPED-ADDRESS")

        # Demonstrate what the naive fixed-offset read would have produced.
        raw = struct.unpack("!H", message(BINDING_SUCCESS, body)[26:28])[0]
        self.assertNotEqual(raw ^ (MAGIC_COOKIE >> 16), port)

    def test_falls_back_to_plain_mapped_address(self):
        ip = bytes([198, 51, 100, 7])
        body = attribute(ATTR_MAPPED_ADDRESS, mapped_value(ip, 4096))
        address, source = parse_binding_response(message(BINDING_SUCCESS, body), TID)
        self.assertEqual((address.ip, address.port), ("198.51.100.7", 4096))
        self.assertEqual(source, "MAPPED-ADDRESS")

    def test_skips_unknown_attributes_before_the_address(self):
        ip = bytes([192, 0, 2, 9])
        body = (
            attribute(0x8022, b"Vendor STUN Server 1.2")
            + attribute(0x802B, mapped_value(bytes([192, 0, 2, 1]), 3478))
            + attribute(ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value(ip, 1234))
        )
        address, _ = parse_binding_response(message(BINDING_SUCCESS, body), TID)
        self.assertEqual((address.ip, address.port), ("192.0.2.9", 1234))

    def test_parses_ipv6_xor_mapped_address(self):
        ip = bytes.fromhex("20010db8000000000000000000000001")
        body = attribute(ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value(ip, 9000, family=FAMILY_IPV6))
        address, _ = parse_binding_response(message(BINDING_SUCCESS, body), TID)
        self.assertEqual(address.port, 9000)
        self.assertEqual(address.family, FAMILY_IPV6)
        self.assertEqual(address.ip, "2001:db8::1")

    def test_rejects_transaction_id_mismatch(self):
        body = attribute(ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value(bytes([1, 2, 3, 4]), 100))
        with self.assertRaises(StunError):
            parse_binding_response(message(BINDING_SUCCESS, body), b"\x00" * 12)

    def test_rejects_bad_magic_cookie(self):
        body = attribute(ATTR_XOR_MAPPED_ADDRESS, xor_mapped_value(bytes([1, 2, 3, 4]), 100))
        raw = message(BINDING_SUCCESS, body, cookie=0xDEADBEEF)
        with self.assertRaises(StunError):
            parse_binding_response(raw, TID)

    def test_reports_error_response(self):
        body = attribute(0x0009, struct.pack("!BBBB", 0, 0, 4, 1) + b"Unauthorized")
        with self.assertRaises(StunError) as ctx:
            parse_binding_response(message(BINDING_ERROR, body), TID)
        self.assertIn("401", str(ctx.exception))

    def test_rejects_response_without_address(self):
        body = attribute(0x8022, b"nothing useful")
        with self.assertRaises(StunError):
            parse_binding_response(message(BINDING_SUCCESS, body), TID)

    def test_rejects_runt_datagram(self):
        with self.assertRaises(StunError):
            parse_binding_response(b"\x01\x01", TID)


if __name__ == "__main__":
    unittest.main()
