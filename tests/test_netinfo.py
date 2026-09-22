"""Tests for address classification.

The boundary cases are the point. Prefix-string tests like
``ip.startswith("100.")`` get every one of these wrong.
"""

import unittest

from nat_audit.netinfo import AddressClass, classify_address, is_carrier_grade


class ClassifyAddressTests(unittest.TestCase):
    def test_rfc1918_ranges(self):
        for address in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255"):
            self.assertEqual(classify_address(address), AddressClass.PRIVATE, address)

    def test_addresses_adjacent_to_rfc1918_are_public(self):
        for address in ("172.15.255.255", "172.32.0.1", "11.0.0.1", "192.169.0.1"):
            self.assertEqual(classify_address(address), AddressClass.PUBLIC, address)

    def test_cgnat_range_boundaries(self):
        # RFC 6598 reserves 100.64.0.0/10, not 100.0.0.0/8.
        self.assertEqual(classify_address("100.64.0.0"), AddressClass.CGNAT)
        self.assertEqual(classify_address("100.127.255.255"), AddressClass.CGNAT)
        self.assertEqual(classify_address("100.63.255.255"), AddressClass.PUBLIC)
        self.assertEqual(classify_address("100.128.0.0"), AddressClass.PUBLIC)

    def test_loopback_and_link_local(self):
        self.assertEqual(classify_address("127.0.0.1"), AddressClass.LOOPBACK)
        self.assertEqual(classify_address("169.254.1.1"), AddressClass.LINK_LOCAL)

    def test_invalid_and_missing(self):
        self.assertEqual(classify_address("not an ip"), AddressClass.UNKNOWN)
        self.assertEqual(classify_address(None), AddressClass.UNKNOWN)
        self.assertEqual(classify_address(""), AddressClass.UNKNOWN)

    def test_ipv6(self):
        self.assertEqual(classify_address("2606:4700:4700::1111"), AddressClass.PUBLIC)
        self.assertEqual(classify_address("::1"), AddressClass.LOOPBACK)
        self.assertEqual(classify_address("fd00::1"), AddressClass.PRIVATE)
        self.assertEqual(classify_address("fe80::1"), AddressClass.LINK_LOCAL)
        # 2001:db8::/32 is the documentation range, which is reserved, not public.
        self.assertEqual(classify_address("2001:db8::1"), AddressClass.PRIVATE)


class CarrierGradeTests(unittest.TestCase):
    def test_detects_only_the_reserved_range(self):
        self.assertTrue(is_carrier_grade("100.100.50.1"))
        self.assertFalse(is_carrier_grade("100.50.50.1"))
        self.assertFalse(is_carrier_grade("192.168.0.1"))
        self.assertFalse(is_carrier_grade(None))


if __name__ == "__main__":
    unittest.main()
