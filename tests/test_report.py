"""Tests for output rendering and redaction."""

import json
import unittest

from nat_audit.audit import AuditResult, CarrierNat, MappingBehaviour, score_audit
from nat_audit.report import redact_ip, render_json, render_text
from nat_audit.stun import MappedAddress, StunResponse


class RedactionTests(unittest.TestCase):
    def test_masks_host_portion_of_ipv4(self):
        self.assertEqual(redact_ip("203.0.113.45"), "203.0.x.x")

    def test_masks_ipv6(self):
        self.assertEqual(redact_ip("2001:db8:1:2::1"), "2001:db8:1:x")

    def test_passes_through_missing_and_invalid(self):
        self.assertIsNone(redact_ip(None))
        self.assertEqual(redact_ip("not an ip"), "not an ip")


class RenderingTests(unittest.TestCase):
    def _result(self):
        result = AuditResult(
            started_at="2026-01-01T00:00:00+00:00",
            local_ip="192.168.0.10",
            local_ip_class="private",
            local_source_port=51234,
            mapping=MappingBehaviour.ENDPOINT_INDEPENDENT,
            carrier_nat=CarrierNat.NOT_DETECTED,
            carrier_reason="ordinary routable space",
            public_ip="203.0.113.45",
        )
        result.stun_responses = [
            StunResponse("a.example", "192.0.2.1", 3478, MappedAddress("203.0.113.45", 40000), 12.0, "XOR-MAPPED-ADDRESS")
        ]
        return score_audit(result)

    def test_text_report_contains_key_fields(self):
        text = render_text(self._result())
        self.assertIn("CONSUMER ISP TRANSPARENCY REPORT CARD", text)
        self.assertIn("203.0.113.45", text)
        self.assertIn("not tested", text)
        self.assertIn("grade", text)

    def test_text_report_redacts(self):
        text = render_text(self._result(), redact=True)
        self.assertNotIn("203.0.113.45", text)
        self.assertIn("203.0.x.x", text)

    def test_text_report_lines_fit_the_card(self):
        for line in render_text(self._result()).splitlines():
            self.assertLessEqual(len(line), 80, line)

    def test_json_is_valid_and_versioned(self):
        payload = json.loads(render_json(self._result()))
        self.assertEqual(payload["schema"], "nat-audit/1")
        self.assertEqual(payload["nat"]["mapping_behaviour"], MappingBehaviour.ENDPOINT_INDEPENDENT)
        self.assertEqual(payload["nat"]["public_ip"], "203.0.113.45")

    def test_json_redaction_covers_nested_responses(self):
        payload = json.loads(render_json(self._result(), redact=True))
        self.assertEqual(payload["nat"]["public_ip"], "203.0.x.x")
        self.assertEqual(payload["stun"]["responses"][0]["mapped_ip"], "203.0.x.x")


if __name__ == "__main__":
    unittest.main()
