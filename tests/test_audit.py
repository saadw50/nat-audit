"""Tests for mapping classification, CGNAT detection and scoring."""

import unittest

from nat_audit.audit import (
    AuditResult,
    CarrierNat,
    MappingBehaviour,
    classify_mapping,
    detect_carrier_nat,
    grade_for,
    peering_points,
    score_audit,
)
from nat_audit.probes import GroupResult, Probe, ProbeResult
from nat_audit.stun import MappedAddress, StunResponse


def response(server, server_ip, mapped_ip, mapped_port):
    return StunResponse(
        server=server,
        server_ip=server_ip,
        server_port=3478,
        mapped=MappedAddress(mapped_ip, mapped_port),
        rtt_ms=12.0,
        attribute="XOR-MAPPED-ADDRESS",
    )


class MappingClassificationTests(unittest.TestCase):
    def test_no_responses_means_blocked(self):
        self.assertEqual(classify_mapping([]), MappingBehaviour.BLOCKED)

    def test_single_response_is_undetermined_not_open(self):
        """One reply means the other servers timed out.

        Treating that as the best possible result -- an open, full-cone NAT
        -- inverts the meaning of a failure.
        """
        single = [response("a.example", "192.0.2.1", "203.0.113.5", 40000)]
        self.assertEqual(classify_mapping(single), MappingBehaviour.UNDETERMINED)

    def test_same_port_across_distinct_servers_is_endpoint_independent(self):
        responses = [
            response("a.example", "192.0.2.1", "203.0.113.5", 40000),
            response("b.example", "198.51.100.1", "203.0.113.5", 40000),
        ]
        self.assertEqual(classify_mapping(responses), MappingBehaviour.ENDPOINT_INDEPENDENT)

    def test_differing_ports_are_endpoint_dependent(self):
        responses = [
            response("a.example", "192.0.2.1", "203.0.113.5", 40000),
            response("b.example", "198.51.100.1", "203.0.113.5", 40001),
        ]
        self.assertEqual(classify_mapping(responses), MappingBehaviour.ENDPOINT_DEPENDENT)

    def test_two_hostnames_on_one_server_ip_cannot_decide(self):
        """Two names for the same box is not a two-destination test."""
        responses = [
            response("a.example", "192.0.2.1", "203.0.113.5", 40000),
            response("alias.example", "192.0.2.1", "203.0.113.5", 40000),
        ]
        self.assertEqual(classify_mapping(responses), MappingBehaviour.UNDETERMINED)


class CarrierNatTests(unittest.TestCase):
    def test_public_address_in_shared_space_is_cgnat(self):
        responses = [response("a.example", "192.0.2.1", "100.88.12.4", 40000)]
        status, reason = detect_carrier_nat(responses, "192.168.0.10")
        self.assertEqual(status, CarrierNat.DETECTED)
        self.assertIn("6598", reason)

    def test_ordinary_public_address_is_not_detected(self):
        responses = [response("a.example", "192.0.2.1", "203.0.113.5", 40000)]
        status, _ = detect_carrier_nat(responses, "192.168.0.10")
        self.assertEqual(status, CarrierNat.NOT_DETECTED)

    def test_host_holding_shared_address_directly(self):
        responses = [response("a.example", "192.0.2.1", "203.0.113.5", 40000)]
        status, _ = detect_carrier_nat(responses, "100.70.0.9")
        self.assertEqual(status, CarrierNat.DETECTED)

    def test_no_responses_is_unknown_not_clean(self):
        status, _ = detect_carrier_nat([], "192.168.0.10")
        self.assertEqual(status, CarrierNat.UNKNOWN)


class ScoringTests(unittest.TestCase):
    def _result(self, mapping, carrier, local_ms, intl_ms):
        result = AuditResult(
            started_at="2026-01-01T00:00:00+00:00",
            local_ip="192.168.0.10",
            local_ip_class="private",
            local_source_port=51234,
            mapping=mapping,
            carrier_nat=carrier,
            carrier_reason="test",
        )
        result.local_group = self._group("local", local_ms)
        result.international_group = self._group("intl", intl_ms)
        return result

    @staticmethod
    def _group(name, value):
        group = GroupResult(name=name)
        if value is not None:
            probe_result = ProbeResult(probe=Probe(name, "example.net", 80))
            probe_result.samples = [value]
            probe_result.resolved_ip = "192.0.2.1"
            group.results.append(probe_result)
        return group

    def test_grade_bands(self):
        self.assertEqual(grade_for(100), "A")
        self.assertEqual(grade_for(85), "A")
        self.assertEqual(grade_for(84), "B")
        self.assertEqual(grade_for(55), "C")
        self.assertEqual(grade_for(0), "F")

    def test_best_case_scores_an_a(self):
        result = score_audit(
            self._result(MappingBehaviour.ENDPOINT_INDEPENDENT, CarrierNat.NOT_DETECTED, 5.0, 120.0)
        )
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A")

    def test_blocked_udp_behind_cgnat_scores_an_f(self):
        result = score_audit(self._result(MappingBehaviour.BLOCKED, CarrierNat.DETECTED, 5.0, 120.0))
        self.assertLess(result.score, 40)
        self.assertEqual(result.grade, "F")

    def test_breakdown_sums_to_score(self):
        result = score_audit(
            self._result(MappingBehaviour.ENDPOINT_DEPENDENT, CarrierNat.DETECTED, 40.0, 45.0)
        )
        self.assertEqual(sum(item["points"] for item in result.score_breakdown), result.score)

    def test_peering_ratio_is_none_when_one_side_unreachable(self):
        result = self._result(MappingBehaviour.ENDPOINT_INDEPENDENT, CarrierNat.NOT_DETECTED, None, 120.0)
        self.assertIsNone(result.peering_ratio)
        scored = score_audit(result)
        self.assertEqual(scored.score_breakdown[2]["points"], 0)

    def test_local_slower_than_international_is_penalised(self):
        points, reason = peering_points(0.5)
        self.assertEqual(points, 5)
        self.assertIn("slower", reason)

    def test_filtering_is_always_declared_untested(self):
        result = score_audit(
            self._result(MappingBehaviour.ENDPOINT_INDEPENDENT, CarrierNat.NOT_DETECTED, 5.0, 120.0)
        )
        self.assertEqual(result.to_dict()["nat"]["filtering_behaviour"], "not-tested")
        self.assertTrue(any("Filtering behaviour" in note for note in result.notes))


if __name__ == "__main__":
    unittest.main()
