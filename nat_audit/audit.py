"""Audit orchestration: run the measurements, then score them.

Nothing in this module prints. It returns an :class:`AuditResult`, which
:mod:`nat_audit.report` renders as a text card or as JSON. Keeping the
measurement separate from the presentation is what makes the scoring
testable without a network.

What this tool can and cannot conclude
--------------------------------------
It determines **mapping behaviour** (RFC 5780 terminology): whether the NAT
reuses one external port across different destinations. That is detectable
from a single host, and it is the property that decides whether simple
hole-punching can work.

It does **not** determine filtering behaviour -- whether unsolicited
packets from a new peer are accepted. Distinguishing "full-cone" from
"restricted-cone" requires a server that can reply from an alternate
address and port (RFC 5780 CHANGE-REQUEST / OTHER-ADDRESS). Reporting those
labels from mapped addresses alone, as many scripts do, is guesswork. This
tool says "not tested" instead.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import netinfo, probes
from .stun import StunClient, StunError, StunResponse

__all__ = [
    "MappingBehaviour",
    "CarrierNat",
    "AuditConfig",
    "AuditResult",
    "classify_mapping",
    "score_audit",
    "run_audit",
]

DEFAULT_STUN_SERVERS: Tuple[Tuple[str, int], ...] = (
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 3478),
)

DEFAULT_LOCAL_PROBES: Tuple[probes.Probe, ...] = (
    probes.Probe("BDIX portal", "bdix.net", 80),
    probes.Probe("Local CDN edge", "www.bdix.net", 80),
)

DEFAULT_INTERNATIONAL_PROBES: Tuple[probes.Probe, ...] = (
    probes.Probe("Cloudflare DNS", "1.1.1.1", 53),
    probes.Probe("Google DNS", "8.8.8.8", 53),
)


class MappingBehaviour(object):
    """RFC 5780 mapping behaviour categories."""

    ENDPOINT_INDEPENDENT = "endpoint-independent"
    ENDPOINT_DEPENDENT = "endpoint-dependent"
    UNDETERMINED = "undetermined"
    BLOCKED = "udp-blocked"

    DESCRIPTIONS = {
        ENDPOINT_INDEPENDENT: "One external port reused for all destinations (P2P friendly)",
        ENDPOINT_DEPENDENT: "A different external port per destination (symmetric; blocks hole punching)",
        UNDETERMINED: "Too few distinct servers replied to compare mappings",
        BLOCKED: "No STUN server replied; outbound UDP appears to be blocked",
    }


class CarrierNat(object):
    """Whether the connection sits behind carrier-grade NAT."""

    DETECTED = "detected"
    NOT_DETECTED = "not-detected"
    UNKNOWN = "unknown"


def classify_mapping(responses: Sequence[StunResponse]) -> str:
    """Decide mapping behaviour from a set of Binding responses.

    The comparison is only valid across **distinct server addresses**: two
    replies from the same server say nothing about how the NAT treats a
    different destination. Hostnames that resolve to the same IP are
    therefore collapsed before the test.
    """
    if not responses:
        return MappingBehaviour.BLOCKED

    distinct_servers = {r.server_ip for r in responses}
    if len(distinct_servers) < 2:
        return MappingBehaviour.UNDETERMINED

    endpoints = {(r.mapped.ip, r.mapped.port) for r in responses}
    if len(endpoints) == 1:
        return MappingBehaviour.ENDPOINT_INDEPENDENT
    return MappingBehaviour.ENDPOINT_DEPENDENT


def detect_carrier_nat(responses: Sequence[StunResponse], local_ip: Optional[str]) -> Tuple[str, str]:
    """Report whether CGNAT is visible, and say why.

    A positive result is trustworthy: an RFC 6598 address on the public
    side means carrier NAT. A negative result is weaker, and is reported as
    such -- an operator can perfectly well run carrier NAT on ordinary
    public address space, and no client-side test can rule that out.
    """
    if not responses:
        return CarrierNat.UNKNOWN, "No public address observed (no STUN reply)."

    public_ips = {r.mapped.ip for r in responses}
    if any(netinfo.is_carrier_grade(ip) for ip in public_ips):
        return (
            CarrierNat.DETECTED,
            "Public address is in RFC 6598 shared space (100.64.0.0/10): carrier-grade NAT.",
        )
    if netinfo.is_carrier_grade(local_ip):
        return (
            CarrierNat.DETECTED,
            "This host holds an RFC 6598 address directly.",
        )
    return (
        CarrierNat.NOT_DETECTED,
        "Public address is ordinary routable space; carrier NAT on public ranges cannot be ruled out from the client.",
    )


@dataclass
class AuditConfig:
    """Everything the audit needs to know before it starts."""

    stun_servers: Sequence[Tuple[str, int]] = DEFAULT_STUN_SERVERS
    local_probes: Sequence[probes.Probe] = DEFAULT_LOCAL_PROBES
    international_probes: Sequence[probes.Probe] = DEFAULT_INTERNATIONAL_PROBES
    local_group_name: str = "BDIX / local peering"
    international_group_name: str = "International"
    stun_timeout: float = 2.5
    probe_timeout: float = 1.5
    samples: int = 4
    source_port: int = 0
    operator_lookup: bool = False
    operator_endpoint: str = netinfo.DEFAULT_OPERATOR_ENDPOINT


# --- Scoring -----------------------------------------------------------
#
# The rubric is published rather than hidden inside the code, so a reader
# can disagree with the weights instead of wondering where a letter came
# from. Each component is reported alongside the total.

MAPPING_POINTS = {
    MappingBehaviour.ENDPOINT_INDEPENDENT: 50,
    MappingBehaviour.UNDETERMINED: 25,
    MappingBehaviour.ENDPOINT_DEPENDENT: 15,
    MappingBehaviour.BLOCKED: 0,
}

CARRIER_POINTS = {
    CarrierNat.NOT_DETECTED: 25,
    CarrierNat.UNKNOWN: 15,
    CarrierNat.DETECTED: 5,
}

GRADE_BANDS = ((85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F"))


def peering_points(ratio: Optional[float]) -> Tuple[int, str]:
    """Score how much better local peering is than international transit."""
    if ratio is None:
        return 0, "Local peering not measurable"
    if ratio >= 2.0:
        return 25, "Local routes are much faster than international transit"
    if ratio >= 1.2:
        return 18, "Local routes are somewhat faster than international transit"
    if ratio >= 0.9:
        return 10, "Local and international latency are comparable"
    return 5, "Local routes are slower than international transit (likely no local peering)"


def grade_for(score: int) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


@dataclass
class AuditResult:
    """The full outcome of one audit run."""

    started_at: str
    local_ip: str
    local_ip_class: str
    local_source_port: int
    stun_responses: List[StunResponse] = field(default_factory=list)
    stun_failures: List[Tuple[str, str]] = field(default_factory=list)
    mapping: str = MappingBehaviour.BLOCKED
    carrier_nat: str = CarrierNat.UNKNOWN
    carrier_reason: str = ""
    public_ip: Optional[str] = None
    local_group: Optional[probes.GroupResult] = None
    international_group: Optional[probes.GroupResult] = None
    operator: Optional[netinfo.Operator] = None
    score: int = 0
    grade: str = "F"
    score_breakdown: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def peering_ratio(self) -> Optional[float]:
        """International median divided by local median.

        ``2.0`` means international destinations are twice as far away in
        latency terms as local ones, which is the signature of working
        local peering. ``None`` means one side was unreachable and no
        honest comparison exists.
        """
        if self.local_group is None or self.international_group is None:
            return None
        local = self.local_group.median_ms
        intl = self.international_group.median_ms
        if not local or not intl or local <= 0:
            return None
        return intl / local

    @property
    def observed_ports(self) -> List[int]:
        return [r.mapped.port for r in self.stun_responses]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": "nat-audit/1",
            "started_at": self.started_at,
            "local": {
                "ip": self.local_ip,
                "class": self.local_ip_class,
                "source_port": self.local_source_port,
            },
            "nat": {
                "mapping_behaviour": self.mapping,
                "mapping_description": MappingBehaviour.DESCRIPTIONS.get(self.mapping, ""),
                "filtering_behaviour": "not-tested",
                "carrier_grade_nat": self.carrier_nat,
                "carrier_grade_reason": self.carrier_reason,
                "public_ip": self.public_ip,
                "observed_external_ports": self.observed_ports,
            },
            "stun": {
                "responses": [
                    {
                        "server": r.server,
                        "server_ip": r.server_ip,
                        "mapped_ip": r.mapped.ip,
                        "mapped_port": r.mapped.port,
                        "rtt_ms": round(r.rtt_ms, 2),
                        "attribute": r.attribute,
                    }
                    for r in self.stun_responses
                ],
                "failures": [{"server": s, "error": e} for s, e in self.stun_failures],
            },
            "latency": {
                "local": self.local_group.to_dict() if self.local_group else None,
                "international": self.international_group.to_dict() if self.international_group else None,
                "peering_ratio": round(self.peering_ratio, 2) if self.peering_ratio else None,
            },
            "operator": {
                "name": self.operator.name if self.operator else None,
                "asn": self.operator.asn if self.operator else None,
                "country": self.operator.country if self.operator else None,
                "source": self.operator.source if self.operator else None,
                "error": self.operator.error if self.operator else None,
            }
            if self.operator
            else None,
            "assessment": {
                "score": self.score,
                "grade": self.grade,
                "breakdown": self.score_breakdown,
                "notes": self.notes,
            },
        }


def score_audit(result: AuditResult) -> AuditResult:
    """Apply the published rubric to a measured result, in place."""
    mapping_score = MAPPING_POINTS.get(result.mapping, 0)
    carrier_score = CARRIER_POINTS.get(result.carrier_nat, 0)
    peering_score, peering_reason = peering_points(result.peering_ratio)

    result.score_breakdown = [
        {
            "component": "NAT mapping behaviour",
            "points": mapping_score,
            "max": 50,
            "reason": MappingBehaviour.DESCRIPTIONS.get(result.mapping, ""),
        },
        {
            "component": "Carrier-grade NAT",
            "points": carrier_score,
            "max": 25,
            "reason": result.carrier_reason,
        },
        {
            "component": "Local peering advantage",
            "points": peering_score,
            "max": 25,
            "reason": peering_reason,
        },
    ]
    result.score = mapping_score + carrier_score + peering_score
    result.grade = grade_for(result.score)

    notes: List[str] = []
    if result.mapping == MappingBehaviour.BLOCKED:
        notes.append(
            "No STUN server replied. Either outbound UDP is filtered, or a local "
            "firewall is dropping the responses. Peer-to-peer applications will "
            "need a relay (TURN) on this connection."
        )
    elif result.mapping == MappingBehaviour.ENDPOINT_DEPENDENT:
        notes.append(
            "Endpoint-dependent mapping means each destination sees a different "
            "external port, so hole punching fails and P2P traffic must be relayed."
        )
    elif result.mapping == MappingBehaviour.UNDETERMINED:
        notes.append(
            "Fewer than two distinct STUN servers replied, so mapping behaviour "
            "could not be compared. Re-run, or pass --stun to add servers."
        )
    if result.carrier_nat == CarrierNat.DETECTED:
        notes.append(
            "Behind carrier-grade NAT the public address is shared, so inbound "
            "port forwarding is not available from the router alone."
        )
    ratio = result.peering_ratio
    if ratio is not None and ratio < 0.9:
        notes.append(
            "Local endpoints are slower than international ones, which usually "
            "means local traffic is being carried over international transit."
        )
    notes.append("Filtering behaviour (full-cone vs restricted) is not tested; it needs an RFC 5780 server.")
    result.notes = notes
    return result


def run_audit(config: Optional[AuditConfig] = None) -> AuditResult:
    """Run the complete audit and return a scored :class:`AuditResult`."""
    config = config or AuditConfig()
    local_ip = netinfo.detect_local_address()

    result = AuditResult(
        started_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        local_ip=local_ip,
        local_ip_class=netinfo.classify_address(local_ip),
        local_source_port=0,
    )

    try:
        with StunClient(timeout=config.stun_timeout, source_port=config.source_port) as client:
            result.local_source_port = client.local_port
            responses, failures = client.survey(config.stun_servers)
    except (StunError, OSError) as exc:
        responses, failures = [], [("socket", str(exc))]

    result.stun_responses = list(responses)
    result.stun_failures = list(failures)
    result.mapping = classify_mapping(responses)
    result.carrier_nat, result.carrier_reason = detect_carrier_nat(responses, local_ip)
    if responses:
        result.public_ip = responses[0].mapped.ip

    result.local_group = probes.measure_group(
        config.local_group_name, config.local_probes, config.samples, config.probe_timeout
    )
    result.international_group = probes.measure_group(
        config.international_group_name, config.international_probes, config.samples, config.probe_timeout
    )

    if config.operator_lookup:
        result.operator = netinfo.lookup_operator(config.operator_endpoint)

    return score_audit(result)
