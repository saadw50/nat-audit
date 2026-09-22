"""Rendering an :class:`~nat_audit.audit.AuditResult`.

Two renderers share one result object: a human-readable report card and a
JSON document. The JSON is the interesting one -- it is stable, versioned
by its ``schema`` field, and designed to be collected across many
connections so that results can be compared rather than just admired.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Optional

from .audit import AuditResult, MappingBehaviour

__all__ = ["redact_ip", "render_text", "render_json"]

WIDTH = 64
LABEL_WIDTH = 24


def redact_ip(address: Optional[str]) -> Optional[str]:
    """Mask the host portion of an address for sharing.

    Report output gets pasted into issues, forums and screenshots. The
    first two octets identify the operator, which is the part that matters
    for a comparison; the rest identifies the subscriber, which does not.
    """
    if not address:
        return address
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 4:
        octets = address.split(".")
        return ".".join(octets[:2] + ["x", "x"])
    groups = address.split(":")
    return ":".join(groups[:3] + ["x"])


def _row(label: str, value: object) -> str:
    return " {0} : {1}".format(label.ljust(LABEL_WIDTH), value)


def _wrapped_rows(label: str, text: str):
    """A labelled row whose value wraps under the label rather than overflowing."""
    indent = " " * (LABEL_WIDTH + 4)
    available = WIDTH - len(indent)
    rows = []
    words = text.split()
    line = ""
    for word in words:
        candidate = (line + " " + word).strip()
        if len(candidate) > available and line:
            rows.append(line)
            line = word
        else:
            line = candidate
    if line:
        rows.append(line)
    if not rows:
        return []
    if not label.strip():
        # A continuation block under the previous row: indent, no divider.
        return [indent + row for row in rows]
    out = [_row(label, rows[0])]
    out.extend(indent + row for row in rows[1:])
    return out


def _rule(char: str = "-") -> str:
    return char * WIDTH


def _format_group(group) -> str:
    if group is None:
        return "not measured"
    if group.median_ms is None:
        return "unreachable ({0}/{1} endpoints)".format(len(group.reachable), len(group.results))
    return "{0:.1f} ms median, {1:.1f} ms best ({2}/{3} up)".format(
        group.median_ms, group.min_ms, len(group.reachable), len(group.results)
    )


def render_text(result: AuditResult, redact: bool = False) -> str:
    """Render the report card."""
    public_ip = redact_ip(result.public_ip) if redact else result.public_ip
    local_ip = redact_ip(result.local_ip) if redact else result.local_ip

    lines = []
    lines.append(_rule("="))
    lines.append("CONSUMER ISP TRANSPARENCY REPORT CARD".center(WIDTH))
    lines.append(_rule("="))

    if result.operator and result.operator.name:
        operator = result.operator.name
        if result.operator.asn:
            operator = "{0} ({1})".format(operator, result.operator.asn)
        lines.append(_row("Operator", operator))
    lines.append(_row("Local address", "{0}  [{1}]".format(local_ip, result.local_ip_class)))
    lines.append(_row("Public address", public_ip or "not observed"))
    lines.append(_row("Local source port", result.local_source_port or "n/a"))

    lines.append(_rule())
    lines.append(_row("NAT mapping", result.mapping))
    lines.extend(_wrapped_rows("", MappingBehaviour.DESCRIPTIONS.get(result.mapping, "")))
    lines.append(_row("NAT filtering", "not tested (needs an RFC 5780 server)"))
    lines.append(_row("Carrier-grade NAT", result.carrier_nat))
    if result.observed_ports:
        ports = ", ".join(str(p) for p in result.observed_ports)
        lines.append(_row("External ports seen", ports))

    lines.append(_rule())
    lines.append(_row("Local peering latency", _format_group(result.local_group)))
    lines.append(_row("International latency", _format_group(result.international_group)))
    ratio = result.peering_ratio
    if ratio is None:
        lines.append(_row("Peering advantage", "not comparable"))
    else:
        lines.append(_row("Peering advantage", "{0:.2f}x".format(ratio)))

    lines.append(_rule())
    for item in result.score_breakdown:
        label = "{0}".format(item["component"])
        lines.append(_row(label, "{0}/{1}".format(item["points"], item["max"])))
    lines.append(_row("TOTAL", "{0}/100   grade {1}".format(result.score, result.grade)))

    if result.stun_failures:
        lines.append(_rule())
        lines.append(" Unreachable STUN servers:")
        for server, error in result.stun_failures:
            lines.append("   - {0}: {1}".format(server, error))

    if result.notes:
        lines.append(_rule())
        lines.append(" Notes:")
        for note in result.notes:
            lines.extend(_wrap(note, prefix="   - ", continuation="     "))

    lines.append(_rule("="))
    return "\n".join(lines)


def _wrap(text: str, prefix: str, continuation: str):
    """Wrap a note to the card width without pulling in textwrap's defaults."""
    words = text.split()
    out = []
    current = prefix
    limit = WIDTH
    for word in words:
        candidate = current + ("" if current in (prefix, continuation) else " ") + word
        if len(candidate) > limit and current not in (prefix, continuation):
            out.append(current)
            current = continuation + word
        else:
            current = candidate
    if current.strip():
        out.append(current)
    return out


def render_json(result: AuditResult, redact: bool = False, indent: int = 2) -> str:
    """Render the result as JSON."""
    payload = result.to_dict()
    if redact:
        payload["local"]["ip"] = redact_ip(payload["local"]["ip"])
        payload["nat"]["public_ip"] = redact_ip(payload["nat"]["public_ip"])
        for entry in payload["stun"]["responses"]:
            entry["mapped_ip"] = redact_ip(entry["mapped_ip"])
    return json.dumps(payload, indent=indent, sort_keys=False)
