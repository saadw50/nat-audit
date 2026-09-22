"""Local address discovery and IP address classification.

The public address this tool reports comes from STUN, not from a web API.
That is both more accurate (it is the address a peer would actually see on
the UDP path being tested) and more private (no third party is told your
IP just to run an audit). An optional HTTPS lookup adds the operator name
only when the user asks for it with ``--isp-lookup``.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "AddressClass",
    "classify_address",
    "detect_local_address",
    "lookup_operator",
    "is_carrier_grade",
]

# RFC 6598: shared address space reserved for carrier-grade NAT.
# Note this is a /10, not a /8 -- 100.0.0.0-100.63.255.255 is ordinary
# public space and must not be mistaken for CGNAT.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

DEFAULT_OPERATOR_ENDPOINT = "https://ipinfo.io/json"


class AddressClass(object):
    """String constants for the address categories this tool distinguishes."""

    PRIVATE = "private"          # RFC 1918
    CGNAT = "cgnat"              # RFC 6598 shared address space
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"    # RFC 3927 / APIPA
    PUBLIC = "public"
    UNKNOWN = "unknown"


def classify_address(address: Optional[str]) -> str:
    """Categorise an IPv4/IPv6 address.

    ``ipaddress`` is used rather than string prefix tests so the boundaries
    are exactly right: ``100.63.255.255`` is public, ``100.64.0.0`` is
    CGNAT, and ``172.32.0.1`` is public even though ``172.16.0.1`` is not.
    """
    if not address:
        return AddressClass.UNKNOWN
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return AddressClass.UNKNOWN

    if ip.is_loopback:
        return AddressClass.LOOPBACK
    if ip.is_link_local:
        return AddressClass.LINK_LOCAL
    if ip.version == 4 and ip in CGNAT_NETWORK:
        return AddressClass.CGNAT
    if ip.is_private:
        return AddressClass.PRIVATE
    return AddressClass.PUBLIC


def is_carrier_grade(address: Optional[str]) -> bool:
    """True when the address sits in RFC 6598 shared address space."""
    return classify_address(address) == AddressClass.CGNAT


def detect_local_address(probe_host: str = "192.0.2.1", probe_port: int = 33434) -> str:
    """Return the source address the kernel would use to reach the internet.

    Connecting a UDP socket sends no packets; it only asks the routing
    table which local address applies. The destination is a TEST-NET-1
    address (RFC 5737) so nothing is contacted even by accident.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((probe_host, probe_port))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


@dataclass(frozen=True)
class Operator:
    """Network operator details from an optional third-party lookup."""

    name: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None


def lookup_operator(
    endpoint: str = DEFAULT_OPERATOR_ENDPOINT, timeout: float = 4.0
) -> Operator:
    """Look up the network operator name over HTTPS. Opt-in only.

    This is the one call that discloses the caller's address to a third
    party, which is why it never runs unless explicitly requested. HTTPS is
    required: an audit tool that leaks its own findings in plaintext would
    be a poor advertisement for itself.
    """
    if not endpoint.lower().startswith("https://"):
        return Operator(error="operator lookup refused: endpoint is not HTTPS")

    request = urllib.request.Request(
        endpoint, headers={"User-Agent": "nat-audit/1.0 (+https://github.com/)", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return Operator(error="operator lookup failed: {0}".format(exc))

    org = payload.get("org") or payload.get("isp") or payload.get("asn")
    asn = None
    name = None
    if isinstance(org, str):
        parts = org.split(" ", 1)
        if parts[0].upper().startswith("AS") and len(parts) == 2:
            asn, name = parts[0], parts[1]
        else:
            name = org
    elif isinstance(org, dict):  # some services nest it
        asn = org.get("asn")
        name = org.get("name")

    return Operator(
        name=name,
        asn=asn,
        country=payload.get("country"),
        source=endpoint,
    )
