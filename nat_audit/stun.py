"""A small, strict STUN client (RFC 5389) for NAT mapping discovery.

This module deliberately implements only what an audit needs: Binding
requests over UDP, strict response validation, and a correct TLV walk of
the attribute list.

Two implementation details matter more than they look:

1. **Attributes are a TLV list, not a fixed layout.** A STUN message is a
   20-byte header followed by attributes the server may emit in any order,
   each padded to a 4-byte boundary. Several widely used public servers
   send ``MAPPED-ADDRESS`` (0x0001) *before* ``XOR-MAPPED-ADDRESS``
   (0x0020). Reading the mapped port from a hard-coded offset therefore
   yields a plausible-looking but wrong value -- and silently, because the
   bytes are still well-formed. :func:`iter_attributes` walks the list
   properly instead.

2. **One socket, many servers.** See :class:`StunClient`.

References
----------
RFC 5389 -- Session Traversal Utilities for NAT (STUN)
RFC 5780 -- NAT Behavior Discovery Using STUN
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence, Tuple

__all__ = [
    "MappedAddress",
    "StunError",
    "StunResponse",
    "StunClient",
    "build_binding_request",
    "iter_attributes",
    "parse_binding_response",
]

MAGIC_COOKIE = 0x2112A442
_COOKIE_BYTES = struct.pack("!I", MAGIC_COOKIE)
HEADER_SIZE = 20
TRANSACTION_ID_SIZE = 12

# Message types: 14-bit method/class encoding (RFC 5389 section 6).
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_ERROR_CODE = 0x0009
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_OTHER_ADDRESS = 0x802C

FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02


class StunError(Exception):
    """Raised when a STUN exchange fails or a response is malformed."""


@dataclass(frozen=True)
class MappedAddress:
    """The public transport address a STUN server observed for us."""

    ip: str
    port: int
    family: int = FAMILY_IPV4

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.family == FAMILY_IPV6:
            return "[{0}]:{1}".format(self.ip, self.port)
        return "{0}:{1}".format(self.ip, self.port)


@dataclass(frozen=True)
class StunResponse:
    """A successful Binding response from one server."""

    server: str
    server_ip: str
    server_port: int
    mapped: MappedAddress
    rtt_ms: float
    attribute: str
    """Which attribute the address came from, for transparency in reports."""


def build_binding_request(
    transaction_id: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Build a Binding request. Returns ``(packet, transaction_id)``.

    The transaction ID is random by default. A hard-coded one would let any
    observer forge a matching response, and makes it impossible to tell a
    fresh reply from a stale one when a socket talks to several servers.
    """
    tid = transaction_id if transaction_id is not None else os.urandom(TRANSACTION_ID_SIZE)
    if len(tid) != TRANSACTION_ID_SIZE:
        raise ValueError("transaction id must be 12 bytes")
    packet = struct.pack("!HHI12s", BINDING_REQUEST, 0, MAGIC_COOKIE, tid)
    return packet, tid


def iter_attributes(message: bytes) -> Iterator[Tuple[int, bytes]]:
    """Yield ``(type, value)`` for each attribute in a STUN message.

    Attribute values are padded to a multiple of four bytes; the padding is
    not included in the declared length, so it has to be skipped explicitly.
    The walk is bounded by the length declared in the header, and stops
    early on a truncated attribute rather than reading past the buffer.
    """
    if len(message) < HEADER_SIZE:
        return
    declared_len = struct.unpack("!H", message[2:4])[0]
    end = min(len(message), HEADER_SIZE + declared_len)
    offset = HEADER_SIZE
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", message[offset : offset + 4])
        value_start = offset + 4
        value_end = value_start + attr_len
        if value_end > end:
            return  # truncated attribute; stop rather than over-read
        yield attr_type, message[value_start:value_end]
        offset = value_end + (-attr_len % 4)  # skip 4-byte alignment padding


def _parse_address_value(
    attr_type: int, value: bytes, transaction_id: bytes
) -> Optional[MappedAddress]:
    """Decode a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute value."""
    if len(value) < 4:
        return None
    family = value[1]
    port = struct.unpack("!H", value[2:4])[0]
    addr = value[4:]

    if attr_type == ATTR_XOR_MAPPED_ADDRESS:
        port ^= MAGIC_COOKIE >> 16
        key = _COOKIE_BYTES + transaction_id
        addr = bytes(a ^ b for a, b in zip(addr, key))

    if family == FAMILY_IPV4:
        if len(addr) < 4:
            return None
        return MappedAddress(socket.inet_ntop(socket.AF_INET, addr[:4]), port, FAMILY_IPV4)
    if family == FAMILY_IPV6:
        if len(addr) < 16:
            return None
        return MappedAddress(socket.inet_ntop(socket.AF_INET6, addr[:16]), port, FAMILY_IPV6)
    return None


def parse_binding_response(
    message: bytes, expected_transaction_id: bytes
) -> Tuple[MappedAddress, str]:
    """Validate a Binding response and extract the mapped address.

    Returns ``(address, attribute_name)``. ``XOR-MAPPED-ADDRESS`` is
    preferred when both forms are present, because middleboxes that rewrite
    IP addresses in payloads cannot recognise the obfuscated form.

    Raises :class:`StunError` on any mismatch -- wrong length, wrong magic
    cookie, wrong transaction ID, an error response, or no usable address.
    """
    if len(message) < HEADER_SIZE:
        raise StunError("response shorter than a STUN header")

    msg_type, msg_len, cookie = struct.unpack("!HHI", message[:8])
    tid = message[8:HEADER_SIZE]

    if cookie != MAGIC_COOKIE:
        raise StunError("bad magic cookie (not a RFC 5389 STUN message)")
    if tid != expected_transaction_id:
        raise StunError("transaction id mismatch")
    if len(message) < HEADER_SIZE + msg_len:
        raise StunError("declared length exceeds datagram size")

    if msg_type == BINDING_ERROR:
        raise StunError(_error_text(message, tid))
    if msg_type != BINDING_SUCCESS:
        raise StunError("unexpected message type 0x{0:04x}".format(msg_type))

    plain: Optional[MappedAddress] = None
    for attr_type, value in iter_attributes(message):
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            address = _parse_address_value(attr_type, value, tid)
            if address is not None:
                return address, "XOR-MAPPED-ADDRESS"
        elif attr_type == ATTR_MAPPED_ADDRESS and plain is None:
            plain = _parse_address_value(attr_type, value, tid)

    if plain is not None:
        return plain, "MAPPED-ADDRESS"
    raise StunError("no mapped address attribute in response")


def _error_text(message: bytes, tid: bytes) -> str:
    for attr_type, value in iter_attributes(message):
        if attr_type == ATTR_ERROR_CODE and len(value) >= 4:
            code = value[2] * 100 + value[3]
            reason = value[4:].decode("utf-8", "replace")
            return "server returned error {0} {1}".format(code, reason).strip()
    return "server returned an error response"


class StunClient:
    """Queries several STUN servers through a single bound UDP socket.

    Reusing one local source port is the whole point. NAT mapping behaviour
    is defined by what the NAT does with *the same* internal endpoint when
    it talks to *different* external endpoints:

    * same external port for every destination -> endpoint-independent
      mapping (the P2P-friendly case, loosely "cone" NAT);
    * a different external port per destination -> endpoint-dependent
      mapping (what is usually called "symmetric").

    Opening a fresh socket per server destroys the experiment: the source
    port differs each time, so even a completely open NAT hands out
    different external ports and every network looks symmetric.

    Use as a context manager, or call :meth:`close` when done.
    """

    def __init__(self, timeout: float = 2.5, source_port: int = 0, retries: int = 1) -> None:
        if retries < 0:
            raise ValueError("retries must be >= 0")
        self._timeout = float(timeout)
        self._retries = int(retries)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind(("0.0.0.0", source_port))
        except OSError:
            self._sock.close()
            raise
        self._closed = False

    @property
    def local_port(self) -> int:
        """The bound local source port shared by every query."""
        return self._sock.getsockname()[1]

    def query(self, host: str, port: int) -> StunResponse:
        """Send a Binding request to one server and return its response.

        Retransmits once by default, since a lost UDP datagram is not the
        same thing as a blocked one.
        """
        if self._closed:
            raise StunError("client is closed")
        try:
            server_ip = socket.gethostbyname(host)
        except OSError as exc:
            raise StunError("DNS resolution failed: {0}".format(exc)) from exc

        packet, tid = build_binding_request()
        last_error = "no response within {0:.1f}s".format(self._timeout)

        for _ in range(self._retries + 1):
            start = time.perf_counter()
            try:
                self._sock.sendto(packet, (server_ip, port))
            except OSError as exc:
                raise StunError("send failed: {0}".format(exc)) from exc

            deadline = start + self._timeout
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                self._sock.settimeout(remaining)
                try:
                    data, addr = self._sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError as exc:
                    last_error = str(exc)
                    break
                if addr[0] != server_ip:
                    # A late reply from a server queried earlier on this
                    # same socket. Ignore it and keep waiting.
                    continue
                try:
                    mapped, attribute = parse_binding_response(data, tid)
                except StunError as exc:
                    last_error = str(exc)
                    continue
                rtt_ms = (time.perf_counter() - start) * 1000.0
                return StunResponse(host, server_ip, port, mapped, rtt_ms, attribute)

        raise StunError(last_error)

    def survey(self, servers: Sequence[Tuple[str, int]]) -> Tuple[List[StunResponse], List[Tuple[str, str]]]:
        """Query every server in turn. Returns ``(responses, failures)``."""
        responses: List[StunResponse] = []
        failures: List[Tuple[str, str]] = []
        for host, port in servers:
            try:
                responses.append(self.query(host, port))
            except StunError as exc:
                failures.append(("{0}:{1}".format(host, port), str(exc)))
        return responses, failures

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._sock.close()

    def __enter__(self) -> "StunClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
