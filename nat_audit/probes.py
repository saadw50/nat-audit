"""TCP handshake latency probes.

Three things separate a usable measurement from a misleading one:

* **DNS is resolved before the clock starts.** Timing
  ``connect(("example.net", 80))`` includes the resolver round trip, which
  can be tens of milliseconds. Comparing a hostname probe against a
  raw-IP probe then measures the resolver, not the route.
* **More than one sample.** A single handshake is dominated by jitter and
  queueing. Several samples are taken and the median is reported, with the
  minimum kept as the floor -- the closest estimate of the true path RTT.
* **Sequential, not parallel.** Probes run one at a time. Concurrent
  connections share the access link and inflate each other's timings,
  which matters most on exactly the constrained connections this tool is
  meant to characterise.
"""

from __future__ import annotations

import socket
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = ["Probe", "ProbeResult", "GroupResult", "measure", "measure_group"]


@dataclass(frozen=True)
class Probe:
    """A TCP endpoint to time, with a human-readable label."""

    label: str
    host: str
    port: int


@dataclass
class ProbeResult:
    """Timing samples for a single endpoint."""

    probe: Probe
    resolved_ip: Optional[str] = None
    samples: List[float] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return bool(self.samples)

    @property
    def median_ms(self) -> Optional[float]:
        return statistics.median(self.samples) if self.samples else None

    @property
    def min_ms(self) -> Optional[float]:
        return min(self.samples) if self.samples else None

    def to_dict(self) -> Dict[str, object]:
        return {
            "label": self.probe.label,
            "host": self.probe.host,
            "port": self.probe.port,
            "resolved_ip": self.resolved_ip,
            "samples_ms": [round(s, 2) for s in self.samples],
            "median_ms": round(self.median_ms, 2) if self.median_ms is not None else None,
            "min_ms": round(self.min_ms, 2) if self.min_ms is not None else None,
            "error": self.error,
        }


@dataclass
class GroupResult:
    """Aggregate timings for a named group of endpoints (e.g. BDIX)."""

    name: str
    results: List[ProbeResult] = field(default_factory=list)

    @property
    def reachable(self) -> List[ProbeResult]:
        return [r for r in self.results if r.ok]

    @property
    def median_ms(self) -> Optional[float]:
        """Median of the per-host medians across every reachable endpoint."""
        medians = [r.median_ms for r in self.reachable if r.median_ms is not None]
        return statistics.median(medians) if medians else None

    @property
    def min_ms(self) -> Optional[float]:
        mins = [r.min_ms for r in self.reachable if r.min_ms is not None]
        return min(mins) if mins else None

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "reachable": len(self.reachable),
            "total": len(self.results),
            "median_ms": round(self.median_ms, 2) if self.median_ms is not None else None,
            "min_ms": round(self.min_ms, 2) if self.min_ms is not None else None,
            "probes": [r.to_dict() for r in self.results],
        }


def _resolve(host: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a hostname to an IPv4 literal outside any timed section."""
    try:
        ipaddress_literal = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        return ipaddress_literal, None
    except (OSError, IndexError) as exc:
        return None, "DNS resolution failed: {0}".format(exc)


def _single_handshake(ip: str, port: int, timeout: float) -> Tuple[Optional[float], Optional[str]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        elapsed = (time.perf_counter() - start) * 1000.0
        return elapsed, None
    except socket.timeout:
        return None, "timed out after {0:.1f}s".format(timeout)
    except OSError as exc:
        return None, str(exc)
    finally:
        sock.close()


def measure(probe: Probe, samples: int = 4, timeout: float = 1.5) -> ProbeResult:
    """Time ``samples`` TCP handshakes to one endpoint.

    If the first attempt fails the endpoint is treated as unreachable and
    the remaining attempts are skipped, so an unreachable host costs one
    timeout rather than ``samples`` of them.
    """
    result = ProbeResult(probe=probe)
    resolved, error = _resolve(probe.host)
    if resolved is None:
        result.error = error
        return result
    result.resolved_ip = resolved

    for attempt in range(max(1, samples)):
        elapsed, error = _single_handshake(resolved, probe.port, timeout)
        if elapsed is None:
            if attempt == 0:
                result.error = error
                return result
            result.error = result.error or error
            break
        result.samples.append(elapsed)
    return result


def measure_group(
    name: str, probes: Sequence[Probe], samples: int = 4, timeout: float = 1.5
) -> GroupResult:
    """Measure every probe in a group, sequentially."""
    return GroupResult(name=name, results=[measure(p, samples, timeout) for p in probes])
