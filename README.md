# nat-audit

A dependency-free command-line auditor for consumer internet connections. It
reports what your connection actually does, rather than what the package
advertises: whether NAT lets peer-to-peer traffic through, whether you are
behind carrier-grade NAT, and how local (IXP) latency compares with
international transit.

Built for the Bangladeshi market, where "BDIX-connected" is a headline
feature and carrier-grade NAT is common but rarely disclosed. Nothing in the
tool is country-specific, though: point `--local-probe` at any local exchange
and it works anywhere.

![tests](https://github.com/saadw50/nat-audit/actions/workflows/tests.yml/badge.svg)

## Why

Three questions decide whether a home connection is good for anything beyond
browsing, and none of them appear on a speed test:

- **Can peers reach you directly?** This is set by NAT *mapping behaviour*,
  not by bandwidth. Get it wrong and every video call, game and file transfer
  is relayed through a third party, adding latency you cannot buy your way
  out of.
- **Do you have a real public address?** Behind carrier-grade NAT your
  address is shared with other subscribers, so no amount of router
  configuration will give you working port forwarding.
- **Is local peering real?** An operator can advertise IXP membership while
  still hauling "local" traffic over international transit. The latency ratio
  between local and international endpoints shows which it is.

## Install

Python 3.8 or newer. No third-party dependencies — everything used is in the
standard library.

```bash
git clone https://github.com/saadw50/nat-audit.git
cd nat-audit
python -m nat_audit
```

Or install it as a command:

```bash
pip install .
nat-audit
```

## Usage

```bash
nat-audit                      # the report card
nat-audit --json               # machine-readable output
nat-audit --redact             # mask the host portion of addresses
nat-audit --isp-lookup         # add the operator name (opt-in, see Privacy)
nat-audit --samples 8          # more handshakes per endpoint
nat-audit --stun stun.example.org:3478 --stun stun2.example.org
nat-audit --local-probe ixp.example.net:80 --intl-probe 9.9.9.9:53
```

Exit status is `0` on a complete audit, `1` when UDP is blocked and mapping
behaviour could not be determined, `2` on a usage error.

### Example output

Illustrative values from a connection behind carrier-grade NAT with good
local peering. Your numbers will differ.

```
================================================================
             CONSUMER ISP TRANSPARENCY REPORT CARD
================================================================
 Operator                 : Example Broadband Ltd (AS64496)
 Local address            : 192.168.x.x  [private]
 Public address           : 100.88.x.x
 Local source port        : 51873
----------------------------------------------------------------
 NAT mapping              : endpoint-dependent
                            A different external port per
                            destination (symmetric; blocks hole
                            punching)
 NAT filtering            : not tested (needs an RFC 5780 server)
 Carrier-grade NAT        : detected
 External ports seen      : 41207, 41244
----------------------------------------------------------------
 Local peering latency    : 4.5 ms median, 3.8 ms best (2/2 up)
 International latency    : 117.9 ms median, 109.8 ms best (2/2 up)
 Peering advantage        : 25.91x
----------------------------------------------------------------
 NAT mapping behaviour    : 15/50
 Carrier-grade NAT        : 5/25
 Local peering advantage  : 25/25
 TOTAL                    : 45/100   grade D
----------------------------------------------------------------
 Notes:
   - Endpoint-dependent mapping means each destination sees a
     different external port, so hole punching fails and P2P
     traffic must be relayed.
   - Behind carrier-grade NAT the public address is shared, so
     inbound port forwarding is not available from the router
     alone.
   - Filtering behaviour (full-cone vs restricted) is not
     tested; it needs an RFC 5780 server.
================================================================
```

That connection has excellent local peering and is still a poor choice for
anyone who needs inbound reachability — which is exactly the trade-off a
speed test hides.

## Methodology

### NAT mapping behaviour

The tool sends STUN Binding requests ([RFC 5389][rfc5389]) to several servers
**through a single bound UDP socket**, and compares the external transport
address each one reports.

Using one socket is the entire experiment. Mapping behaviour is defined by
what the NAT does with the *same* internal endpoint when it contacts
*different* external endpoints:

| Observation                                      | Mapping behaviour      | Consequence                          |
| ------------------------------------------------ | ---------------------- | ------------------------------------ |
| Same external port from every server              | Endpoint-independent   | Hole punching works; P2P is direct   |
| A different external port per server              | Endpoint-dependent     | Hole punching fails; needs a relay   |
| Fewer than two *distinct* servers replied         | Undetermined           | Not enough data to compare           |
| No server replied                                 | UDP blocked            | P2P requires TURN                    |

A fresh socket per server would give a different source port each time, so
even a completely open NAT would hand out different external ports and every
connection on earth would look symmetric. Responses from two hostnames that
resolve to the same IP are collapsed for the same reason: that is one
destination, not two.

### What is deliberately not measured

**Filtering behaviour** — the "full-cone / restricted-cone / port-restricted"
distinction — is *not* reported, because it cannot be determined from mapped
addresses alone. It requires a server that replies from an alternate address
and port ([RFC 5780][rfc5780] `CHANGE-REQUEST` / `OTHER-ADDRESS`); the older
RFC 3489 classification that many scripts copy was deprecated precisely
because it was unreliable. The report says `not tested` rather than guessing.

### Carrier-grade NAT

CGNAT is reported as `detected` only on positive evidence: a public address
inside the RFC 6598 shared range `100.64.0.0/10`, or a host holding such an
address directly. Note that this is a `/10`, not a `/8` — `100.63.255.255` is
ordinary public space, and treating all of `100.0.0.0/8` as CGNAT is a common
bug.

A negative result is reported as `not-detected`, never as "clean": an
operator can run carrier NAT on ordinary public address space, and no
client-side test can rule that out.

### Latency

TCP handshake time is used as the latency estimate, since it needs no
elevated privileges (unlike ICMP) and measures the path a real connection
takes.

- Hostnames are resolved **before** the clock starts. Timing a `connect()` to
  a hostname includes the resolver round trip, which can be tens of
  milliseconds — enough to make a local endpoint look slower than a distant
  one when only the distant one was given as a raw IP.
- Several handshakes are taken per endpoint; the **median** is reported and
  the minimum is kept as the floor. A single sample measures jitter.
- Probes run **sequentially**. Parallel connections share the access link and
  inflate each other's timings, which matters most on the constrained
  connections this tool exists to characterise.
- An endpoint that fails on its first attempt is marked unreachable and
  skipped, so a dead host costs one timeout rather than several.

The reported *peering advantage* is the international median divided by the
local median. A value near `1.0` means "local" traffic is travelling the same
distance as international traffic. If either side is unreachable the ratio is
`null` rather than a fabricated `1.0`.

### Scoring

The rubric is published so you can disagree with the weights rather than
wonder where a letter came from. Every component appears in the output
alongside the total.

| Component               | Points | Awarded for                                      |
| ----------------------- | ------ | ------------------------------------------------ |
| NAT mapping behaviour   | 0–50   | 50 endpoint-independent, 25 undetermined, 15 endpoint-dependent, 0 UDP blocked |
| Carrier-grade NAT       | 0–25   | 25 not detected, 15 unknown, 5 detected          |
| Local peering advantage | 0–25   | 25 at ≥2.0×, 18 at ≥1.2×, 10 at ≥0.9×, 5 below   |

Grades: **A** ≥85, **B** ≥70, **C** ≥55, **D** ≥40, **F** below 40.

## Privacy

- **No third party is contacted over HTTP by default.** The public address
  comes from the STUN exchange the audit already performs, which is both more
  accurate — it is the address a peer would actually see on the UDP path
  being tested — and more private than asking a web API.
- `--isp-lookup` is opt-in, uses HTTPS only, and is the single call that
  discloses your address to an outside service. A non-HTTPS endpoint is
  refused.
- `--redact` masks the host portion of every address in both output formats.
  Use it before pasting results into an issue, a forum or a screenshot.

## JSON output

`--json` emits a stable, versioned document (`"schema": "nat-audit/1"`)
carrying every measurement, not just the summary — individual samples,
per-server mapped ports, which attribute each address came from, and the
score breakdown. It is meant to be collected: run the audit across many
connections and the results are directly comparable.

```bash
nat-audit --json --redact > results/$(date +%F)-operator.json
```

## Limitations

Stated plainly, because a measurement tool that hides its blind spots is
worse than no tool:

- IPv4 only. The STUN parser decodes IPv6 mapped addresses, but probing and
  classification assume IPv4.
- Filtering behaviour is not tested (see Methodology).
- TCP handshake time includes the remote host's accept latency, so it is an
  upper bound on path RTT rather than an exact measurement.
- A single run is a snapshot. Consumer links vary by time of day; for
  anything comparative, sample repeatedly.
- The default local probes target BDIX endpoints. Outside Bangladesh, pass
  `--local-probe` with a nearby exchange.
- Mapping behaviour describes the NAT path at the moment of the test. Some
  operators change behaviour under load or per subscriber class.

## Development

```bash
python -m unittest discover -s tests -t . -v
```

The suite runs entirely offline. STUN messages are constructed byte by byte
and fed to the parser, which is the only way to cover the cases that matter —
attribute ordering, alignment padding, truncated attributes, transaction ID
mismatches and error responses are not things you can arrange on demand from
a public server.

One test is a deliberate regression guard: `test_mapped_address_first_still_parses_correctly`
builds a response with `MAPPED-ADDRESS` before `XOR-MAPPED-ADDRESS`, as
several public servers emit. A parser reading a fixed byte offset picks up the
un-obfuscated port, XORs it anyway, and returns a wrong number that still
looks like a plausible port — a silent failure that a naive implementation
never notices.

## References

- [RFC 5389][rfc5389] — Session Traversal Utilities for NAT (STUN)
- [RFC 5780][rfc5780] — NAT Behavior Discovery Using STUN
- [RFC 6598][rfc6598] — IANA-Reserved IPv4 Prefix for Shared Address Space
- [RFC 4787][rfc4787] — NAT Behavioral Requirements for Unicast UDP

[rfc5389]: https://datatracker.ietf.org/doc/html/rfc5389
[rfc5780]: https://datatracker.ietf.org/doc/html/rfc5780
[rfc6598]: https://datatracker.ietf.org/doc/html/rfc6598
[rfc4787]: https://datatracker.ietf.org/doc/html/rfc4787

## License

MIT — see [LICENSE](LICENSE).
