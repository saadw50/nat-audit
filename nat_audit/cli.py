"""Command-line interface for nat-audit."""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence, Tuple

from . import __version__
from .audit import (
    DEFAULT_INTERNATIONAL_PROBES,
    DEFAULT_LOCAL_PROBES,
    DEFAULT_STUN_SERVERS,
    AuditConfig,
    MappingBehaviour,
    run_audit,
)
from .netinfo import DEFAULT_OPERATOR_ENDPOINT
from .probes import Probe
from .report import render_json, render_text

EXIT_OK = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2


def _parse_endpoint(value: str, default_port: int) -> Tuple[str, int]:
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        try:
            return host, int(port)
        except ValueError:
            raise argparse.ArgumentTypeError("invalid port in {0!r}".format(value))
    return value, default_port


def _stun_endpoint(value: str) -> Tuple[str, int]:
    return _parse_endpoint(value, 3478)


def _probe_endpoint(value: str) -> Probe:
    host, port = _parse_endpoint(value, 80)
    return Probe(label=host, host=host, port=port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nat-audit",
        description=(
            "Audit a consumer internet connection: NAT mapping behaviour, "
            "carrier-grade NAT, and local (BDIX) versus international latency."
        ),
        epilog=(
            "By default no third party is contacted over HTTP -- the public "
            "address comes from STUN. Use --isp-lookup to add the operator "
            "name via an HTTPS API, and --redact before sharing output."
        ),
    )
    parser.add_argument("--version", action="version", version="nat-audit {0}".format(__version__))
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of the report card")
    parser.add_argument("--redact", action="store_true", help="mask the host portion of IP addresses in output")
    parser.add_argument(
        "--isp-lookup",
        action="store_true",
        help="look up the operator name over HTTPS (discloses your IP to a third party)",
    )
    parser.add_argument(
        "--isp-endpoint",
        default=DEFAULT_OPERATOR_ENDPOINT,
        metavar="URL",
        help="HTTPS endpoint for the operator lookup (default: %(default)s)",
    )
    parser.add_argument(
        "--stun",
        action="append",
        type=_stun_endpoint,
        metavar="HOST[:PORT]",
        help="STUN server to query; repeatable. Replaces the defaults.",
    )
    parser.add_argument(
        "--local-probe",
        action="append",
        type=_probe_endpoint,
        metavar="HOST[:PORT]",
        help="local/IXP TCP endpoint to time; repeatable. Replaces the defaults.",
    )
    parser.add_argument(
        "--intl-probe",
        action="append",
        type=_probe_endpoint,
        metavar="HOST[:PORT]",
        help="international TCP endpoint to time; repeatable. Replaces the defaults.",
    )
    parser.add_argument("--samples", type=int, default=4, metavar="N", help="handshakes per endpoint (default: %(default)s)")
    parser.add_argument("--stun-timeout", type=float, default=2.5, metavar="SEC", help="per-attempt STUN timeout (default: %(default)s)")
    parser.add_argument("--probe-timeout", type=float, default=1.5, metavar="SEC", help="TCP connect timeout (default: %(default)s)")
    parser.add_argument(
        "--source-port",
        type=int,
        default=0,
        metavar="PORT",
        help="bind STUN queries to a fixed local port (default: ephemeral)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.samples < 1:
        parser.error("--samples must be at least 1")

    config = AuditConfig(
        stun_servers=tuple(args.stun) if args.stun else DEFAULT_STUN_SERVERS,
        local_probes=tuple(args.local_probe) if args.local_probe else DEFAULT_LOCAL_PROBES,
        international_probes=tuple(args.intl_probe) if args.intl_probe else DEFAULT_INTERNATIONAL_PROBES,
        stun_timeout=args.stun_timeout,
        probe_timeout=args.probe_timeout,
        samples=args.samples,
        source_port=args.source_port,
        operator_lookup=args.isp_lookup,
        operator_endpoint=args.isp_endpoint,
    )

    try:
        result = run_audit(config)
    except KeyboardInterrupt:  # pragma: no cover
        sys.stderr.write("\ninterrupted\n")
        return EXIT_INCOMPLETE

    if args.json:
        sys.stdout.write(render_json(result, redact=args.redact) + "\n")
    else:
        sys.stdout.write(render_text(result, redact=args.redact) + "\n")

    if result.mapping == MappingBehaviour.BLOCKED:
        return EXIT_INCOMPLETE
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
