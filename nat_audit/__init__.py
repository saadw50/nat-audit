"""nat-audit -- NAT behaviour and ISP peering auditor.

A dependency-free command-line tool that reports how a consumer internet
connection actually behaves: whether NAT mapping allows peer-to-peer
traffic, whether the connection sits behind carrier-grade NAT, and how
local (IXP) latency compares with international transit.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
