"""
Custom types used within PortScanner
"""
from dataclasses import dataclass
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Optional, Text, Union


__all__ = [
    "IPAddress",
    "IPNetwork",
    "IPTypes",
    "IPAny",
    "ScanState",
    "ScanInfo",
]


# Type aliases
IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]
IPTypes = Union[IPAddress, IPNetwork]
IPAny = Union[IPTypes, Text]


class ScanState(IntEnum):
    """
    Possible values for the state of a particular host/port
    """

    OPEN = auto()  # Port is open and a reply was received
    CLOSED = auto()  # Connection was actively refused
    TIMEOUT = auto()  # Port did not respond within the desired time frame
    UNKNOWN = auto()  # Unknown error occurred (unlikely)


@dataclass
class ScanInfo:
    """
    Returned info from an individual port scan
    """

    host: str
    port: int
    state: ScanState
    banner: Optional[str] = None
