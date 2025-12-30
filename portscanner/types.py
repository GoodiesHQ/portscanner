"""
Custom types used within PortScanner
"""
from dataclasses import dataclass
from enum import IntEnum, auto
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Iterator, Optional, Text, Union, get_args


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

@dataclass(frozen=True)
class Target:
    name: str
    host: IPTypes

    def iter_ips(self) -> Iterator["TargetIP"]:
        ip_types = get_args(IPAddress)
        net_types = get_args(IPNetwork)

        if isinstance(self.host, ip_types):
            yield TargetIP(name=self.name, addr=self.host)
            return
        elif isinstance(self.host, net_types):
            for ip in self.host:
                yield TargetIP(name=self.name, addr=ip)
            return
        raise TypeError(f"Unsupported host type: {type(self.host)}")

    def __iter__(self) -> Iterator["TargetIP"]:
        return self.iter_ips()

@dataclass(frozen=True)
class TargetIP:
    name: str
    addr: IPAddress

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
    name: str
    addr: IPAddress
    port: int
    state: ScanState
    banner: Optional[str] = None
