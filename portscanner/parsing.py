"""
Parsing functions used throughout portscanner
"""

from ipaddress import ip_address
from typing import List

from portscanner.utils import trycast

__all__ = [
    "port_range",
    "dns_servers",
]


def port_range(port_ranges: str, quiet: bool = True):
    """
    Parse port ranges such as:
        80
        80,443
        21-23,80,443,8000-8080
    """
    valid_ports = set()
    for ports in port_ranges.split(","):
        try:
            if "-" not in ports:
                if (port := trycast(int, ports)) is not None:
                    if 0 < port < 65536:
                        valid_ports.add(port)
            elif ports.count("-") == 1:
                start, stop = map(
                    lambda s: trycast(int, s.strip()), ports.split("-")
                )
                if start is None or stop is None:
                    raise ValueError
                start, stop = (stop, start) if start > stop else (start, stop)
                for i in range(max((1, start)), min((stop, 65535)) + 1):
                    valid_ports.add(i)
            else:
                raise ValueError
        except ValueError:
            if not quiet:
                print("Invalid Port Range:", ports)
    if len(valid_ports) == 0:
        raise ValueError("no valid ports were provided")
    return sorted(valid_ports)


def dns_servers(server_list: str, quiet: bool = True) -> List[str]:
    """
    Parse a comma-separated list of IPv4/IPv6 DNS server addresses such as:
        1.1.1.1
        1.1.1.1,8.8.8.8
        2606:4700:4700::1111,2001:4860:4860::8888
    """
    valid_servers = []
    for server in server_list.split(","):
        server = server.strip()
        if trycast(ip_address, server) is not None:
            valid_servers.append(server)
        elif not quiet:
            print("Invalid DNS Server:", server)
    if len(valid_servers) == 0:
        raise ValueError("no valid DNS servers were provided")
    return valid_servers
