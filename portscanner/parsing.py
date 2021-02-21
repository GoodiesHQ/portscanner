"""
Parsing functions used throughout portscanner
"""
from contextlib import suppress
from functools import partial

from portscanner.utils import trycast


__all__ = [
    "port_range",
]


def port_range(port_ranges: str, quiet: bool = True):
    """
    Parse port ranges such as:
        80
        80,443
        21-23,80,443,8000-8080
    """
    valid_ports = set()
    for port_range in port_ranges.split(","):
        try:
            if "-" not in port_range:
                if (port := trycast(int, port_range)) is not None:
                    if 0 < port < 65536:
                        valid_ports.add(port)
            elif port_range.count("-") == 1:
                start, stop = map(
                    lambda s: trycast(int, s.strip()), port_range.split("-")
                )
                if start is None or stop is None:
                    raise ValueError
                start, stop = (stop, start) if start > stop else (start, stop)
                for i in range(max((0, start)), min((stop, 65535)) + 1):
                    valid_ports.add(i)
            else:
                raise ValueError
        except ValueError:
            if not quiet:
                print("Invalid Port Range:", port_range)
    return sorted(valid_ports)
