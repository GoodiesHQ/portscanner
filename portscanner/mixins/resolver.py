"""
DNS Resolver mixin for PortScanner
"""

from abc import ABC, abstractmethod, abstractproperty
from contextlib import suppress
from ipaddress import ip_address, ip_network
from typing import Union, Optional, List, Collection, get_args
import asyncio

from aiodns import DNSResolver
from aiodns.error import DNSError
from portscanner.types import IPAddress, IPNetwork, IPAny, IPTypes

__all__ = [
    "MxResolverBase",
    "MxResolver",
]


class MxResolverBase:
    @abstractproperty
    def resolver(self) -> DNSResolver:
        """
        Return the resolver used for the mixin
        Should be located at `self._resolver` by the child class
        """

    @abstractproperty
    def timeout(self) -> float:
        """
        Return the resolver timeout used for the mixin
        Should be located at `self._timeout` by the child class
        """

    @abstractmethod
    async def resolve_all(self, host: IPAny, qtype: str) -> List[IPNetwork]:
        """
        Resolve a host into all of its IP addresses.
        Upon error or NXDOMAIN, return an empty list
        """

    @abstractmethod
    async def resolve(self, host: IPAny, qtype: str) -> Optional[IPNetwork]:
        """
        Resolve a host into the first IP address returned by `resolve_all`
        Upon error or NXDOMAIN, return None
        """


class MxResolver(MxResolverBase):
    DEFAULT_TIMEOUT = 1.0

    @property
    def resolver(self) -> DNSResolver:
        return self._resolver

    @resolver.setter
    def resolver(self, resolver: DNSResolver):
        self._resolver = resolver

    @property
    def timeout(self) -> float:
        return getattr(self, "_timeout", self.DEFAULT_TIMEOUT)

    @timeout.setter
    def timeout(self, timeout: float):
        self._timeout = timeout

    async def resolve_all(self, host: IPAny, qtype: str = "A") -> List[IPNetwork]:
        """
        Return a list of valid IPv4/IPv6 addresses
        """
        if isinstance(host, get_args(IPTypes)):
            return [host]
        with suppress(ValueError):
            return [ip_network(host, strict=False)]
        if isinstance(qtype, str):
            qtypes = [qtype]
        elif isinstance(qtype, Collection):
            qtypes = list(qtype)
        else:
            raise ValueError(f"Invalid Query Type '{qtype}'")
        tasks = set()
        for qtype in self._Q if qtypes is None else qtypes:
            if (qtype := qtype.upper()) not in self._Q:
                raise ValueError(f"Supported query types: {', '.join(self._Q)}")
            tasks.add(asyncio.wait_for(self.resolver.query(host, qtype), self.timeout))
        with suppress(TimeoutError, asyncio.TimeoutError, DNSError):
            results, _ = await asyncio.wait(tasks, timeout=self.timeout)
            return list(
                ip_network(r.host, strict=False)
                for res in results
                for r in res.result()
                if not res.cancelled() or res.exception()
            )
        return []

    async def resolve(self, host: IPAny, qtype: str = "A") -> Optional[IPTypes]:
        if isinstance(host, get_args(IPTypes)):
            return host
        ips = await self.resolve_all(host, qtype)
        return ips[0] if ips else None
