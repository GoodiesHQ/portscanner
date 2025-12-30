"""
DNS Resolver mixin for PortScanner
"""

from abc import abstractmethod
from contextlib import suppress
from ipaddress import ip_network
from typing import Optional, List, Collection, get_args
import asyncio

from aiodns import DNSResolver
from aiodns.error import DNSError
from portscanner.types import IPAddress, IPNetwork, IPAny, IPTypes, Target

__all__ = [
    "MxResolverBase",
    "MxResolver",
]


class MxResolverBase:
    @property
    @abstractmethod
    def resolver(self) -> DNSResolver:
        """
        Return the resolver used for the mixin
        Should be located at `self._resolver` by the child class
        """

    @property
    @abstractmethod
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

from .loop import MxLoopBase

class MxResolver(MxResolverBase, MxLoopBase):
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

    async def resolve_all(self, host: IPAny, qtype: str = "A") -> List[Target]:
        """
        Resolve a host into all of its IP address types. This could be a 
        string literal IP address or CIDR, or it could be a hostname to resolve.
        On error or NXDOMAIN, return an empty list
        """
        # Name is only required for resolved hosts, so default to empty string
        name = ""

        # If the host is already an IP address or network, return it directly
        if isinstance(host, get_args(IPTypes)):
            return [Target(name="", host=host)]

        # Check if the host is a literal IP address or CIDR
        try:
            return [Target(name="", host=ip_network(host, strict=False))]
        except ValueError:
            # Not a literal IP address or CIDR, continue to resolve
            pass

        # Normalize qtype into a list
        if isinstance(qtype, str):
            qtypes = [qtype]
        elif isinstance(qtype, Collection):
            qtypes = list(qtype)
        else:
            raise ValueError(f"Invalid Query Type '{qtype}'")

        # Validate the allowed query types (A/AAAA)
        qtypes = [qt.upper() for qt in qtypes]
        for qt in qtypes:
            if qt not in self._Q:
                raise ValueError(f"Supported query types: {', '.join(self._Q)}")

        # NOTE: aiodns.query returns a Future, not a coroutine
        futs = [asyncio.ensure_future(self.resolver.query(host, qt), loop=self.loop) for qt in qtypes]

        try:
            # Await all queries with the provided timeout
            responses = await asyncio.wait_for(
                asyncio.gather(*futs, return_exceptions=True),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            print("timed out!")
            for fut in futs:
                fut.cancel()
            await asyncio.gather(*futs, return_exceptions=True)
            return []

        # All names resolve to the same host, so just use the first
        name = host
        results: List[Target] = []
        for resp in responses:
            if isinstance(resp, BaseException):
                if isinstance(resp, DNSError):
                    pass
                else:
                    print(f"[-] Error: {resp}")
                continue
            for r in resp:
                with suppress(ValueError):
                    results.append(
                        Target(name=name,
                               host=ip_network(r.host, strict=False)
                        )
                    )

        return results
    
    async def resolve(self, host: IPAny, qtype: str = "A") -> Optional[Target]:
        """
        Resolve a host into the first IP address returned by `resolve_all`
        On error or NXDOMAIN, return None
        """
        targets = await self.resolve_all(host, qtype)
        return targets[0] if targets else None