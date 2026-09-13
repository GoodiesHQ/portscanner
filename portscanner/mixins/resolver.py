"""
DNS Resolver mixin for PortScanner
"""

from abc import abstractmethod
from contextlib import suppress
from ipaddress import ip_network
from typing import Optional, List, Collection, Sequence
import asyncio

from aiodns import DNSResolver
from portscanner.types import IPAny, Target

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
    async def resolve_all(
        self, host: IPAny, qtype: str | Sequence[str]
    ) -> List[Target]:
        """
        Resolve a host into all of its IP addresses.
        Upon error or NXDOMAIN, return an empty list
        """

    @abstractmethod
    async def resolve(
        self, host: IPAny, qtype: str | Sequence[str]
    ) -> Optional[Target]:
        """
        Resolve a host into the first IP address returned by `resolve_all`
        Upon error or NXDOMAIN, return None
        """


from .loop import MxLoopBase


class MxResolver(MxResolverBase, MxLoopBase):
    DEFAULT_TIMEOUT = 1.0

    @property
    def resolver(self) -> DNSResolver:
        if self._resolver is None:
            self._resolver = DNSResolver(nameservers=self._nameservers, loop=self.loop)
        return self._resolver

    @resolver.setter
    def resolver(self, resolver: DNSResolver):
        self._resolver = resolver
        self._owns_resolver = resolver is None

    @property
    def timeout(self) -> float:
        return getattr(self, "_dns_timeout", self.DEFAULT_TIMEOUT)

    @timeout.setter
    def timeout(self, timeout: float):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._dns_timeout = timeout

    def _server_resolver(self, server: str) -> DNSResolver:
        """
        A dedicated, memoized resolver that only ever queries one server.
        """
        resolver = self._server_resolvers.get(server)
        if resolver is None:
            resolver = DNSResolver(nameservers=(server,), loop=self.loop)
            self._server_resolvers[server] = resolver
        return resolver

    async def _discover_servers(self) -> Sequence[str]:
        """
        The OS-configured DNS servers, the same ones an unconfigured DNSResolver would use.
        """
        if self._system_nameservers is None:
            probe = DNSResolver(loop=self.loop)
            try:
                self._system_nameservers = tuple(probe.nameservers)
            finally:
                await probe.close()
        return self._system_nameservers

    async def _race(self, host: IPAny, qtype: str, servers: Sequence[str]):
        """
        Query every server concurrently and return the first successful response.
        """
        if not servers:
            raise RuntimeError("No DNS servers configured")
        tasks = [
            asyncio.ensure_future(self._server_resolver(server).query(host, qtype))
            for server in servers
        ]
        pending = set(tasks)
        last_exc: Optional[BaseException] = None
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    exc = task.exception()
                    if exc is None:
                        return task.result()
                    last_exc = exc
            raise last_exc
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def resolve_all(
        self, host: IPAny, qtype: str | Sequence[str] = "A"
    ) -> List[Target]:
        """
        Resolve a host into all of its IP address types. This could be a
        string literal IP address or CIDR, or it could be a hostname to resolve.
        On error or NXDOMAIN, return an empty list
        """
        # Check if the host is a string literal IP address or CIDR or an IP object
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

        if self._resolver is not None:
            futs = [self.resolver.query(host, qt) for qt in qtypes]
        else:
            servers = self._nameservers
            if servers is None:
                servers = await self._discover_servers()
            futs = [self._race(host, qt, servers) for qt in qtypes]

        try:
            # Await all queries with the provided timeout
            responses = await asyncio.wait_for(
                asyncio.gather(*futs, return_exceptions=True),
                timeout=self.timeout,
            )
        except (asyncio.TimeoutError, TimeoutError):
            return []

        # All names resolve to the same host, so just use the first
        name = host
        results: List[Target] = []
        for resp in responses:
            if isinstance(resp, BaseException):
                if isinstance(resp, asyncio.CancelledError):
                    raise resp
                continue
            for r in resp:
                with suppress(ValueError):
                    results.append(
                        Target(name=name, host=ip_network(r.host, strict=False))
                    )

        return results

    async def resolve(
        self, host: IPAny, qtype: str | Sequence[str] = "A"
    ) -> Optional[Target]:
        """
        Resolve a host into the first IP address returned by `resolve_all`
        On error or NXDOMAIN, return None
        """
        targets = await self.resolve_all(host, qtype)
        return targets[0] if targets else None
