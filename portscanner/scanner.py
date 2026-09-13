"""
Implementation of an asynchronous port scanner
"""

from contextlib import aclosing, suppress
from socket import AF_INET, AF_INET6, AF_UNSPEC
from types import TracebackType
from typing import Awaitable, Coroutine, Dict, Optional, List, Type, Sequence, Collection, AsyncIterator
import asyncio
import sys
import time

from aiodns import DNSResolver

from portscanner.mixins import MxLoop, MxResolver, MxWorkPool
from portscanner.types import (
    IPAny, ScanInfo, ScanState,
    Target, TargetIP
)


class PortScanner(MxLoop, MxResolver, MxWorkPool):
    """
    Implementation of the port scanner
    """

    _Q = ("A", "AAAA")

    def __init__(
        self,
        workers: int = 10,
        timeout: float = 3.0,
        banner_buffer: Optional[int] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        resolver: Optional[DNSResolver] = None,
        nameservers: Optional[Sequence[str]] = None,
        dns_timeout: Optional[float] = None,
    ):
        MxLoop.__init__(self, loop)
        MxWorkPool.__init__(self, workers)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if dns_timeout is not None and dns_timeout <= 0:
            raise ValueError("dns_timeout must be positive")
        if banner_buffer is not None and banner_buffer < 0:
            raise ValueError("banner_buffer must not be negative")
        self._timeout = timeout
        self._dns_timeout = dns_timeout if dns_timeout is not None else timeout
        self._banner_buffer = banner_buffer
        self._nameservers = tuple(nameservers) if nameservers is not None else None
        self._resolver = resolver
        self._owns_resolver = resolver is None
        self._server_resolvers: Dict[str, DNSResolver] = {}
        self._system_nameservers: Optional[Sequence[str]] = None

    def __enter__(self):
        return self

    def __exit__(self,
                    exc_type: Optional[Type[BaseException]],
                    exc: Optional[BaseException],
                    tb: Optional[TracebackType]):
        if exc_type is KeyboardInterrupt:
            print("\n[!] Scan interrupted by user", file=sys.stderr)
        return False

    async def __aenter__(self):
        return self

    async def aclose(self):
        """
        Release the DNS resolvers created internally 
        """
        resolvers = list(self._server_resolvers.values())
        self._server_resolvers.clear()
        if self._owns_resolver and self._resolver is not None:
            resolvers.append(self._resolver)
            self._resolver = None
        if resolvers:
            await asyncio.gather(*(r.close() for r in resolvers), return_exceptions=True)

    async def __aexit__(self,
                    exc_type: Optional[Type[BaseException]],
                    exc: Optional[BaseException],
                    tb: Optional[TracebackType]):
        await self.aclose()
        if exc_type is KeyboardInterrupt:
            print("\n[!] Scan interrupted by user", file=sys.stderr)
        return False

    def _run(self, coro: Awaitable) -> Coroutine:
        return asyncio.wait_for(coro, timeout=self._timeout)

    async def scan(
        self,
        hosts: Collection[IPAny],
        ports: Sequence[int],
        open: bool = False,
        qtype: str | Sequence[str] = "A",
        all: bool = True,
        verbose: bool = False,
    ) -> AsyncIterator[ScanInfo]:
        # Internal method to resolve all ofthe provided hosts
        async def resolve(original: IPAny, qtype: str | Sequence[str] = "A") -> List[Target]:
            targets: List[Target] = []
            if all:
                results = await self.resolve_all(original, qtype=qtype)
                if results is not None and len(results) > 0:
                    targets.extend(results)
            else:
                result = await self.resolve(original, qtype=qtype)
                if result is not None:
                    targets.append(result)
            if not targets:
                print(f"[!] Warning: failed to resolve host: {original}", file=sys.stderr)
            return targets

        # Task generator to resolve all hosts
        tasks = (resolve(host, qtype=qtype) for host in hosts)
        if verbose:
            start = time.perf_counter()

        # Maintain a list of all resolved targets
        resolved_targets: List[Target] = []
        async with aclosing(self.worker_run_many(tasks)) as results:
            async for targets in results:
                resolved_targets.extend(targets)
        resolved_targets = list(dict.fromkeys(resolved_targets))
        
        if verbose:
            print(
                f"Resolution of {len(hosts)} hosts took {time.perf_counter()-start:.3f} seconds"
            )
            total_hosts = sum(rh.host.num_addresses for rh in resolved_targets)
            print("Scanning", len(ports), "ports on", total_hosts, "hosts")

        tasks = (
            self._scan_port(
                target=target,
                port=port,
            )
            for resolved_target in resolved_targets
            for target in resolved_target
            for port in ports
        )

        if verbose:
            start = time.perf_counter()

        async with aclosing(self.worker_run_many(tasks)) as results:
            async for scan_info in results:
                if not open or scan_info.state == ScanState.OPEN:
                    yield scan_info

        if verbose:
            print(f"Scan executed in {time.perf_counter() - start:.3f} seconds")

    async def scan_port(
        self, host: IPAny, port: int, qtype: str | Sequence[str] = "A"
    ) -> ScanInfo:
        target = await self.resolve(host, qtype)
        if target is None:
            raise ValueError(f"Unable to resolve host: {host}")
        if target.host.num_addresses != 1:
            raise ValueError("scan_port only accepts single IP addresses")
        addrs = list(target.iter_ips())
        return await self.worker_run(self._scan_port(addrs[0], port))

    _family = {
        4: AF_INET,
        6: AF_INET6,
    }

    async def _scan_port(
        self, target: TargetIP, port: int
    ) -> ScanInfo:
        try:
            family = self._family.get(target.addr.version, AF_UNSPEC)
            # Set initial values
            state, banner, reader, writer = ScanState.UNKNOWN, None, None, None
            fut = asyncio.open_connection(host=str(target.addr), port=port, family=family)
            reader, writer = await self._run(fut)
            state = ScanState.OPEN
            if self._banner_buffer:
                data = await self._run(reader.read(self._banner_buffer))
                banner = data.decode("utf-8", errors="ignore").translate(
                    str.maketrans("", "", "\r\n")
                )
        except asyncio.TimeoutError:
            if state == ScanState.UNKNOWN:
                state = ScanState.TIMEOUT
        except ConnectionRefusedError:
            if state == ScanState.UNKNOWN:
                state = ScanState.CLOSED
        except OSError as e:
            # Anything other than a refusal/timeout (e.g. EMFILE from too many
            # concurrent workers, "no route to host", ...): stays UNKNOWN, but
            # surface *why* instead of failing silently.
            banner = str(e)
        finally:
            if writer:
                writer.close()
                with suppress(OSError, asyncio.TimeoutError):
                    await self._run(writer.wait_closed())
        return ScanInfo(name=target.name, addr=target.addr, port=port, state=state, banner=banner)
