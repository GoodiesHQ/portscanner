"""
Implementation of an asynchronous port scanner
"""

from codecs import decode
from functools import partial
from socket import AF_INET, AF_INET6, AF_UNSPEC
from types import TracebackType
from typing import Optional, List, Type, Sequence, get_args, Collection
import asyncio
import sys
import time
import traceback

from aiodns import DNSResolver

from portscanner.mixins import MxLoop, MxResolver, MxWorkPool
from portscanner.types import IPAddress, IPNetwork, IPAny, ScanInfo, ScanState, Target, TargetIP
from portscanner.utils import flatten


class PortScanner(MxLoop, MxResolver, MxWorkPool):
    """
    Implementation of the port scanner
    """

    _NS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
    _Q = ("A", "AAAA")

    def __init__(
        self,
        workers: int = 10,
        timeout: float = 3.0,
        banner_buffer: Optional[int] = None,
        loop: asyncio.AbstractEventLoop = None,
        resolver: DNSResolver = None,
    ):
        MxLoop.__init__(self, loop)
        MxWorkPool.__init__(self, workers)
        self._timeout = timeout
        self._banner_buffer = banner_buffer
        self._resolver = resolver or DNSResolver(self._NS, loop=self.loop)

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
    
    async def __aexit__(self,
                    exc_type: Optional[Type[BaseException]],
                    exc: Optional[BaseException],
                    tb: Optional[TracebackType]):
        if exc_type is KeyboardInterrupt:
            print("\n[!] Scan interrupted by user", file=sys.stderr)
        return False

    def _run(self, coro):
        return asyncio.wait_for(coro, timeout=self._timeout)

    async def scan(
        self,
        hosts: Collection[IPAny],
        ports: Sequence[int],
        open: bool = False,
        qtype: str = "A",
        all: bool = True,
        verbose: bool = False,
    ):
        # Internal method to resolve all ofthe provided hosts
        async def resolve(original: IPAny, qtype: str = "A") -> List[Target]:
            targets: List[Target] = []
            if all:
                results = await self.resolve_all(original, qtype=qtype)
                if results is not None and len(results) > 0:
                    targets.extend(results)
            else:
                result = await self.resolve(original, qtype=qtype)
                if result is not None:
                    targets.append(result)
            return targets

        # Task generator to resolve all hosts
        tasks = (
            resolve(host, qtype=qt)
              for qt in flatten(qtype)
                for host in iter(hosts)
        )
        if verbose:
            start = time.time()

        # Maintain a list of all resolved targets
        resolved_targets: List[Target] = []
        async for targets in self.worker_run_many(tasks):
            resolved_targets += targets
        
        if verbose:
            print(
                f"Resolution of {len(hosts)} hosts took {time.time()-start:.3f} seconds"
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
            start = time.time()

        async for scan_info in self.worker_run_many(tasks):
            if not open or scan_info.state == ScanState.OPEN:
                yield scan_info

        if verbose:
            print(f"Scan executed in {time.time() - start:.3f} seconds")

    async def worker(self, *args):
        import random

        r = random.randint(1, 10)
        await asyncio.sleep(r / 10.0)
        return r

    async def scan_port(
        self, host: IPAny, port: int, qtype: str = "A"
    ) -> ScanInfo:
        target = await self.resolve(host, qtype)
        if target.host.num_addresses != 1:
            raise ValueError("scan_port only accepts single IP addresses")
        addrs = list(target.iter_ips())
        return await self.worker_run(self._scan_port(addrs[0], port))

    async def _scan_port(
        self, target: TargetIP, port: int
    ) -> ScanInfo:
        try:
            family = {
                4: AF_INET,
                6: AF_INET6,
            }.get(target.addr.version, AF_UNSPEC)

            # Set initial values
            state, banner, reader, writer = ScanState.UNKNOWN, None, None, None
            fut = asyncio.open_connection(host=str(target.addr), port=port, family=family)
            reader, writer = await self._run(fut)
            state = ScanState.OPEN
            if self._banner_buffer:
                writer.write(b"")
                task = self._run(reader.read(self._banner_buffer))
                table = str.maketrans("", "", "\r\n")
                decoder = partial(decode, encoding="utf-8", errors="ignore")
                banner = decoder(await task).translate(table)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            if state == ScanState.UNKNOWN:
                state = ScanState.TIMEOUT
        except (ConnectionRefusedError, OSError) as e:
            if state == ScanState.UNKNOWN:
                state = ScanState.CLOSED
        except Exception as e:
            print(f"Error ({type(e)}):\n{e}", file=sys.stderr)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
            return ScanInfo(name=target.name, addr=target.addr, port=port, state=state, banner=banner)
