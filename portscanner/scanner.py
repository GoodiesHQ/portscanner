"""
Implementation of an asynchronous port scanner
"""

from codecs import decode
from contextlib import suppress
from dataclasses import dataclass
from enum import IntEnum, auto
from functools import partial
from ipaddress import ip_address
from socket import AF_INET, AF_INET6, AF_UNSPEC
from typing import Optional, List, Union, Sequence, get_args, Iterable, Collection
import asyncio
import sys
import time

from aiodns import DNSResolver
from aiodns.error import DNSError

from portscanner.mixins import MxLoop, MxResolver, MxWorkPool
from portscanner.types import IPAddress, IPNetwork, IPTypes, IPAny, ScanInfo, ScanState
from portscanner.utils import trycast, trycast_many, flattener, flatten


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

    def __exit__(self, *args):
        return True

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
        resolved_hosts = []

        # Resolve all hosts first before scanning is initiated
        resolver = self.resolve_all if all else self.resolve
        tasks = (
            resolver(host, qtype=qt) for qt in flatten(qtype) for host in iter(hosts)
        )
        if verbose:
            start = time.time()
        async for resolved_host in self.worker_run_many(tasks):
            if resolved_host:
                if isinstance(resolved_host, List):
                    resolved_hosts += resolved_host
                else:
                    resolved_hosts.append(resolved_host)

        if verbose:
            print(
                f"Resolution of {len(hosts)} hosts took {time.time()-start:.3f} seconds"
            )
            total_hosts = sum(rh.num_addresses for rh in resolved_hosts)
            print("Scanning", len(ports), "ports on", total_hosts, "hosts")

        data_gen = flattener(host=resolved_hosts, port=ports)
        tasks = (self._scan_port(*data) for data in data_gen)

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
        self, host: Union[IPAddress, str], port: int, qtype: str = "A"
    ) -> ScanInfo:
        return await self.worker_run(self._scan_port(host, port, qtype))

    async def _scan_port(
        self, host: Union[IPAddress, str], port: int, qtype: str = "A"
    ) -> ScanInfo:
        try:
            if (host := await self.resolve(host)) is None:
                raise ValueError(f"Invalid host '{host}'")
            if isinstance(host, get_args(IPNetwork)):
                host = host[0]

            family = {
                4: AF_INET,
                6: AF_INET6,
            }.get(host.version, AF_UNSPEC)

            # Set initial values
            state, banner, reader, writer = ScanState.UNKNOWN, None, None, None
            fut = asyncio.open_connection(host=str(host), port=port, family=family)
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
            return ScanInfo(host=host, port=port, state=state, banner=banner)
