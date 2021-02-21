"""
WorkPool implementation to allow for limited execution of an unbounded number of tasks
"""
from abc import ABC, abstractmethod, abstractproperty
from contextlib import suppress
from typing import Coroutine, Callable, Iterable
import asyncio

__all__ = [
    "MxWorkPoolBase",
    "MxWorkPool",
]


class MxWorkPoolBase(ABC):
    """
    Provides async multi-worker functionality to a class
    """

    @abstractmethod
    def __init__(self, worker_count: int):
        """Initialize the work pool"""

    @abstractproperty
    def worker_available(self) -> bool:
        """Return True if workers are available, False if semahore is locked"""

    @abstractproperty
    def worker_sem(self) -> asyncio.Semaphore:
        """Read-only handle to the worker semaphore used"""

    @abstractproperty
    def worker_count(self) -> int:
        """Number of workers"""

    @abstractmethod
    async def worker_run(self, coro: Coroutine) -> asyncio.Future:
        """Run a single corotuine in the pool and return its corresponding future"""

    @abstractmethod
    async def worker_run_many(self, coros: Coroutine) -> asyncio.Future:
        """Run a single corotuine in the pool and return its corresponding future"""


class MxWorkPool(MxWorkPoolBase):
    """Workpool implementation"""

    def __init__(self, worker_count: int):
        """Set worker count and create the shared semaphore"""
        self._worker_count = worker_count
        self.__sem = asyncio.Semaphore(worker_count)

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if hasattr(self, "_loop"):
            return self._loop
        return asyncio.get_event_loop()

    @property
    def worker_available(self) -> bool:
        return not self.__sem.locked()

    @property
    def worker_sem(self) -> asyncio.Semaphore:
        return self.__sem

    @property
    def worker_count(self) -> int:
        return self._worker_count

    def worker_run(self, coro: Coroutine, *callbacks) -> asyncio.Future:
        async def worker():
            # with suppress(asyncio.CancelledError):
            async with self.worker_sem:
                return await coro

        fut = self.loop.create_task(worker())
        for callback in callbacks:
            fut.add_done_callback(callback)
        return fut

    async def worker_run_many(self, coros: Iterable[Coroutine], timeout: float = 1.0):
        futures = set()
        init = False

        async def check(t):
            nonlocal futures
            if futures:
                done, futures = await asyncio.wait(
                    futures, timeout=t, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    if not task.cancelled() and not task.exception():
                        yield task.result()

        wait = 0
        try:
            while futures or not init:
                init = True
                async for item in check(wait):
                    yield item
                if len(futures) < self.worker_count:
                    wait = 0
                    with suppress(StopIteration):
                        futures.add(self.worker_run(next(coros)))
                        continue
                wait = timeout
        except asyncio.CancelledError:
            for future in futures:
                future.cancel()
