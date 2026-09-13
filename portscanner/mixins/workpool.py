"""
WorkPool implementation to allow for limited execution of an unbounded number of tasks
"""

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Coroutine, Iterable
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

    @property
    @abstractmethod
    def worker_available(self) -> bool:
        """Return True if workers are available, False if semahore is locked"""

    @property
    @abstractmethod
    def worker_sem(self) -> asyncio.Semaphore:
        """Read-only handle to the worker semaphore used"""

    @property
    @abstractmethod
    def worker_count(self) -> int:
        """Number of workers"""

    @abstractmethod
    def worker_run(self, coro: Coroutine, *callbacks) -> asyncio.Task:
        """Run a single coroutine in the pool and return its corresponding task"""

    @abstractmethod
    def worker_run_many(
        self, coros: Iterable[Coroutine], timeout: float = 1.0
    ) -> AsyncIterator[Any]:
        """Run coroutines in the pool, bounded to worker_count at a time, yielding results as they complete"""


class MxWorkPool(MxWorkPoolBase):
    """Workpool implementation"""

    def __init__(self, worker_count: int):
        """Set worker count and create the shared semaphore"""
        if worker_count < 1:
            raise ValueError("workers must be positive")
        self._worker_count = worker_count
        self.__sem = asyncio.Semaphore(worker_count)

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if getattr(self, "_loop", None) is not None:
            return self._loop
        return asyncio.get_running_loop()

    @property
    def worker_available(self) -> bool:
        return not self.__sem.locked()

    @property
    def worker_sem(self) -> asyncio.Semaphore:
        return self.__sem

    @property
    def worker_count(self) -> int:
        return self._worker_count

    def worker_run(self, coro: Coroutine, *callbacks) -> asyncio.Task:
        started = False

        async def worker():
            nonlocal started
            async with self.worker_sem:
                started = True
                return await coro

        def close_unstarted(task):
            if not started:
                coro.close()

        task = self.loop.create_task(worker())
        task.add_done_callback(close_unstarted)
        for callback in callbacks:
            task.add_done_callback(callback)
        return task

    async def worker_run_many(self, coros: Iterable[Coroutine], timeout: float = 1.0):
        """
        Yield completed results with bounded task creation.

        The timeout argument is retained for compatibility; completion wakes the
        pool immediately, without polling.
        """
        iterator = iter(coros)
        pending = set()
        exhausted = False
        try:
            while True:
                while not exhausted and len(pending) < self.worker_count:
                    try:
                        coro = next(iterator)
                    except StopIteration:
                        exhausted = True
                    else:
                        pending.add(self.worker_run(coro))
                if not pending:
                    break
                done, _ = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    result = task.result()
                    pending.remove(task)
                    yield result
        finally:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
