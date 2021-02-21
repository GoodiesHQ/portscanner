"""
Loop acquisition mixin for PortScanner
"""

from abc import ABC, abstractstaticmethod, abstractproperty
from contextlib import suppress
from typing import Optional
import asyncio

__all__ = [
    "MXLoopBase",
    "MXLoop",
]


class MxLoopBase(ABC):
    @abstractproperty
    def loop(self) -> asyncio.AbstractEventLoop:
        """
        Get the stored event loop or return one from the environment
        Should be stored in `self._loop` in the child class
        """

    @abstractstaticmethod
    def _get_loop() -> asyncio.AbstractEventLoop:
        """
        Get the environment loop. It is up to the implementation
        if you'd like to raise an exception or create and set a new loop
        """


class MxLoop(MxLoopBase):
    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._loop = loop or self._get_loop()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop or self._get_loop()

    @staticmethod
    def _get_loop() -> Optional[asyncio.AbstractEventLoop]:
        with suppress(RuntimeError):
            return getattr(
                asyncio,
                "get_running_loop",
                asyncio.get_event_loop,
            )()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop
