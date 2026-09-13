"""
Loop acquisition mixin for PortScanner
"""

from abc import ABC, abstractmethod
from typing import Optional
import asyncio

__all__ = [
    "MxLoopBase",
    "MxLoop",
]


class MxLoopBase(ABC):
    @property
    @abstractmethod
    def loop(self) -> asyncio.AbstractEventLoop:
        """
        Get the stored event loop or return one from the environment
        Should be stored in `self._loop` in the child class
        """

    @staticmethod
    @abstractmethod
    def _get_loop() -> asyncio.AbstractEventLoop:
        """
        Get the environment loop. It is up to the implementation
        if you'd like to raise an exception or create and set a new loop
        """


class MxLoop(MxLoopBase):
    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        self._loop = loop

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        return self._loop or self._get_loop()

    @staticmethod
    def _get_loop() -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()
