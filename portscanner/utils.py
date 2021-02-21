"""
Utilities and helper functions/classes for PortScanner
"""
from collections import namedtuple
from functools import partial, wraps
from itertools import product
from portscanner.types import IPNetwork
from typing import Collection, Iterable, Text
import asyncio


__all__ = [
    "splat",
    "cleanup",
    "bind",
    "trycast",
    "trycast_many",
    "flatten",
]


def splat(func):
    """
    Wrapper for a fuction that will simply accept a tuple and splat into the function
    """

    @wraps(func)
    def splatter(args: tuple, **kwargs):
        return func(*args, **kwargs)

    return splatter


def cleanup(loop: asyncio.AbstractEventLoop):
    """
    Safe cleanup method to destroy all pending tasks
    """
    while (pending := asyncio.all_tasks(loop)) :
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.wait(pending))
    loop.close()


class bind(partial):
    """
    An improved version of partial which accepts Ellipsis (...) as a placeholder
    """

    def __call__(self, *args, **keywords):
        keywords = {**self.keywords, **keywords}
        iargs = iter(args)
        args = (next(iargs) if arg is ... else arg for arg in self.args)
        return self.func(*args, *iargs, **keywords)


def trycast(new_type, value, default=None):
    """
    Attempt to cast `value` as `new_type` or `default` if conversion fails
    """
    try:
        default = new_type(value)
    finally:
        return default


def trycast_many(new_type, value_iter, default=None, flat: bool = False):
    """
    Generator to yield only valid cast items from an iterables
    """
    for value in flatten(value_iter) if flat else value_iter:
        if (new_value := trycast(new_type, value, default)) is not default:
            yield new_value


def flatten(*values):
    """
    Flatten one or several iterables into one generator
    """
    for value in values:
        if not isinstance(value, Text) and isinstance(value, Iterable):
            for val in value:
                yield from flatten(val)
        else:
            yield value


def flattener(**iterables):
    """
    Nested loop through named iterables. The names provided of the iterables
    are the name names provided in the output, but each `yield` will be
    equivalent to nested
    """
    names, iters = zip(*iterables.items())
    Value = namedtuple("Value", names)

    for values in product(*map(flatten, iters)):
        yield Value(*values)
