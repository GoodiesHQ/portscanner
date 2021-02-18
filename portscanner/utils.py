"""
Utilities for PortScanner
"""

from functools import partial

__all__ = [
    "bind", "trycast",
]


class bind(partial):
    """
    An improved version of partial which accepts Ellipsis object (...) as a placeholder
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
