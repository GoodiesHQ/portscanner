"""
Colors used for output, particularly in the run module
"""

from colorama import init, Fore, Style


__all__ = [
    "Clr",
]


class Clr:
    """3-Letter Color Constants"""

    init = init

    RST = Style.RESET_ALL
    BRT = Style.BRIGHT

    GRN = BRT + Fore.GREEN
    BLU = BRT + Fore.BLUE
    CYN = BRT + Fore.CYAN
    YLW = BRT + Fore.YELLOW
    PRP = BRT + Fore.MAGENTA
    RED = BRT + Fore.RED
    WHT = BRT + Fore.WHITE
