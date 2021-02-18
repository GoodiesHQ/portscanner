from portscanner.utils import trycast


def port_range(port_ranges: str, quiet: bool = True):
    """
    Parse port ranges such as:
        80
        80,443
        21-23,80,443,8000-8080
    """
    valid_ports = set()
    for port_range in map(str.strip, port_ranges.split(",")):
        try:
            if "-" not in port_range:
                if (port := trycast(int, port_range)) is not None:
                    if 0 < port < 65536:
                        valid_ports.add(port)
            elif port_range.count("-") == 1:
                start, stop = map(str.strip,port_range.split("-")
                if (start := trycast(int, start)) is None or \
                    (stop := trycast(int, stop)) is None:
                    raise ValueError
                start, stop = (stop, start) if start > stop else (start, stop)
                print(start, stop)
                for i in range(max((0, start)), min((stop, 65535)) + 1):
                    valid_ports.add(i)
            else:
                raise ValueError
        except ValueError:
            if not quiet:
                print("Invalid Port Range:", port_range)
    return sorted(valid_ports)
