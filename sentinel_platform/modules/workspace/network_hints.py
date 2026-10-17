"""Reachable-address suggestions only; users remain free to choose another NIC."""
import ipaddress,socket
def addresses():
    values=[]
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            # UDP connect chooses a route without sending any traffic.
            probe.connect(('192.0.2.1',9));values.append(probe.getsockname()[0])
    except OSError:pass
    try:values.extend(row[4][0] for row in socket.getaddrinfo(socket.gethostname(),None,type=socket.SOCK_STREAM))
    except OSError:pass
    result=[]
    for value in values:
        try:address=ipaddress.ip_address(value)
        except ValueError:continue
        if not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast) and str(address) not in result:result.append(str(address))
    return result
