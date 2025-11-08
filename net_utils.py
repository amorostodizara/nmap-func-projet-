import socket
import ipaddress
try:
    import psutil
except Exception:
    psutil = None

def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def get_netmask_for_ip(ip):
    """Retourne ip_network pour une IP donnée"""
    if not ip:
        return None
    if psutil:
        for ifname, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == ip:
                    if getattr(addr, "netmask", None):
                        try:
                            return ipaddress.ip_network(f"{ip}/{addr.netmask}", strict=False)
                        except Exception:
                            pass
    try:
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except Exception:
        return None
