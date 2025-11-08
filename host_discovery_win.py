# import subprocess
# import platform
# import concurrent.futures
# import socket
# import ipaddress

# def parse_arp_a_output(output: str):
#     ips = set()
#     for ln in output.splitlines():
#         ln = ln.strip()
#         parts = ln.split()
#         if len(parts) >= 2 and parts[0].count(".") == 3:
#             try:
#                 ipaddress.ip_address(parts[0])
#                 ips.add(parts[0])
#             except Exception:
#                 pass
#     return list(ips)

# def get_arp_table_windows():
#     try:
#         res = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
#         return parse_arp_a_output(res.stdout)
#     except Exception:
#         return []

# def discover_hosts(network, quick_probe_ports=(80, 443)):
#     discovered = set()
#     print(f"[+] Découverte sur {network} ...")
#     if platform.system().lower().startswith("win"):
#         for ip in get_arp_table_windows():
#             try:
#                 if ipaddress.ip_address(ip) in network:
#                     discovered.add(ip)
#             except Exception:
#                 pass

#     def probe(ip):
#         for p in quick_probe_ports:
#             try:
#                 s = socket.create_connection((str(ip), p), timeout=1)
#                 s.close()
#                 return True
#             except Exception:
#                 continue
#         return False

#     to_probe = [ip for ip in network.hosts() if str(ip) not in discovered]
#     with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
#         futures = {ex.submit(probe, ip): ip for ip in to_probe}
#         for fut in concurrent.futures.as_completed(futures):
#             ip = futures[fut]
#             try:
#                 if fut.result():
#                     discovered.add(str(ip))
#                     print(f"  • {ip} => alive")
#             except Exception:
#                 pass
#     return sorted(discovered)

# host_discovery_win.py
import subprocess
import platform
import concurrent.futures
import socket
import ipaddress
import re
from typing import List, Dict, Optional

def parse_arp_a_output(output: str) -> List[str]:
    ips = set()
    for ln in output.splitlines():
        ln = ln.strip()
        parts = ln.split()
        if len(parts) >= 2 and parts[0].count(".") == 3:
            try:
                ipaddress.ip_address(parts[0])
                ips.add(parts[0])
            except Exception:
                pass
    return list(ips)

def get_arp_table_windows() -> List[str]:
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
        return parse_arp_a_output(res.stdout)
    except Exception:
        return []

def mac_from_arp(ip: str) -> Optional[str]:
    """Retourne la MAC pour une IP via 'arp -a IP' si présente."""
    try:
        p = subprocess.run(["arp","-a", ip], capture_output=True, text=True, check=False)
        out = p.stdout
        for ln in out.splitlines():
            if ip in ln:
                parts = ln.split()
                for part in parts:
                    # Windows MAC format ex: 00-11-22-33-44-55
                    if '-' in part and re.match(r'^[0-9A-Fa-f\-]{17,}$', part):
                        return part
    except Exception:
        pass
    return None

def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def nbt_name(ip: str) -> Optional[str]:
    """Tentative NetBIOS name via nbtstat -A (Windows)."""
    if platform.system().lower().startswith("win"):
        try:
            p = subprocess.run(["nbtstat","-A", ip], capture_output=True, text=True, check=False)
            out = p.stdout
            # Heuristique : trouver la première token printable utile
            for ln in out.splitlines():
                if "<20>" in ln or "<00>" in ln:
                    parts = ln.split()
                    for tok in parts:
                        if not tok.startswith("<") and len(tok.strip()) > 1:
                            return tok.strip()
        except Exception:
            pass
    return None

def discover_hosts(network: ipaddress.IPv4Network, quick_probe_ports=(80, 443)) -> List[Dict]:
    """
    Découverte : combine ARP table + probes TCP.
    Retourne liste d'objets: { "ip": "...", "mac": "...", "hostname": "..." }
    """
    discovered_ips = set()
    hosts = []

    print(f"[+] Découverte sur {network} ...")

    # 1) ARP passive
    if platform.system().lower().startswith("win"):
        arp_ips = get_arp_table_windows()
        for ip in arp_ips:
            try:
                if ipaddress.ip_address(ip) in network:
                    discovered_ips.add(ip)
            except Exception:
                pass
        if discovered_ips:
            print(f"  • Découvert via ARP: {len(discovered_ips)} hôte(s)")

    # 2) TCP-probe pour compléter (80/443 typiquement)
    def probe(ip):
        for p in quick_probe_ports:
            try:
                s = socket.create_connection((str(ip), p), timeout=1)
                s.close()
                return True
            except Exception:
                continue
        return False

    to_probe = [ip for ip in network.hosts() if str(ip) not in discovered_ips]
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futures = {ex.submit(probe, ip): ip for ip in to_probe}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    discovered_ips.add(str(ip))
                    print(f"  • {ip} => alive (tcp probe)")
            except Exception:
                pass

    # Construire la liste finale d'hôtes enrichis (ip, mac, hostname)
    for ip in sorted(discovered_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = mac_from_arp(ip)
        hostname = reverse_dns(ip) or nbt_name(ip)
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname})

    print(f"[+] Découverte terminée — {len(hosts)} hôte(s) trouvés.")
    return hosts

