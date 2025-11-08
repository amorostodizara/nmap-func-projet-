# import socket
# import time
# import concurrent.futures

# CONNECT_TIMEOUT = 2.0
# BANNER_TIMEOUT = 2.0

# def grab_banner(ip, port, sock):
#     banner = ""
#     sock.settimeout(BANNER_TIMEOUT)
#     try:
#         if port in (80, 8080, 8000, 443):
#             sock.sendall(b"HEAD / HTTP/1.0\r\nHost: local\r\n\r\n")
#         data = sock.recv(1024)
#         if data:
#             banner = data.decode(errors="ignore").strip()
#     except Exception:
#         pass
#     return banner

# def scan_port(ip, port):
#     res = {"ip": ip, "port": port, "state": "closed"}
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(CONNECT_TIMEOUT)
#         start = time.time()
#         sock.connect((ip, port))
#         res["state"] = "open"
#         res["rtt"] = round((time.time() - start) * 1000, 2)
#         res["banner"] = grab_banner(ip, port, sock)
#         sock.close()
#     except socket.timeout:
#         res["state"] = "filtered"
#     except ConnectionRefusedError:
#         res["state"] = "closed"
#     except Exception as e:
#         res["state"] = "error"
#         res["error"] = str(e)
#     return res

# def scan_host_ports(ip, ports, realtime_print=True):
#     results = []
#     with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
#         futures = {ex.submit(scan_port, ip, p): p for p in ports}
#         for fut in concurrent.futures.as_completed(futures):
#             r = fut.result()
#             results.append(r)
#             # 🔹 On n'affiche que les ports ouverts
#             if realtime_print and r["state"] == "open":
#                 snippet = (r.get("banner") or "")[:80]
#                 print(
#                     f"  -> {ip}:{r['port']} OPEN  {('banner: '+snippet) if snippet else ''}"
#                 )
#     return results


# port_scan_win.py
import socket
import time
import concurrent.futures
import json
import os
import re
from typing import List, Dict, Optional

CONNECT_TIMEOUT = 2.0
BANNER_TIMEOUT = 2.0
MAX_WORKERS = 100

# charger DB vuln une seule fois
def load_vuln_db(path="vuln_db.json") -> Dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

VULN_DB = load_vuln_db()

def check_vulns_from_banner(banner: Optional[str], vuln_db: Dict) -> Optional[List[Dict]]:
    if not banner or not vuln_db:
        return None
    found = []
    for product, info in vuln_db.items():
        if product.lower() in banner.lower():
            vers = re.findall(r"(\d+\.\d+(?:\.\d+)*)", banner)
            for v in vers:
                for vv in info.get("vulnerable_versions", []):
                    if v.startswith(vv):
                        found.append({"product": product, "version": v, "notes": info.get("notes")})
    return found if found else None

def grab_banner(sock: socket.socket, ip: str, port: int) -> Optional[str]:
    banner = ""
    sock.settimeout(BANNER_TIMEOUT)
    try:
        if port in (80, 8080, 8000, 443):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: local\r\n\r\n")
            except Exception:
                pass
        data = sock.recv(1024)
        if data:
            banner = data.decode(errors='ignore').strip()
    except Exception:
        pass
    return banner or None

def scan_port(ip: str, port: int) -> Dict:
    out = {"ip": ip, "port": port, "state": "closed", "banner": None, "rtt_ms": None, "vulns": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        start = time.time()
        s.connect((ip, port))
        out["state"] = "open"
        out["rtt_ms"] = round((time.time() - start) * 1000, 2)
        try:
            b = grab_banner(s, ip, port)
            if b:
                out["banner"] = b
                # check vuln
                out["vulns"] = check_vulns_from_banner(b, VULN_DB)
        finally:
            s.close()
    except socket.timeout:
        out["state"] = "filtered"
    except ConnectionRefusedError:
        out["state"] = "closed"
    except Exception as e:
        out["state"] = "error"
        out["error"] = str(e)
    return out

def scan_host_ports(ip: str, ports: List[int], realtime_print: bool = True) -> List[Dict]:
    """
    Scanne les ports et affiche uniquement les ports ouverts (avec bannières/vulns).
    Retourne la liste complète des services (open/closed/filtered).
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            results.append(r)
            # n'affiche que les ports ouverts
            if realtime_print and r.get("state") == "open":
                snippet = (r.get("banner") or "")[:100]
                print(f"  -> {ip}:{r['port']} OPEN  {('banner: '+snippet) if snippet else ''}")
                if r.get("vulns"):
                    for v in r["vulns"]:
                        print(f"     !!! VULN: {v['product']} {v['version']} — {v.get('notes')}")
    return results
