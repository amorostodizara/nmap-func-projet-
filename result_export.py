# import json
# import csv
# from tabulate import tabulate

# def print_table(results):
#     if not results:
#         print("[*] Aucun résultat.")
#         return
#     rows = [[r.get("ip"), r.get("port"), r.get("state"),
#              r.get("rtt", ""), (r.get("banner") or "")[:80]] for r in results]
#     headers = ["IP", "Port", "Etat", "RTT(ms)", "Banner"]
#     print(tabulate(rows, headers=headers, tablefmt="grid"))

# def export_results(results, filename, fmt):
#     if fmt == "json":
#         with open(filename, "w", encoding="utf-8") as f:
#             json.dump(results, f, indent=2, ensure_ascii=False)
#     elif fmt == "csv":
#         keys = ["ip", "port", "state", "rtt", "banner", "error"]
#         with open(filename, "w", newline="", encoding="utf-8") as f:
#             writer = csv.DictWriter(f, fieldnames=keys)
#             writer.writeheader()
#             for r in results:
#                 writer.writerow({k: r.get(k, "") for k in keys})
#     print(f"[+] Exporté: {filename}")

# result_export.py
import json
import csv
from typing import List, Dict
try:
    from tabulate import tabulate
except Exception:
    tabulate = None

def print_host_summary(host_obj: Dict, services: List[Dict], os_info=None):
    """
    Affiche résumé pour un hôte:
      IP, MAC, Hostname, OS, puis ports ouverts / vulnérabilités
    """
    ip = host_obj.get("ip")
    print(f"\n=== {ip} ===")
    if host_obj.get("mac"):
        print(f"MAC: {host_obj.get('mac')}")
    if host_obj.get("hostname"):
        print(f"Nom: {host_obj.get('hostname')}")
    if os_info:
        print(f"OS: {os_info.get('os_guess')} (TTL={os_info.get('ttl')})")
    open_services = [s for s in services if s.get("state") == "open"]
    if not open_services:
        print(" -> Aucun port ouvert détecté.")
        return
    for s in open_services:
        banner = (s.get("banner") or "")[:120]
        print(f" -> {ip}:{s['port']} OPEN  {('banner: '+banner) if banner else ''}")
        if s.get("vulns"):
            for v in s["vulns"]:
                print(f"    !!! VULN: {v['product']} {v['version']} — {v.get('notes')}")

def export_results_flat(all_hosts: List[Dict], filename: str, fmt: str):
    """
    Exporte les résultats globaux:
    all_hosts: [ { ip, mac, hostname, os: {...}, services: [ ... ] }, ... ]
    """
    if fmt == "json":
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(all_hosts, f, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        # Écriture CSV "une ligne par service"
        keys = ["ip","mac","hostname","os_guess","ttl","port","state","banner","vulns"]
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for host in all_hosts:
                os_guess = host.get("os",{}).get("os_guess")
                ttl = host.get("os",{}).get("ttl")
                for s in host.get("services",[]):
                    writer.writerow({
                        "ip": host.get("ip"),
                        "mac": host.get("mac"),
                        "hostname": host.get("hostname"),
                        "os_guess": os_guess,
                        "ttl": ttl,
                        "port": s.get("port"),
                        "state": s.get("state"),
                        "banner": (s.get("banner") or "")[:200],
                        "vulns": json.dumps(s.get("vulns") or [])
                    })
    print(f"[+] Exporté: {filename}")
