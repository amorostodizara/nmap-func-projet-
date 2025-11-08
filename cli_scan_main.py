# #!/usr/bin/env python3
# import argparse
# import sys
# import ipaddress
# import time

# from net_utils import get_primary_ip, get_netmask_for_ip
# from host_discovery_win import discover_hosts
# from port_scan_win import scan_host_ports
# from result_export import print_table, export_results

# DEFAULT_PORTS = [22, 80, 443, 3389, 3306]

# def main():
#     parser = argparse.ArgumentParser(description="Mini Scanner Windows modulaire")
#     sub = parser.add_subparsers(dest="cmd")

#     p_disc = sub.add_parser("discover")
#     p_scan = sub.add_parser("scan")
#     p_scan.add_argument("--target", required=True)
#     p_scan.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
#     p_scan.add_argument("--out", choices=("json"))

#     p_full = sub.add_parser("full")
#     p_full.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
#     p_full.add_argument("--out", choices=("json", "csv"))

#     args = parser.parse_args()

#     if args.cmd == "discover":
#         ip = get_primary_ip()
#         if not ip:
#             print("[!] IP locale non détectée.")
#             sys.exit(1)
#         net = get_netmask_for_ip(ip)
#         print(f"[+] IP: {ip} Réseau: {net}")
#         hosts = discover_hosts(net)
#         print(f"[+] Hôtes trouvés ({len(hosts)}): {hosts}")

#     elif args.cmd == "scan":
#         try:
#             net = ipaddress.ip_network(args.target, strict=False)
#         except Exception:
#             print("[!] target invalide.")
#             sys.exit(1)
#         ports = [int(p) for p in args.ports.split(",") if p.strip()]
#         all_res = []
#         for ip in net.hosts():
#             all_res += scan_host_ports(str(ip), ports)
#         print_table(all_res)
#         if args.out:
#             export_results(all_res, f"scan_{int(time.time())}.{args.out}", args.out)

#     elif args.cmd == "full":
#         ip = get_primary_ip()
#         net = get_netmask_for_ip(ip)
#         ports = [int(p) for p in args.ports.split(",") if p.strip()]
#         hosts = discover_hosts(net)
#         all_res = []
#         for ip in hosts:
#             all_res += scan_host_ports(ip, ports)
#         print_table(all_res)
#         if args.out:
#             export_results(all_res, f"fullscan_{int(time.time())}.{args.out}", args.out)

#     else:
#         parser.print_help()

# if __name__ == "__main__":
#     main()

# cli_scan_main.py
#!/usr/bin/env python3
import argparse
import sys
import ipaddress
import time
import os

from net_utils import get_primary_ip, get_netmask_for_ip  # si tu as ce module; sinon fallback below
from host_discovery_win import discover_hosts
from port_scan_win import scan_host_ports
from os_detection import detect_os
from result_export import print_host_summary, export_results_flat

# fallback get_primary_ip/get_netmask_for_ip si net_utils absent
try:
    from net_utils import get_primary_ip as _gpi, get_netmask_for_ip as _gnm
    get_primary_ip = _gpi
    get_netmask_for_ip = _gnm
except Exception:
    import socket, ipaddress
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
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except Exception:
            return None

DEFAULT_PORTS = [22, 80, 443, 3389, 3306]

def main():
    parser = argparse.ArgumentParser(description="CLI Scanner — découvre hôtes, scan ports, détecte OS, affiche vuln")
    sub = parser.add_subparsers(dest="cmd")

    p_disc = sub.add_parser("discover", help="Découvrir les hôtes")
    p_disc.add_argument("--outdir", default=".", help="Dossier de sortie")

    p_scan = sub.add_parser("scan", help="Scanner une cible (CIDR)")
    p_scan.add_argument("--target", required=True)
    p_scan.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
    p_scan.add_argument("--out", choices=("json","csv"), default=None)
    p_scan.add_argument("--outdir", default=".", help="Dossier de sortie")

    p_full = sub.add_parser("full", help="Découverte auto + scan ports + os")
    p_full.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS))
    p_full.add_argument("--out", choices=("json","csv"), default=None)
    p_full.add_argument("--outdir", default=".", help="Dossier de sortie")

    args = parser.parse_args()

    if args.cmd == "discover":
        ip = get_primary_ip()
        if not ip:
            print("[!] IP locale non détectée.")
            sys.exit(1)
        net = get_netmask_for_ip(ip)
        print(f"[+] IP: {ip} Réseau: {net}")
        hosts = discover_hosts(net)
        print(f"[+] Hôtes trouvés ({len(hosts)}):")
        for h in hosts:
            print(f" - {h.get('ip')}  MAC:{h.get('mac') or '-'}  Host:{h.get('hostname') or '-'}")
        sys.exit(0)

    if args.cmd == "scan":
        try:
            net = ipaddress.ip_network(args.target, strict=False)
        except Exception:
            print("[!] target invalide.")
            sys.exit(1)
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        hosts = discover_hosts(net)
        all_hosts = []
        for host in hosts:
            ip = host.get("ip")
            print(f"\n[+] Traitement {ip}")
            services = scan_host_ports(ip, ports)
            os_info = detect_os(ip)
            print_host_summary(host, services, os_info)
            host_entry = {
                "ip": ip,
                "mac": host.get("mac"),
                "hostname": host.get("hostname"),
                "os": os_info,
                "services": services
            }
            all_hosts.append(host_entry)
        if args.out:
            fname = os.path.join(args.outdir, f"scan_{int(time.time())}.{args.out}")
            export_results_flat(all_hosts, fname, args.out)
        sys.exit(0)

    if args.cmd == "full":
        ip = get_primary_ip()
        if not ip:
            print("[!] IP locale non détectée.")
            sys.exit(1)
        net = get_netmask_for_ip(ip)
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        hosts = discover_hosts(net)
        if not hosts:
            print("[!] Aucun hôte découvert — sortie.")
            sys.exit(0)
        all_hosts = []
        for host in hosts:
            ip = host.get("ip")
            print(f"\n[+] Traitement {ip}")
            services = scan_host_ports(ip, ports)
            os_info = detect_os(ip)
            print_host_summary(host, services, os_info)
            host_entry = {
                "ip": ip,
                "mac": host.get("mac"),
                "hostname": host.get("hostname"),
                "os": os_info,
                "services": services
            }
            all_hosts.append(host_entry)
        if args.out:
            fname = os.path.join(args.outdir, f"fullscan_{int(time.time())}.{args.out}")
            export_results_flat(all_hosts, fname, args.out)
        sys.exit(0)

    parser.print_help()

if __name__ == "__main__":
    main()
