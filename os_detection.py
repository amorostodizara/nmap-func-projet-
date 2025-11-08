# os_detection.py
import platform
import subprocess
import re
from typing import Dict, Optional

def detect_os(ip: str) -> Dict[str, Optional[object]]:
    """
    Ping l'hôte (1 echo) et déduit le TTL -> heuristique OS.
    Retourne: { "ttl": int|None, "os_guess": "..."}.
    """
    param = "-n" if platform.system().lower().startswith("win") else "-c"
    try:
        p = subprocess.run(["ping", param, "1", ip], capture_output=True, text=True, check=False)
        out = p.stdout
        m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        ttl = int(m.group(1)) if m else None
    except Exception:
        ttl = None

    if ttl is None:
        return {"ttl": None, "os_guess": None}

    if ttl >= 128:
        guess = "Windows (estimation)"
    elif ttl >= 100:
        guess = "Possiblement Windows"
    elif ttl >= 64:
        guess = "Linux/Unix (estimation)"
    else:
        guess = "Equipement réseau / TTL faible"

    return {"ttl": ttl, "os_guess": guess}
