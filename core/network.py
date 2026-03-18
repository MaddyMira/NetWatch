"""
core/network.py
───────────────
All raw network operations:
  • Pinging (single host or fast discovery ping) — IPv4 and IPv6
  • Network interface detection (Windows ipconfig + route table)
  • Parallel subnet scan
  • Device-type classification
"""
import concurrent.futures
import ipaddress
import os
import socket
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

try:
    from ping3 import ping as _ping3
except ImportError:
    import sys
    raise ImportError("ping3 is not installed. Run: pip install ping3") from None


def _is_ipv6(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address)
    except ValueError:
        return False


def _ping6(ip: str, timeout: float) -> Optional[float]:
    """
    ICMP6 ping via system command.  Returns latency in ms or None.
    Falls back gracefully if ping6 / ping -6 is unavailable.
    """
    if os.name == 'nt':
        cmd = ['ping', '-6', '-n', '1', '-w', str(int(timeout * 1000)), ip]
    else:
        # Try ping6 first, fall back to ping -6
        ping_bin = 'ping6' if os.path.exists('/bin/ping6') or os.path.exists('/usr/bin/ping6') else 'ping'
        cmd = [ping_bin] + (['-6'] if ping_bin == 'ping' else []) + ['-c', '1', '-W', str(int(timeout)), ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0),
        )
        if result.returncode != 0:
            return None
        # Parse "time=X ms" or "time=X.Xms"
        import re
        m = re.search(r'[Tt]ime[=<]\s*([\d.]+)\s*ms', result.stdout)
        if m:
            return float(m.group(1))
        return 1.0   # alive but no timing line (rare on some OS)
    except Exception:
        return None


# ── Ping helpers ─────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 3.0, retries: int = 2) -> Optional[float]:
    """
    Ping *ip* up to *retries+1* times.  Works for both IPv4 and IPv6.
    Returns latency in **milliseconds**, or *None* if unreachable.
    """
    if _is_ipv6(ip):
        for _ in range(retries + 1):
            lat = _ping6(ip, timeout)
            if lat is not None:
                return lat
        return None

    for _ in range(retries + 1):
        try:
            result = _ping3(ip, timeout=timeout)
            if result is not None:
                return result * 1000.0
        except Exception:
            continue
    return None


def ping_host_fast(ip: str) -> Optional[Tuple[str, float]]:
    """
    Single-shot ping with a 1-second timeout, intended for discovery scans.
    Returns (ip, latency_ms) or *None*.  Supports IPv4 only (discovery is
    subnet-based and subnets are always IPv4 CIDR here).
    """
    try:
        result = _ping3(str(ip), timeout=1)
        if result is not None:
            return str(ip), result * 1000.0
    except Exception:
        pass
    return None


# ── Network interface detection ───────────────────────────────────────────────

def detect_networks() -> List[Dict]:
    """
    Return a list of network dicts (keys: network, interface, ip, gateway, priority),
    sorted by priority (1 = Ethernet, 2 = Wi-Fi, 3 = VPN/route, 4-5 = fallback).
    """
    nets: List[Dict] = []
    if os.name == 'nt':
        nets.extend(_parse_ipconfig())
    nets.extend(_parse_route_table())
    if not nets:
        nets.extend(_fallback_networks())

    seen, unique = set(), []
    for n in nets:
        if n['network'] not in seen:
            seen.add(n['network'])
            unique.append(n)
    return sorted(unique, key=lambda x: x['priority'])


def _parse_ipconfig() -> List[Dict]:
    nets = []
    try:
        r = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, shell=True)
        adapter = ip = subnet = gateway = None

        for raw_line in r.stdout.splitlines():
            line = raw_line.strip()

            if 'adapter' in line.lower() and ':' in line:
                # Flush previous adapter
                if adapter and ip and gateway:
                    net = _calc_network(ip, subnet or '255.255.255.0')
                    if net:
                        nets.append({'network': net, 'interface': adapter,
                                     'ip': ip, 'gateway': gateway,
                                     'priority': _iface_priority(adapter)})
                adapter = line.replace(':', '').strip()
                ip = subnet = gateway = None

            elif 'IPv4 Address' in line or 'IP Address' in line:
                candidate = line.split(':')[-1].strip().replace('(Preferred)', '').strip()
                if _valid_ip(candidate) and not candidate.startswith('169.254'):
                    ip = candidate

            elif 'Subnet Mask' in line:
                subnet = line.split(':')[-1].strip()

            elif 'Default Gateway' in line:
                gw = line.split(':')[-1].strip()
                if _valid_ip(gw):
                    gateway = gw

        # Flush last adapter
        if adapter and ip and gateway:
            net = _calc_network(ip, subnet or '255.255.255.0')
            if net:
                nets.append({'network': net, 'interface': adapter,
                             'ip': ip, 'gateway': gateway,
                             'priority': _iface_priority(adapter)})
    except Exception as e:
        print(f"[network] ipconfig parse error: {e}")
    return nets


def _parse_route_table() -> List[Dict]:
    nets = []
    try:
        cmd = ['route', 'print'] if os.name == 'nt' else ['route', '-n']
        r = subprocess.run(cmd, capture_output=True, text=True,
                           shell=(os.name == 'nt'))
        for line in r.stdout.splitlines():
            parts = line.split()
            if os.name == 'nt':
                if (len(parts) >= 4 and parts[0] != '0.0.0.0'
                        and _valid_ip(parts[0]) and _valid_ip(parts[1])):
                    net = _calc_network(parts[0], parts[1])
                    if net and not (net.startswith('127.') or
                                   net.startswith('169.254')):
                        nets.append({
                            'network': net, 'interface': 'Route Table',
                            'ip': parts[0],
                            'gateway': parts[2] if len(parts) > 2 else '',
                            'priority': 3,
                        })
            else:
                if len(parts) >= 8 and parts[0] != '0.0.0.0' and '/' in parts[0]:
                    nets.append({
                        'network': parts[0],
                        'interface': parts[-1],
                        'ip': '',
                        'gateway': parts[1] if len(parts) > 1 else '',
                        'priority': 3,
                    })
    except Exception as e:
        print(f"[network] route table parse error: {e}")
    return nets


def _fallback_networks() -> List[Dict]:
    return [
        {'network': '192.168.1.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
        {'network': '192.168.0.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
        {'network': '10.0.0.0/24',    'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
        {'network': '172.16.0.0/24',  'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 4},
        {'network': '192.168.2.0/24', 'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 5},
        {'network': '10.0.1.0/24',    'interface': 'Common Range', 'ip': '', 'gateway': '', 'priority': 5},
    ]


def _calc_network(ip: str, mask: str) -> Optional[str]:
    try:
        cidr = _mask_to_cidr(mask) if '.' in mask else int(mask)
        return str(ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False))
    except Exception:
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{'.'.join(parts[:3])}.0/24"
        except Exception:
            pass
    return None


def _mask_to_cidr(mask: str) -> int:
    try:
        return bin(struct.unpack("!I", socket.inet_aton(mask))[0]).count('1')
    except Exception:
        return {'255.255.255.0': 24, '255.255.0.0': 16, '255.0.0.0': 8}.get(mask, 24)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _iface_priority(name: str) -> int:
    n = name.lower()
    if 'ethernet' in n or 'local area' in n: return 1
    if 'wi-fi' in n or 'wireless' in n:      return 2
    if 'vpn' in n or 'virtual' in n:         return 3
    return 4


# ── Subnet scan ──────────────────────────────────────────────────────────────

def scan_network(
    network: str,
    max_workers: int = 64,
) -> List[Tuple[str, float]]:
    """
    Ping every host in *network* (CIDR) concurrently.
    Returns a list of (ip, latency_ms) for alive hosts only.
    """
    net_obj = ipaddress.IPv4Network(network)
    alive: List[Tuple[str, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ping_host_fast, str(ip)): ip for ip in net_obj.hosts()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    return alive


# ── Device classification ─────────────────────────────────────────────────────

_HOSTNAME_PATTERNS = {
    'Router/Gateway': ['router', 'gateway', 'gw', 'fw', 'firewall'],
    'Printer':        ['printer', 'prnt', 'hp', 'canon', 'epson', 'brother', 'xerox'],
    'Camera/NVR':     ['camera', 'cam', 'nvr', 'dvr', 'ipc', 'hikvision', 'dahua'],
    'NAS/Storage':    ['nas', 'storage', 'synology', 'qnap', 'freenas', 'truenas'],
    'Access Point':   ['ap', 'wifi', 'wireless', 'unifi', 'ubnt'],
    'Server':         ['server', 'srv', 'esxi', 'proxmox', 'pve', 'vmware'],
    'Smart TV/Media': ['tv', 'chromecast', 'roku', 'firetv', 'appletv', 'shield'],
}


def classify_device(ip: str, hostname: Optional[str] = None) -> str:
    """
    Return a human-readable device type string based on hostname patterns
    and last-octet IP heuristics.
    """
    if hostname:
        hn = hostname.lower()
        for dtype, keys in _HOSTNAME_PATTERNS.items():
            if any(k in hn for k in keys):
                return dtype

    try:
        last = int(ip.split('.')[-1])
        if last == 1:         return 'Router/Gateway'
        if last <= 10:        return 'Network Device'
        if last <= 50:        return 'Computer'
        if last <= 100:       return 'Mobile Device'
        if last <= 150:       return 'IoT Device'
        if last >= 200:       return 'Server/Printer'
    except Exception:
        pass
    return 'Unknown Device'