"""
core/dns_tools.py
─────────────────
DNS record lookups and IP geolocation / Whois enrichment.

All functions are safe to call from background threads.
No external pip dependencies — uses stdlib socket/dnspython-free approach
plus a free HTTP API (ip-api.com) for geolocation.

Functions
─────────
lookup_dns(host)         → {A, PTR, MX, NS, CNAME, TXT} records
geolocate_ip(ip)         → country, city, ISP, ASN, lat/lon
is_private_ip(ip)        → True for RFC-1918 / loopback / link-local
"""
import ipaddress
import json
import socket
import subprocess
import os
import urllib.request
import urllib.error
from typing import Dict, List, Optional


# ── Private-IP check ──────────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── DNS lookups ───────────────────────────────────────────────────────────────

def _run_nslookup(query: str, qtype: str, server: str = '') -> List[str]:
    """
    Run nslookup (available on both Windows and Linux) and parse output.
    Falls back to empty list on error.
    """
    cmd = ['nslookup', f'-type={qtype}', query]
    if server:
        cmd.append(server)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=6,
            shell=(os.name == 'nt'),
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0),
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def _socket_a(host: str) -> List[str]:
    """Resolve A records using stdlib socket."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return list({i[4][0] for i in infos})
    except Exception:
        return []


def _socket_ptr(ip: str) -> Optional[str]:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2)
        host = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return host
    except Exception:
        return None


def _parse_mx(lines: List[str]) -> List[str]:
    results = []
    for line in lines:
        line = line.strip()
        # "MX preference = 10, mail exchanger = smtp.example.com"
        if 'mail exchanger' in line.lower():
            parts = line.split('=')
            if len(parts) >= 2:
                results.append(parts[-1].strip().rstrip('.'))
        # "  10 smtp.example.com" (Linux nslookup)
        elif line and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 2:
                results.append(f"{parts[0]} {parts[1].rstrip('.')}")
    return results


def _parse_ns(lines: List[str]) -> List[str]:
    results = []
    for line in lines:
        line = line.strip()
        if 'nameserver' in line.lower() or 'name server' in line.lower():
            parts = line.split('=')
            if len(parts) >= 2:
                results.append(parts[-1].strip().rstrip('.'))
        elif line.endswith('.') and 'server:' not in line.lower():
            results.append(line.rstrip('.'))
    return results


def _parse_txt(lines: List[str]) -> List[str]:
    results = []
    for line in lines:
        if '"' in line:
            start = line.find('"')
            end   = line.rfind('"')
            if end > start:
                results.append(line[start+1:end])
    return results


def lookup_dns(host: str) -> Dict:
    """
    Perform A, PTR, MX, NS, and TXT lookups for *host*.
    Returns a dict of {record_type: [values]}.
    """
    result: Dict = {
        'host':  host,
        'A':     [],
        'PTR':   None,
        'MX':    [],
        'NS':    [],
        'TXT':   [],
        'error': None,
    }

    # A records — use socket for reliability
    result['A'] = _socket_a(host)

    # PTR — if host looks like an IP
    try:
        ipaddress.ip_address(host)
        result['PTR'] = _socket_ptr(host)
    except ValueError:
        pass

    # MX
    mx_lines = _run_nslookup(host, 'MX')
    result['MX'] = _parse_mx(mx_lines) or []

    # NS
    ns_lines = _run_nslookup(host, 'NS')
    result['NS'] = _parse_ns(ns_lines) or []

    # TXT
    txt_lines = _run_nslookup(host, 'TXT')
    result['TXT'] = _parse_txt(txt_lines) or []

    return result


# ── Geolocation (ip-api.com — free, no key, 45 req/min) ──────────────────────

_GEO_URL = 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,query'

_GEO_CACHE: Dict[str, Dict] = {}


def geolocate_ip(ip: str) -> Dict:
    """
    Return geolocation data for *ip* using the ip-api.com free endpoint.
    Private IPs return immediately with a "private address" message.
    Results are in-process cached.
    """
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    if is_private_ip(ip):
        result = {
            'ip':      ip,
            'private': True,
            'country': 'Private Network',
            'city':    '—',
            'isp':     '—',
            'asn':     '—',
            'lat':     None,
            'lon':     None,
        }
        _GEO_CACHE[ip] = result
        return result

    try:
        url = _GEO_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={'User-Agent': 'NETWATCH/3.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        if data.get('status') == 'success':
            result = {
                'ip':      data.get('query', ip),
                'private': False,
                'country': f"{data.get('country','')} ({data.get('countryCode','')})",
                'region':  data.get('regionName', ''),
                'city':    data.get('city', ''),
                'zip':     data.get('zip', ''),
                'isp':     data.get('isp', ''),
                'org':     data.get('org', ''),
                'asn':     data.get('as', ''),
                'lat':     data.get('lat'),
                'lon':     data.get('lon'),
            }
        else:
            result = {
                'ip':      ip,
                'private': False,
                'error':   data.get('message', 'Lookup failed'),
            }
    except urllib.error.URLError as e:
        result = {'ip': ip, 'private': False, 'error': f'Network error: {e.reason}'}
    except Exception as e:
        result = {'ip': ip, 'private': False, 'error': str(e)}

    _GEO_CACHE[ip] = result
    return result


def clear_geo_cache() -> None:
    _GEO_CACHE.clear()
