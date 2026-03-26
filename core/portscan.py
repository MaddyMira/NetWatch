"""
core/portscan.py
────────────────
Fast concurrent TCP port scanner with service banner grabbing.

scan_ports(ip, ports, timeout, max_workers)
    → yields ScanResult dicts as ports are checked (streaming)

scan_ports_batch(ip, profile, timeout)
    → convenience wrapper; profile = 'quick' | 'common' | 'full'

Each ScanResult:
    {
        port:     int,
        state:    'open' | 'closed' | 'filtered',
        service:  str,          # well-known name (e.g. 'HTTP', 'SSH')
        banner:   str | None,   # raw banner if grabbed
        tls:      bool,         # True if TLS handshake succeeded
    }
"""
import socket
import ssl
import concurrent.futures
import threading
from typing import Dict, Generator, Iterable, List, Optional

# ── Service map ───────────────────────────────────────────────────────────────
_SERVICES: Dict[int, str] = {
    20: 'FTP-Data',   21: 'FTP',        22: 'SSH',        23: 'Telnet',
    25: 'SMTP',       53: 'DNS',        67: 'DHCP',       68: 'DHCP',
    69: 'TFTP',       80: 'HTTP',       88: 'Kerberos',   110: 'POP3',
    111: 'RPC',       119: 'NNTP',      123: 'NTP',       135: 'MSRPC',
    137: 'NetBIOS',   138: 'NetBIOS',   139: 'NetBIOS',   143: 'IMAP',
    161: 'SNMP',      162: 'SNMP-Trap', 179: 'BGP',       194: 'IRC',
    389: 'LDAP',      443: 'HTTPS',     445: 'SMB',       465: 'SMTPS',
    500: 'IKE',       514: 'Syslog',    515: 'LPD',       548: 'AFP',
    554: 'RTSP',      587: 'SMTP-Sub',  631: 'IPP/CUPS',  636: 'LDAPS',
    993: 'IMAPS',     995: 'POP3S',     1080: 'SOCKS',    1194: 'OpenVPN',
    1433: 'MSSQL',    1521: 'Oracle',   1723: 'PPTP',     2049: 'NFS',
    2181: 'ZooKeeper',2375: 'Docker',   2376: 'DockerTLS',3000: 'Dev-HTTP',
    3306: 'MySQL',    3389: 'RDP',      3690: 'SVN',      4443: 'Alt-HTTPS',
    4500: 'IKEv2',    4899: 'Radmin',   5000: 'UPnP/Dev', 5001: 'Synology',
    5060: 'SIP',      5432: 'PostgreSQL',5900: 'VNC',     5985: 'WinRM',
    5986: 'WinRM-S',  6379: 'Redis',    6443: 'K8s-API',  6881: 'BitTorrent',
    7070: 'RTSP-Alt', 7474: 'Neo4j',    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8888: 'Jupyter',  9000: 'SonarQube',9090: 'Prometheus',9200: 'Elasticsearch',
    9300: 'ES-Node',  9418: 'Git',      10000: 'Webmin',  11211: 'Memcached',
    27017: 'MongoDB', 27018: 'MongoDB', 50000: 'SAP',     51820: 'WireGuard',
}

# Port scan profiles
PROFILES: Dict[str, List[int]] = {
    'quick': [
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
        3306, 3389, 5900, 8080, 8443,
    ],
    'common': sorted(_SERVICES.keys()),
    'full': list(range(1, 1025)) + [
        1433, 1521, 1723, 2049, 2375, 3306, 3389, 3690, 4899,
        5000, 5432, 5900, 5985, 6379, 6443, 7474, 8080, 8443,
        8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211, 27017,
    ],
}


# ── Single port probe ─────────────────────────────────────────────────────────

def _probe(ip: str, port: int, timeout: float) -> dict:
    result = {
        'port':    port,
        'state':   'closed',
        'service': _SERVICES.get(port, f'Port-{port}'),
        'banner':  None,
        'tls':     False,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err  = sock.connect_ex((ip, port))
        if err != 0:
            sock.close()
            return result

        result['state'] = 'open'

        # Banner grab — try TLS first on known TLS ports, then plain
        tls_ports = {443, 465, 636, 993, 995, 2376, 4443, 5986, 6443, 8443}
        banner    = None

        if port in tls_ports:
            try:
                ctx = ssl.create_default_context()
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=ip)
                tls_sock.settimeout(timeout)
                # Try to read banner
                tls_sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = tls_sock.recv(256).decode('utf-8', errors='replace').strip()
                result['tls'] = True
                tls_sock.close()
            except Exception:
                pass
        else:
            # Send a minimal probe to elicit a banner
            try:
                sock.settimeout(0.5)
                probe = b'\r\n' if port in {21, 22, 23, 25, 110, 143} else b''
                if probe:
                    sock.send(probe)
                raw   = sock.recv(256)
                banner = raw.decode('utf-8', errors='replace').strip()
            except Exception:
                pass
            sock.close()

        if banner:
            # Trim to first line, max 120 chars
            result['banner'] = banner.splitlines()[0][:120]

    except socket.timeout:
        result['state'] = 'filtered'
    except OSError:
        pass

    return result


# ── Public API ────────────────────────────────────────────────────────────────

def scan_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 0.8,
    max_workers: int = 128,
) -> List[dict]:
    """
    Scan *ports* on *ip* concurrently.
    Returns a list of ScanResult dicts for open ports only, sorted by port.
    """
    open_results = []
    port_list    = list(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, ip, p, timeout): p for p in port_list}
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
                if r['state'] == 'open':
                    open_results.append(r)
            except Exception:
                pass

    return sorted(open_results, key=lambda x: x['port'])


def scan_ports_profile(
    ip: str,
    profile: str = 'quick',
    timeout: float = 0.8,
    on_progress: Optional[callable] = None,
) -> List[dict]:
    """
    Scan using a named profile. Calls on_progress(done, total) if provided.
    """
    ports      = PROFILES.get(profile, PROFILES['quick'])
    total      = len(ports)
    done       = 0
    lock       = threading.Lock()
    open_results = []

    def _probe_with_progress(ip, port, timeout):
        nonlocal done
        r = _probe(ip, port, timeout)
        with lock:
            done += 1
            if on_progress:
                on_progress(done, total)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as pool:
        futures = {pool.submit(_probe_with_progress, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            try:
                r = f.result()
                if r['state'] == 'open':
                    open_results.append(r)
            except Exception:
                pass

    return sorted(open_results, key=lambda x: x['port'])
