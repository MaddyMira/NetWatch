"""
core/traceroute.py
──────────────────
Cross-platform traceroute.

Strategy
────────
  Windows  — parse `tracert -d -w 800 <ip>` output
  Linux    — parse `traceroute -n -w 1 -q 1 <ip>` output
  Fallback — manual ICMP TTL-expansion with socket (requires raw socket / root)

Each yielded hop:
    {
        ttl:      int,
        ip:       str | None,   # None = * (no reply)
        hostname: str | None,
        rtt_ms:   float | None,
        status:   'ok' | 'timeout' | 'dest',
    }
"""
import os
import re
import socket
import subprocess
from typing import Generator, List, Optional


# ── Windows parser ─────────────────────────────────────────────────────────────

_WIN_HOP_RE = re.compile(
    r"^\s*(\d+)"                        # TTL
    r"(?:\s+(\d+|\*)\s*ms)?"           # rtt 1
    r"(?:\s+(\d+|\*)\s*ms)?"           # rtt 2
    r"(?:\s+(\d+|\*)\s*ms)?"           # rtt 3
    r"\s+(\S+)",                        # host/ip or *
    re.MULTILINE,
)

def _parse_windows(target: str, max_hops: int) -> List[dict]:
    hops = []
    try:
        proc = subprocess.run(
            ['tracert', '-d', '-w', '800', '-h', str(max_hops), target],
            capture_output=True, text=True, shell=True,
            timeout=60 + max_hops * 1,
        )
        for m in _WIN_HOP_RE.finditer(proc.stdout):
            ttl   = int(m.group(1))
            rtts  = [m.group(i) for i in (2, 3, 4) if m.group(i) and m.group(i) != '*']
            rtt   = float(min(rtts)) if rtts else None
            host  = m.group(5)
            ip    = host if host != '*' else None
            is_dest = ip == target
            hops.append({
                'ttl':      ttl,
                'ip':       ip,
                'hostname': ip,
                'rtt_ms':   rtt,
                'status':   'dest' if is_dest else ('ok' if ip else 'timeout'),
            })
    except Exception as e:
        print(f"[traceroute] Windows parse error: {e}")
    return hops


# ── Linux/macOS parser ────────────────────────────────────────────────────────

_LIN_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"           # TTL
    r"(?:(\S+)\s+(\S+)\s*ms" # ip rtt
    r"|\*)",                   # or timeout
    re.MULTILINE,
)

def _parse_linux(target: str, max_hops: int) -> List[dict]:
    hops = []
    try:
        proc = subprocess.run(
            ['traceroute', '-n', '-w', '1', '-q', '1',
             '-m', str(max_hops), target],
            capture_output=True, text=True,
            timeout=60 + max_hops * 2,
        )
        for m in _LIN_HOP_RE.finditer(proc.stdout):
            ttl  = int(m.group(1))
            ip   = m.group(2)
            rtt  = float(m.group(3)) if m.group(3) else None
            is_dest = ip == target if ip else False
            hops.append({
                'ttl':      ttl,
                'ip':       ip,
                'hostname': ip,
                'rtt_ms':   rtt,
                'status':   'dest' if is_dest else ('ok' if ip else 'timeout'),
            })
    except Exception as e:
        print(f"[traceroute] Linux parse error: {e}")
    return hops


# ── Raw socket fallback (no external command) ─────────────────────────────────

def _raw_traceroute(target: str, max_hops: int, timeout: float) -> List[dict]:
    """
    Manual TTL-expansion probe using ICMP.
    Requires raw socket (Windows: admin, Linux: root or cap_net_raw).
    Silently falls back to empty list if permissions are unavailable.
    """
    hops = []
    try:
        dest_ip = socket.gethostbyname(target)

        for ttl in range(1, max_hops + 1):
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            import struct, time
            # Build ICMP echo request
            checksum = 0
            header   = struct.pack('bbHHh', 8, 0, checksum, 1, ttl)
            data     = b'NETWATCH'
            checksum = _icmp_checksum(header + data)
            header   = struct.pack('bbHHh', 8, 0, checksum, 1, ttl)
            packet   = header + data

            t0 = time.perf_counter()
            send_sock.sendto(packet, (dest_ip, 1))
            hop_ip = None
            rtt    = None
            try:
                _, addr = recv_sock.recvfrom(1024)
                rtt    = (time.perf_counter() - t0) * 1000
                hop_ip = addr[0]
            except socket.timeout:
                pass
            finally:
                send_sock.close()
                recv_sock.close()

            is_dest = hop_ip == dest_ip
            hops.append({
                'ttl':      ttl,
                'ip':       hop_ip,
                'hostname': hop_ip,
                'rtt_ms':   round(rtt, 2) if rtt is not None else None,
                'status':   'dest' if is_dest else ('ok' if hop_ip else 'timeout'),
            })
            if is_dest:
                break
    except PermissionError:
        pass        # raw socket not available
    except Exception as e:
        print(f"[traceroute] raw error: {e}")
    return hops


def _icmp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s   += word
    s  = (s >> 16) + (s & 0xffff)
    s +=  s >> 16
    return ~s & 0xffff


# ── Public API ────────────────────────────────────────────────────────────────

def run_traceroute(
    target: str,
    max_hops: int = 30,
    timeout: float = 1.0,
) -> List[dict]:
    """
    Run a traceroute to *target* and return a list of hop dicts.
    Chooses the best available method automatically.
    """
    if os.name == 'nt':
        hops = _parse_windows(target, max_hops)
    else:
        hops = _parse_linux(target, max_hops)

    if not hops:
        hops = _raw_traceroute(target, max_hops, timeout)

    # Reverse-resolve hostnames for hops that have an IP
    for hop in hops:
        if hop['ip'] and hop['ip'] != hop['hostname']:
            continue
        if hop['ip']:
            try:
                old = socket.getdefaulttimeout()
                socket.setdefaulttimeout(0.4)
                hop['hostname'] = socket.gethostbyaddr(hop['ip'])[0]
                socket.setdefaulttimeout(old)
            except Exception:
                hop['hostname'] = hop['ip']

    return hops
