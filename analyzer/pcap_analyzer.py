import time
import os
import shutil
import subprocess
from collections import Counter
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def check_tshark_installed():
    """Detect if tshark binary is available in system PATH."""
    path = shutil.which("tshark")
    if not path:
        return None
    try:
        proc = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=3)
        version_line = proc.stdout.splitlines()[0] if proc.stdout else "Available"
        return {"path": path, "version": version_line}
    except Exception:
        return {"path": path, "version": "Available"}


PCAP_MAGIC_NUMBERS = [
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little-endian, microsecond)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big-endian, microsecond)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little-endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big-endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
]


def validate_pcap_file_structure(filepath):
    """
    Validates file existence, non-empty size, and PCAP/PCAPNG magic bytes.
    Returns (is_valid: bool, error_message: str or None)
    """
    if not os.path.exists(filepath):
        return False, f"File not found: {filepath}"
    size = os.path.getsize(filepath)
    if size == 0:
        return False, "PCAP file is empty (0 bytes)."
    if size < 4:
        return False, "File is too small to be a valid PCAP (minimum 4 bytes required for magic header)."
    if size > 50 * 1024 * 1024:
        return False, "File exceeds maximum 50MB PCAP size limit."
    try:
        with open(filepath, "rb") as f:
            header = f.read(4)
            if not any(header.startswith(m) for m in PCAP_MAGIC_NUMBERS):
                return False, "Invalid or corrupted capture structure: File lacks standard PCAP or PCAPNG magic header bytes."
    except Exception as e:
        return False, f"Unable to read file header: {str(e)}"
    return True, None


def analyze_pcap_file(filepath):
    """
    Analyzes a PCAP or PCAPNG file.
    Uses Scapy for packet inspection, with robust fallback and error handling.
    Returns a dictionary of analysis metrics.
    """
    is_valid, err = validate_pcap_file_structure(filepath)
    if not is_valid:
        return {"success": False, "error": err}

    start_time = time.time()

    if not SCAPY_AVAILABLE:
        return {
            "success": False,
            "error": "Scapy library is not installed on this system. Unable to parse PCAP."
        }

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse PCAP file (possibly corrupted or unsupported format): {str(e)}"
        }

    total_packets = len(packets)
    if total_packets == 0:
        return {
            "success": True,
            "filename": os.path.basename(filepath),
            "total_packets": 0,
            "source_ips": [],
            "destination_ips": [],
            "source_ports": [],
            "destination_ports": [],
            "protocols": {},
            "tcp_packets": 0,
            "udp_packets": 0,
            "dns_packets": 0,
            "http_packets": 0,
            "https_packets": 0,
            "packet_frequency": [],
            "analysis_time": round(time.time() - start_time, 4),
            "note": "PCAP contained zero packet frames."
        }

    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()
    protocols = Counter()

    tcp_count = 0
    udp_count = 0
    dns_count = 0
    http_count = 0
    https_count = 0
    icmp_count = 0
    arp_count = 0

    timestamps = []

    for pkt in packets:
        # Extract timestamp
        try:
            pkt_time = float(pkt.time)
            timestamps.append(pkt_time)
        except Exception:
            pass

        # Layer 3 - IP
        if pkt.haslayer(IP):
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1
        elif pkt.haslayer(IPv6):
            src_ips[pkt[IPv6].src] += 1
            dst_ips[pkt[IPv6].dst] += 1
        elif pkt.haslayer(ARP):
            arp_count += 1
            protocols["ARP"] += 1
            continue

        # Layer 4 - Transport
        if pkt.haslayer(TCP):
            tcp_count += 1
            protocols["TCP"] += 1
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            src_ports[str(sport)] += 1
            dst_ports[str(dport)] += 1

            # Application protocol checks (technically honest port-correlated heuristics)
            if dport == 80 or sport == 80 or dport == 8080 or sport == 8080:
                http_count += 1
                protocols["HTTP-like (TCP/80)"] += 1
            elif dport == 443 or sport == 443 or dport == 8443 or sport == 8443:
                https_count += 1
                protocols["HTTPS/TLS-like (TCP/443)"] += 1
            elif dport == 53 or sport == 53 or pkt.haslayer(DNS):
                dns_count += 1
                protocols["DNS"] += 1
                protocols["DNS (TCP/53)"] += 1
            elif dport == 22 or sport == 22:
                protocols["SSH-like (TCP/22)"] += 1
            elif dport == 21 or sport == 21:
                protocols["FTP-like (TCP/21)"] += 1
            elif dport == 23 or sport == 23:
                protocols["TELNET-like (TCP/23)"] += 1

        elif pkt.haslayer(UDP):
            udp_count += 1
            protocols["UDP"] += 1
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            src_ports[str(sport)] += 1
            dst_ports[str(dport)] += 1

            if dport == 53 or sport == 53 or pkt.haslayer(DNS):
                dns_count += 1
                protocols["DNS"] += 1
                protocols["DNS (UDP/53)"] += 1
            elif dport == 67 or dport == 68 or sport == 67 or sport == 68:
                protocols["DHCP (UDP/67-68)"] += 1
            elif dport == 123 or sport == 123:
                protocols["NTP (UDP/123)"] += 1

        elif pkt.haslayer(ICMP):
            icmp_count += 1
            protocols["ICMP"] += 1
        else:
            protocols["Other"] += 1

    # Calculate packet frequency timeline (split into up to 10 time buckets)
    frequency_data = []
    if timestamps:
        timestamps.sort()
        min_t = timestamps[0]
        max_t = timestamps[-1]
        duration = max_t - min_t

        if duration > 0:
            num_buckets = min(10, max(2, int(duration) + 1))
            bucket_size = duration / num_buckets
            buckets = [0] * num_buckets
            for t in timestamps:
                idx = min(int((t - min_t) / bucket_size), num_buckets - 1)
                buckets[idx] += 1

            for i, count in enumerate(buckets):
                bucket_start = min_t + (i * bucket_size)
                time_str = datetime.fromtimestamp(bucket_start).strftime("%H:%M:%S")
                frequency_data.append({"time": time_str, "packets": count})
        else:
            time_str = datetime.fromtimestamp(min_t).strftime("%H:%M:%S")
            frequency_data.append({"time": time_str, "packets": total_packets})

    elapsed_time = round(time.time() - start_time, 4)

    return {
        "success": True,
        "filename": os.path.basename(filepath),
        "total_packets": total_packets,
        "source_ips": [{"ip": ip, "count": count} for ip, count in src_ips.most_common(10)],
        "destination_ips": [{"ip": ip, "count": count} for ip, count in dst_ips.most_common(10)],
        "source_ports": [{"port": port, "count": count} for port, count in src_ports.most_common(10)],
        "destination_ports": [{"port": port, "count": count} for port, count in dst_ports.most_common(10)],
        "protocols": dict(protocols),
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "dns_packets": dns_count,
        "http_packets": http_count,
        "https_packets": https_count,
        "packet_frequency": frequency_data,
        "analysis_time": elapsed_time
    }
