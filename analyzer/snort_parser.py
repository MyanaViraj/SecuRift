import re
from datetime import datetime


def parse_priority_to_severity(priority):
    """
    Maps Snort Priority number to SecuRift Severity level.
    Snort standard: Priority 1 = High/Critical, Priority 2 = Medium, Priority 3 = Low, Priority 4 = Info.
    """
    try:
        p = int(priority)
        if p == 1:
            return "Critical"
        elif p == 2:
            return "High"
        elif p == 3:
            return "Medium"
        else:
            return "Low"
    except Exception:
        return "Medium"


def parse_fast_alert_line(line):
    """
    Parses a single line from a Snort fast alert file.
    Example line:
    09/26-21:30:15.123456 [**] [1:1000001:2] SecuRift HTTP SQLi Detection [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.50:45231 -> 10.0.0.5:80
    """
    line = line.strip()
    if not line or not ("[**]" in line):
        return None

    # Pattern for fast alert format
    # Group 1: Timestamp (optional)
    # Group 2: Generator ID & SID & Rev ([1:1000001:2])
    # Group 3: Alert Message
    # Group 4: Classification (optional)
    # Group 5: Priority (optional)
    # Group 6: Protocol {TCP}
    # Group 7: Source IP:Port
    # Group 8: Destination IP:Port

    timestamp = ""
    # Check if starts with timestamp e.g. "09/26-21:30:15.123456"
    ts_match = re.match(r"^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)", line)
    if ts_match:
        timestamp = ts_match.group(1)

    # Extract SID
    sid = 0
    sid_match = re.search(r"\[\d+:(\d+):\d+\]", line)
    if sid_match:
        sid = int(sid_match.group(1))

    # Extract Message (between [**] [gen:sid:rev] MESSAGE [**])
    msg_match = re.search(r"\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]", line)
    message = msg_match.group(1).strip() if msg_match else "Snort Alert"

    # Extract Classification
    class_match = re.search(r"\[Classification:\s*(.*?)\]", line)
    classification = class_match.group(1).strip() if class_match else "Potentially Bad Traffic"

    # Extract Priority
    prio_match = re.search(r"\[Priority:\s*(\d+)\]", line)
    priority = prio_match.group(1).strip() if prio_match else "2"
    severity = parse_priority_to_severity(priority)

    # Extract Protocol
    proto_match = re.search(r"\{([A-Za-z0-9_-]+)\}", line)
    protocol = proto_match.group(1).upper() if proto_match else "IP"

    # Extract IP and Port: SRC -> DST
    # e.g. 192.168.1.50:45231 -> 10.0.0.5:80 or 192.168.1.50 -> 10.0.0.5
    src_ip = "0.0.0.0"
    src_port = "0"
    dst_ip = "0.0.0.0"
    dst_port = "0"

    ip_match = re.search(r"\{.*?\}\s+([0-9a-fA-F\.\:]+)\s*->\s*([0-9a-fA-F\.\:]+)", line)
    if ip_match:
        src_raw = ip_match.group(1).strip()
        dst_raw = ip_match.group(2).strip()

        if ":" in src_raw and not src_raw.startswith("["):
            parts = src_raw.rsplit(":", 1)
            src_ip, src_port = parts[0], parts[1]
        else:
            src_ip = src_raw

        if ":" in dst_raw and not dst_raw.startswith("["):
            parts = dst_raw.rsplit(":", 1)
            dst_ip, dst_port = parts[0], parts[1]
        else:
            dst_ip = dst_raw

    if not timestamp:
        timestamp = datetime.now().strftime("%m/%d-%H:%M:%S")

    return {
        "timestamp": timestamp,
        "sid": sid,
        "message": message,
        "protocol": protocol,
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "classification": classification,
        "severity": severity,
        "raw_alert": line
    }


def parse_snort_alerts_text(text):
    """
    Parses a block of text containing multiple Snort alerts (fast format or multi-line).
    Returns a list of parsed alert dictionaries.
    """
    alerts = []
    lines = text.strip().splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue

        # Check if single-line fast alert
        if "[**]" in line and ("->" in line or "{" in line):
            parsed = parse_fast_alert_line(line)
            if parsed:
                alerts.append(parsed)
            i += 1
        elif "[**]" in line:
            # Possible multi-line alert
            # Collect lines until next empty line or next [**]
            chunk = [line]
            i += 1
            while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith("[**]"):
                chunk.append(lines[i].strip())
                i += 1
            combined = " ".join(chunk)
            parsed = parse_fast_alert_line(combined)
            if parsed:
                parsed["raw_alert"] = "\n".join(chunk)
                alerts.append(parsed)
        else:
            i += 1

    return alerts
