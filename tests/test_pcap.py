import os
import tempfile
import pytest
from analyzer.pcap_analyzer import analyze_pcap_file
from analyzer.snort_parser import parse_fast_alert_line, parse_snort_alerts_text


def test_analyze_nonexistent_pcap():
    res = analyze_pcap_file("/tmp/nonexistent_file_12345.pcap")
    assert res["success"] is False
    assert "File not found" in res["error"]


def test_analyze_empty_pcap():
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        res = analyze_pcap_file(tmp.name)
        assert res["success"] is False
        assert "empty" in res["error"].lower()


def test_analyze_corrupt_pcap():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(b"NOT A REAL PCAP FILE HEADER RANDOM NOISE")
        tmp.flush()
        tmp_name = tmp.name

    try:
        res = analyze_pcap_file(tmp_name)
        assert res["success"] is False
        assert "corrupted" in res["error"].lower()
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_analyze_sample_benign_pcap():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "uploads", "pcaps", "sample_benign_traffic.pcap")
    if os.path.exists(sample_path):
        res = analyze_pcap_file(sample_path)
        assert res["success"] is True
        assert res["total_packets"] > 0
        assert "TCP" in res["protocols"]
        assert "DNS" in res["protocols"]
        assert len(res["source_ips"]) > 0


def test_snort_alert_fast_parser():
    line = '09/26-10:15:20.102341 [**] [1:1000001:1] DEMO - Network Service Scanning Detected [**] [Classification: attempted-recon] [Priority: 2] {TCP} 192.168.1.50:43210 -> 192.168.1.200:80'
    parsed = parse_fast_alert_line(line)
    assert parsed is not None
    assert parsed["sid"] == 1000001
    assert parsed["message"] == "DEMO - Network Service Scanning Detected"
    assert parsed["protocol"] == "TCP"
    assert parsed["source_ip"] == "192.168.1.50"
    assert parsed["source_port"] == "43210"
    assert parsed["destination_ip"] == "192.168.1.200"
    assert parsed["destination_port"] == "80"
    assert parsed["severity"] == "High"


def test_snort_multiple_alerts_parsing():
    text = """
    09/26-10:15:20.102341 [**] [1:1000001:1] Alert One [**] [Priority: 1] {TCP} 10.0.0.1:1000 -> 10.0.0.2:80
    09/26-10:15:21.102341 [**] [1:1000002:1] Alert Two [**] [Priority: 3] {UDP} 10.0.0.1:2000 -> 10.0.0.2:53
    """
    alerts = parse_snort_alerts_text(text)
    assert len(alerts) == 2
    assert alerts[0]["sid"] == 1000001
    assert alerts[0]["severity"] == "Critical"
    assert alerts[1]["sid"] == 1000002
    assert alerts[1]["severity"] == "Medium"
