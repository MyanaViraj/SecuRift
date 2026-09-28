import os
import sys
import json
import time
from datetime import datetime, timezone
from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, Raw
from app import create_app
from models import db
from models.models import (
    User, Rule, TestCase, PCAPAnalysis, Alert,
    ValidationResult, FalsePositiveRecord, PerformanceMeasurement, MitreMapping,
    SnortExecution, TestExecution, DetectionEvaluation
)
from analyzer.pcap_analyzer import analyze_pcap_file


def generate_sample_pcaps(pcap_dir):
    """Generates safe, harmless synthetic PCAPs using Scapy for testing."""
    os.makedirs(pcap_dir, exist_ok=True)

    base_time = time.time() - 3600

    # 1. Benign Traffic PCAP (Strictly Benign Negative Test Vectors)
    benign_pcap_path = os.path.join(pcap_dir, "sample_benign_traffic.pcap")
    pkts_benign = []

    for i in range(1, 30):
        # Benign HTTP request to standard homepage
        pkt_http = (
            Ether() /
            IP(src="192.168.1.105", dst="142.250.190.46") /
            TCP(sport=50000 + i, dport=80, flags="A") /
            Raw(load=f"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        pkt_http.time = base_time + (i * 2)
        pkts_benign.append(pkt_http)

        # Benign DNS query to corporate resolver
        pkt_dns = (
            Ether() /
            IP(src="192.168.1.105", dst="8.8.8.8") /
            UDP(sport=55000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"api{i}.service.local"))
        )
        pkt_dns.time = base_time + (i * 2) + 0.1
        pkts_benign.append(pkt_dns)

    wrpcap(benign_pcap_path, pkts_benign)

    # 2. Synthetic Recon Scan PCAP (Safe TCP SYN probe packets)
    recon_pcap_path = os.path.join(pcap_dir, "sample_recon_scan.pcap")
    pkts_recon = []
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]

    for idx, p in enumerate(ports):
        pkt_syn = (
            Ether() /
            IP(src="192.168.1.50", dst="192.168.1.200") /
            TCP(sport=43210 + idx, dport=p, flags="S")
        )
        pkt_syn.time = base_time + 100 + (idx * 0.5)
        pkts_recon.append(pkt_syn)

    wrpcap(recon_pcap_path, pkts_recon)

    # 3. Synthetic Web Shell Test Vector PCAP (Controlled detection test)
    webshell_pcap_path = os.path.join(pcap_dir, "sample_webshell_attack.pcap")
    pkts_ws = []
    pkt_ws = (
        Ether() /
        IP(src="203.0.113.88", dst="192.168.1.100") /
        TCP(sport=48921, dport=80, flags="PA") /
        Raw(load="POST /shell.php HTTP/1.1\r\nHost: target.local\r\nContent-Length: 18\r\n\r\ncmd=cmd.exe /c whoami")
    )
    pkt_ws.time = base_time + 200
    pkts_ws.append(pkt_ws)
    wrpcap(webshell_pcap_path, pkts_ws)

    return benign_pcap_path, recon_pcap_path, webshell_pcap_path


def seed_database():
    demo_password = os.environ.get("SECURIFT_DEMO_PASSWORD")
    if not demo_password and os.path.exists(".env"):
        try:
            with open(".env", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SECURIFT_DEMO_PASSWORD="):
                        val = line.split("=", 1)[1].strip().strip("\"'")
                        if val:
                            demo_password = val
                            os.environ["SECURIFT_DEMO_PASSWORD"] = val
                            break
        except Exception:
            pass

    if not demo_password:
        print("[!] ERROR: Environment variable 'SECURIFT_DEMO_PASSWORD' is not set.")
        print("[!] Please configure SECURIFT_DEMO_PASSWORD in your environment or local .env file before running the demo seed workflow.")
        print("[!] Example: export SECURIFT_DEMO_PASSWORD=\"change-this-for-local-demo\"")
        sys.exit(1)

    app = create_app()
    with app.app_context():
        print("[*] Initializing SQLite database schema...")
        db.drop_all()
        db.create_all()

        pcap_dir = app.config["PCAP_FOLDER"]

        # 1. Create Default Admin User
        print("[*] Seeding default operator credential (admin)...")
        admin = User(username="admin", role="Lead Security Architect")
        admin.set_password(demo_password)
        db.session.add(admin)
        db.session.commit()

        # 2. Seed Custom Snort Rules
        print("[*] Seeding custom Snort detection rules...")
        rules_data = [
            {
                "sid": 1000001,
                "rule_text": 'alert tcp any any -> any any (msg:"DEMO - Network Service Scanning Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:1000001; rev:1; classtype:attempted-recon;)',
                "action": "alert",
                "protocol": "tcp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "any",
                "message": "DEMO - Network Service Scanning Detected",
                "revision": 1,
                "classification": "attempted-recon",
                "severity": "High",
                "enabled": True,
                "purpose": "Detects high-frequency TCP SYN packets originating from a single host targeting diverse ports within a 10s evaluation window.",
                "trigger_condition": "TCP flags: SYN; threshold count exceeding 5 distinct attempts within 10 seconds.",
                "expected_behavior": "Sensor generates alert in fast.log; source IP flagged in SOC console.",
                "mitre_technique": "T1046"
            },
            {
                "sid": 1000002,
                "rule_text": 'alert tcp any any -> any 80 (msg:"DEMO - Suspicious Web Shell Access Attempt"; content:"cmd.exe"; nocase; sid:1000002; rev:1; classtype:web-application-attack;)',
                "action": "alert",
                "protocol": "tcp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "80",
                "message": "DEMO - Suspicious Web Shell Access Attempt",
                "revision": 1,
                "classification": "web-application-attack",
                "severity": "Critical",
                "enabled": True,
                "purpose": "Detects outbound web shell interaction containing Windows shell executable string tokens in payload parameters.",
                "trigger_condition": "HTTP payload containing case-insensitive string 'cmd.exe'.",
                "expected_behavior": "Immediate Critical severity alert with payload capture.",
                "mitre_technique": "T1059"
            },
            {
                "sid": 1000003,
                "rule_text": 'alert tcp any any -> any 22 (msg:"DEMO - SSH Brute Force Connection Burst"; flags:S; threshold:type threshold, track by_src, count 10, seconds 30; sid:1000003; rev:1; classtype:attempted-admin;)',
                "action": "alert",
                "protocol": "tcp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "22",
                "message": "DEMO - SSH Brute Force Connection Burst",
                "revision": 1,
                "classification": "attempted-admin",
                "severity": "High",
                "enabled": True,
                "purpose": "Identifies automated SSH password guessing by tracking connection attempts per source host exceeding standard interactive rates.",
                "trigger_condition": "Inbound TCP connection bursts to port 22 exceeding 10 attempts in 30 seconds.",
                "expected_behavior": "Alerts triggered on the 10th packet and subsequent attempts in window.",
                "mitre_technique": "T1110"
            },
            {
                "sid": 1000004,
                "rule_text": 'alert tcp any any -> any 80 (msg:"DEMO - HTTP Directory Traversal Attempt"; content:"/etc/passwd"; sid:1000004; rev:1; classtype:attempted-user;)',
                "action": "alert",
                "protocol": "tcp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "80",
                "message": "DEMO - HTTP Directory Traversal Attempt",
                "revision": 1,
                "classification": "attempted-user",
                "severity": "High",
                "enabled": True,
                "purpose": "Detects path traversal vulnerability probing attempting to read Unix system authentication credentials.",
                "trigger_condition": "HTTP request URI or POST data containing '/etc/passwd'.",
                "expected_behavior": "Generates alert for unauthorized file access probe.",
                "mitre_technique": "T1071.001"
            },
            {
                "sid": 1000005,
                "rule_text": 'alert tcp any any -> any 23 (msg:"DEMO - Unencrypted Telnet Session Established"; sid:1000005; rev:1; classtype:bad-unknown;)',
                "action": "alert",
                "protocol": "tcp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "23",
                "message": "DEMO - Unencrypted Telnet Session Established",
                "revision": 1,
                "classification": "bad-unknown",
                "severity": "Low",
                "enabled": True,
                "purpose": "Audits compliance against obsolete unencrypted network administration protocols.",
                "trigger_condition": "Any TCP handshake to port 23.",
                "expected_behavior": "Informational alert logged for legacy device policy tracking.",
                "mitre_technique": "T1046"
            },
            {
                "sid": 1000006,
                "rule_text": 'alert udp any any -> any 53 (msg:"DEMO - Potential DNS Tunneling Query Length Exceeded"; sid:1000006; rev:1; classtype:attempted-recon;)',
                "action": "alert",
                "protocol": "udp",
                "source_ip": "any",
                "source_port": "any",
                "direction": "->",
                "destination_ip": "any",
                "destination_port": "53",
                "message": "DEMO - Potential DNS Tunneling Query Length Exceeded",
                "revision": 1,
                "classification": "attempted-recon",
                "severity": "Medium",
                "enabled": True,
                "purpose": "Identifies data exfiltration or C2 beaconing using DNS query payload encoding.",
                "trigger_condition": "UDP port 53 query string exceeding 65 bytes in subdomain label.",
                "expected_behavior": "Alerts on abnormal DNS query entropy/length.",
                "mitre_technique": "T1048"
            }
        ]

        rules_by_sid = {}
        for rd in rules_data:
            r = Rule(**rd)
            db.session.add(r)
            db.session.flush()
            rules_by_sid[r.sid] = r

        db.session.commit()

        # 3. Generate Sample PCAPs and Analyze
        print("[*] Generating synthetic PCAPs and establishing baseline...")
        benign_pcap, recon_pcap, webshell_pcap = generate_sample_pcaps(pcap_dir)

        pcap_records = {}
        for p_path in [benign_pcap, recon_pcap, webshell_pcap]:
            fname = os.path.basename(p_path)
            res = analyze_pcap_file(p_path)
            if res.get("success"):
                rec = PCAPAnalysis(
                    filename=fname,
                    stored_filename=fname,
                    original_filename=fname,
                    data_source="DEMO",
                    total_packets=res["total_packets"],
                    source_ips=json.dumps(res["source_ips"]),
                    destination_ips=json.dumps(res["destination_ips"]),
                    source_ports=json.dumps(res["source_ports"]),
                    destination_ports=json.dumps(res["destination_ports"]),
                    protocols=json.dumps(res["protocols"]),
                    tcp_packets=res["tcp_packets"],
                    udp_packets=res["udp_packets"],
                    dns_packets=res["dns_packets"],
                    http_packets=res["http_packets"],
                    https_packets=res["https_packets"],
                    packet_frequency=json.dumps(res["packet_frequency"]),
                    analysis_time=res["analysis_time"]
                )
                db.session.add(rec)
                db.session.flush()
                pcap_records[fname] = rec

        db.session.commit()

        # Create demo SnortExecution record
        print("[*] Seeding demo SnortExecution harness...")
        demo_snort_exec = SnortExecution(
            rule_set="Demonstration Evaluation Suite (SIDs 1000001 - 1000006)",
            command_summary="DEMO SIMULATION — Controlled synthetic test vector evaluation",
            snort_version="Snort 2.9+ (Demo Reference Engine)",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            processing_time=0.0850,
            packets_processed=sum(r.total_packets for r in pcap_records.values()),
            alerts_generated=5,
            exit_code=0,
            status="SUCCESS",
            stdout="Demonstration Snort simulation completed without errors.",
            stderr="",
            execution_type="DEMO_SIMULATION"
        )
        db.session.add(demo_snort_exec)
        db.session.flush()

        # 4. Seed Alerts
        print("[*] Seeding demonstration Snort alerts...")
        alerts_data = [
            {
                "timestamp": "09/26-10:15:20.102341",
                "sid": 1000001,
                "message": "DEMO - Network Service Scanning Detected",
                "protocol": "TCP",
                "source_ip": "192.168.1.50",
                "source_port": "43210",
                "destination_ip": "192.168.1.200",
                "destination_port": "80",
                "classification": "attempted-recon",
                "severity": "High",
                "raw_alert": "09/26-10:15:20.102341 [**] [1:1000001:1] DEMO - Network Service Scanning Detected [**] [Priority: 2] {TCP} 192.168.1.50:43210 -> 192.168.1.200:80",
                "pcap_file": "sample_recon_scan.pcap",
                "source_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_execution_id": demo_snort_exec.id,
                "classification_choice": "True Positive"
            },
            {
                "timestamp": "09/26-10:15:21.341209",
                "sid": 1000001,
                "message": "DEMO - Network Service Scanning Detected",
                "protocol": "TCP",
                "source_ip": "192.168.1.50",
                "source_port": "43215",
                "destination_ip": "192.168.1.200",
                "destination_port": "443",
                "classification": "attempted-recon",
                "severity": "High",
                "raw_alert": "09/26-10:15:21.341209 [**] [1:1000001:1] DEMO - Network Service Scanning Detected [**] [Priority: 2] {TCP} 192.168.1.50:43215 -> 192.168.1.200:443",
                "pcap_file": "sample_recon_scan.pcap",
                "source_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_execution_id": demo_snort_exec.id,
                "classification_choice": "True Positive"
            },
            {
                "timestamp": "09/26-11:02:14.872314",
                "sid": 1000002,
                "message": "DEMO - Suspicious Web Shell Access Attempt",
                "protocol": "TCP",
                "source_ip": "203.0.113.88",
                "source_port": "48921",
                "destination_ip": "192.168.1.100",
                "destination_port": "80",
                "classification": "web-application-attack",
                "severity": "Critical",
                "raw_alert": "09/26-11:02:14.872314 [**] [1:1000002:1] DEMO - Suspicious Web Shell Access Attempt [**] [Priority: 1] {TCP} 203.0.113.88:48921 -> 192.168.1.100:80",
                "pcap_file": "sample_webshell_attack.pcap",
                "source_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_execution_id": demo_snort_exec.id,
                "classification_choice": "True Positive"
            },
            {
                "timestamp": "09/26-11:45:00.128491",
                "sid": 1000003,
                "message": "DEMO - SSH Brute Force Connection Burst",
                "protocol": "TCP",
                "source_ip": "198.51.100.14",
                "source_port": "51234",
                "destination_ip": "192.168.1.10",
                "destination_port": "22",
                "classification": "attempted-admin",
                "severity": "High",
                "raw_alert": "09/26-11:45:00.128491 [**] [1:1000003:1] DEMO - SSH Brute Force Connection Burst [**] [Priority: 2] {TCP} 198.51.100.14:51234 -> 192.168.1.10:22",
                "source_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_execution_id": demo_snort_exec.id,
                "classification_choice": "True Positive"
            },
            {
                "timestamp": "09/26-12:10:05.419082",
                "sid": 1000005,
                "message": "DEMO - Unencrypted Telnet Session Established",
                "protocol": "TCP",
                "source_ip": "10.0.0.15",
                "source_port": "41002",
                "destination_ip": "10.0.0.1",
                "destination_port": "23",
                "classification": "bad-unknown",
                "severity": "Low",
                "raw_alert": "09/26-12:10:05.419082 [**] [1:1000005:1] DEMO - Unencrypted Telnet Session Established [**] [Priority: 3] {TCP} 10.0.0.15:41002 -> 10.0.0.1:23",
                "source_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_execution_id": demo_snort_exec.id,
                "classification_choice": "False Positive"  # Internal admin benign maintenance
            }
        ]

        for ad in alerts_data:
            c_choice = ad.pop("classification_choice")
            alt = Alert(**ad)
            db.session.add(alt)
            db.session.flush()

            # Link false positive record
            fp = FalsePositiveRecord(
                alert_id=alt.id,
                classification=c_choice,
                notes="Seeded controlled baseline audit classification.",
                reviewed_at=datetime.now(timezone.utc)
            )
            db.session.add(fp)

        db.session.commit()

        # 5. Seed Test Cases, Test Executions, and Detection Evaluations
        print("[*] Seeding test cases and coherent evaluation population...")
        test_cases_data = [
            {
                "test_id": "TC-1001",
                "name": "DEMO — Network Service Scanning Probe",
                "category": "Reconnaissance",
                "description": "Evaluates detection of SYN scan burst targeting multiple ports on internal host.",
                "pcap_file": "sample_recon_scan.pcap",
                "expected_detection": "Alert",
                "actual_detection": "Alert",
                "rule_id": rules_by_sid[1000001].id,
                "severity": "High",
                "status": "PASS",
                "classification": "TP"
            },
            {
                "test_id": "TC-1002",
                "name": "DEMO — Suspicious Web Shell Execution",
                "category": "Initial Access",
                "description": "Tests signature capability to identify command execution strings in HTTP query.",
                "pcap_file": "sample_webshell_attack.pcap",
                "expected_detection": "Alert",
                "actual_detection": "Alert",
                "rule_id": rules_by_sid[1000002].id,
                "severity": "Critical",
                "status": "PASS",
                "classification": "TP"
            },
            {
                "test_id": "TC-1003",
                "name": "DEMO — Normal Benign HTTP Web Browsing",
                "category": "Benign Baseline",
                "description": "Verifies that routine GET requests to standard web pages produce zero alerts.",
                "pcap_file": "sample_benign_traffic.pcap",
                "expected_detection": "No Alert",
                "actual_detection": "No Alert",
                "rule_id": rules_by_sid[1000004].id,
                "severity": "Low",
                "status": "PASS",
                "classification": "TN"
            },
            {
                "test_id": "TC-1004",
                "name": "DEMO — Standard DNS Resolver Lookups",
                "category": "Benign Baseline",
                "description": "Verifies that normal small DNS lookups to internal resolvers do not trigger tunneling rules.",
                "pcap_file": "sample_benign_traffic.pcap",
                "expected_detection": "No Alert",
                "actual_detection": "No Alert",
                "rule_id": rules_by_sid[1000006].id,
                "severity": "Low",
                "status": "PASS",
                "classification": "TN"
            },
            {
                "test_id": "TC-1005",
                "name": "DEMO — SSH Brute Force Connection Burst",
                "category": "Credential Access",
                "description": "Tests high-frequency connection attempts targeting port 22.",
                "pcap_file": None,
                "expected_detection": "Alert",
                "actual_detection": "Alert",
                "rule_id": rules_by_sid[1000003].id,
                "severity": "High",
                "status": "PASS",
                "classification": "TP"
            },
            {
                "test_id": "TC-1006",
                "name": "DEMO — Obfuscated Web Command Execution",
                "category": "Defense Evasion",
                "description": "Simulates base64-encoded command string designed to evade simple plaintext content rules.",
                "pcap_file": None,
                "expected_detection": "Alert",
                "actual_detection": "No Alert",
                "rule_id": rules_by_sid[1000002].id,
                "severity": "Critical",
                "status": "NOT DETECTED",
                "classification": "FN"
            },
            {
                "test_id": "TC-1007",
                "name": "DEMO — Routine Backup Admin Synchronization",
                "category": "System Maintenance",
                "description": "Internal administrative synchronization script connecting over legacy port.",
                "pcap_file": None,
                "expected_detection": "No Alert",
                "actual_detection": "Alert",
                "rule_id": rules_by_sid[1000005].id,
                "severity": "Low",
                "status": "UNEXPECTED ALERT",
                "classification": "FP"
            }
        ]

        for tcd in test_cases_data:
            cls_code = tcd.pop("classification")
            tc = TestCase(**tcd)
            db.session.add(tc)
            db.session.flush()

            pcap_item = pcap_records.get(tc.pcap_file) if tc.pcap_file else None

            # TestExecution
            texec = TestExecution(
                test_case_id=tc.id,
                pcap_analysis_id=pcap_item.id if pcap_item else None,
                snort_execution_id=demo_snort_exec.id,
                rule_id=tc.rule_id,
                expected_result=tc.expected_detection,
                actual_result=tc.actual_detection,
                status=tc.status,
                evidence=f"DEMO simulation test vector: Expected '{tc.expected_detection}', Actual '{tc.actual_detection}'.",
                execution_type="DEMO_SIMULATION",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc)
            )
            db.session.add(texec)
            db.session.flush()

            # DetectionEvaluation
            deval = DetectionEvaluation(
                test_execution_id=texec.id,
                rule_id=tc.rule_id,
                expected_detection=tc.expected_detection,
                actual_detection=tc.actual_detection,
                classification=cls_code,
                evidence=f"Controlled demo evaluation for test vector {tc.test_id}.",
                data_source="DEMO",
                reviewed_by="Lead Security Architect",
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(deval)

            # ValidationResult (legacy backward compatibility)
            val = ValidationResult(
                test_case_id=tc.id,
                rule_id=tc.rule_id,
                expected_result=tc.expected_detection,
                actual_result=tc.actual_detection,
                status=tc.status,
                evidence=f"Controlled verification against test case {tc.test_id} (Classification: {cls_code}).",
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(val)

        db.session.commit()

        # 6. Seed Performance Measurements
        print("[*] Seeding performance benchmarks (labeled DEMO_SIMULATION)...")
        perf_records = [
            {
                "rule_id": rules_by_sid[1000001].id,
                "snort_execution_id": demo_snort_exec.id,
                "packets_processed": 10000,
                "alerts_generated": 2,
                "processing_time": 0.0450,
                "alerts_per_1000_packets": 0.20,
                "throughput": 222222.2,
                "detection_rate": 100.0,
                "status": "Optimal",
                "measurement_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_version": "Snort 2.9 (Demo Reference)"
            },
            {
                "rule_id": rules_by_sid[1000002].id,
                "snort_execution_id": demo_snort_exec.id,
                "packets_processed": 10000,
                "alerts_generated": 1,
                "processing_time": 0.0380,
                "alerts_per_1000_packets": 0.10,
                "throughput": 263157.9,
                "detection_rate": 50.0,
                "status": "Optimal",
                "measurement_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_version": "Snort 2.9 (Demo Reference)"
            },
            {
                "rule_id": rules_by_sid[1000003].id,
                "snort_execution_id": demo_snort_exec.id,
                "packets_processed": 10000,
                "alerts_generated": 1,
                "processing_time": 0.0410,
                "alerts_per_1000_packets": 0.10,
                "throughput": 243902.4,
                "detection_rate": 100.0,
                "status": "Optimal",
                "measurement_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_version": "Snort 2.9 (Demo Reference)"
            },
            {
                "rule_id": rules_by_sid[1000005].id,
                "snort_execution_id": demo_snort_exec.id,
                "packets_processed": 5000,
                "alerts_generated": 1,
                "processing_time": 0.0220,
                "alerts_per_1000_packets": 0.20,
                "throughput": 227272.7,
                "detection_rate": 0.0,
                "status": "Optimal",
                "measurement_type": "DEMO_SIMULATION",
                "data_source": "DEMO",
                "snort_version": "Snort 2.9 (Demo Reference)"
            }
        ]

        for pr in perf_records:
            db.session.add(PerformanceMeasurement(**pr))

        # 7. Seed MITRE ATT&CK Mappings
        print("[*] Seeding MITRE ATT&CK mappings...")
        mitre_data = [
            {
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "Discovery",
                "rule_id": rules_by_sid[1000001].id,
                "detection_logic": "Detection mapping based on the documented detection logic: Identifies rapid TCP SYN probes across consecutive ports.",
                "evidence": "Matches threshold rule SID 1000001 trigger parameters.",
                "severity": "High",
                "validation_status": "Validated"
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "rule_id": rules_by_sid[1000002].id,
                "detection_logic": "Detection mapping based on the documented detection logic: Inspects HTTP payloads for executable command invocation tokens ('cmd.exe').",
                "evidence": "Observed in HTTP POST payload parameter inspection.",
                "severity": "Critical",
                "validation_status": "Validated"
            },
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "rule_id": rules_by_sid[1000003].id,
                "detection_logic": "Detection mapping based on the documented detection logic: Monitors repeated SSH authentication connection attempts.",
                "evidence": "Threshold burst rule SID 1000003.",
                "severity": "High",
                "validation_status": "Validated"
            },
            {
                "technique_id": "T1071.001",
                "technique_name": "Web Protocols",
                "tactic": "Command and Control",
                "rule_id": rules_by_sid[1000004].id,
                "detection_logic": "Detection mapping based on the documented detection logic: Identifies directory traversal probing within HTTP application traffic.",
                "evidence": "Matches file path token in rule SID 1000004.",
                "severity": "High",
                "validation_status": "Candidate"
            },
            {
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "rule_id": rules_by_sid[1000006].id,
                "detection_logic": "Detection mapping based on the documented detection logic: Inspects abnormal DNS query lengths indicating data exfiltration tunneling.",
                "evidence": "DNS label size threshold inspection.",
                "severity": "Medium",
                "validation_status": "Candidate"
            }
        ]

        for md in mitre_data:
            db.session.add(MitreMapping(**md))

        db.session.commit()
        print("[+] Demonstration environment seeded successfully!")
        print("    Demo User: admin | Password: [Configured via SECURIFT_DEMO_PASSWORD]")


if __name__ == "__main__":
    seed_database()
