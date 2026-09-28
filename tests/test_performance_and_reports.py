import os
import io
import pytest
from unittest.mock import patch
from app import create_app
from config import TestingConfig
from models import db
from models.models import (
    User, Rule, PCAPAnalysis, PerformanceMeasurement, DetectionEvaluation
)
from analyzer.snort_runner import check_snort_installed, run_snort_on_pcap
from analyzer.report_generator import (
    generate_rules_pdf,
    generate_coverage_pdf,
    generate_performance_pdf
)


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        admin = User(username="admin", role="Administrator")
        admin.set_password("admin123")
        db.session.add(admin)

        rule = Rule(
            sid=1000001,
            rule_text='alert tcp any any -> any 80 (msg:"SQL Injection Pattern"; sid:1000001; rev:1;)',
            message="SQL Injection Pattern",
            severity="High",
            enabled=True
        )
        pcap = PCAPAnalysis(filename="traffic.pcap", total_packets=2000, data_source="REAL")
        db.session.add_all([rule, pcap])
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_performance_without_snort_execution(client, app):
    """When Snort is not installed, real benchmarking must be rejected, not simulated."""
    client.post("/login", data={"username": "admin", "password": "admin123"})

    with patch("routes.performance.check_snort_installed", return_value=None):
        resp = client.post("/performance/run", data={
            "rule_id": 1,
            "pcap_file": "sample_benign_traffic.pcap"
        }, follow_redirects=True)

        assert resp.status_code == 200
        # Check that clear fallback notice is present and no benchmark was fabricated
        assert b"Snort is unavailable" in resp.data

    with app.app_context():
        # Verify NO fake PerformanceMeasurement record was inserted
        measurements = PerformanceMeasurement.query.all()
        assert len(measurements) == 0


def test_performance_with_mock_snort_execution(client, app):
    """Verify benchmarking captures real elapsed time and real alert counts when Snort runs."""
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # Ensure a target pcap exists in PCAP_FOLDER
    pcap_dir = app.config["PCAP_FOLDER"]
    os.makedirs(pcap_dir, exist_ok=True)
    test_pcap_path = os.path.join(pcap_dir, "traffic.pcap")
    with open(test_pcap_path, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)

    mock_alerts = [
        {"sid": 1000001, "message": "SQL Injection Pattern", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2"}
    ]
    mock_snort_res = {
        "success": True,
        "execution_time": 0.125,
        "alerts_raw": '09/26-10:15:20.102341 [**] [1:1000001:1] SQL Injection Pattern [**] [Priority: 1] {TCP} 10.0.0.1:1000 -> 10.0.0.2:80',
        "return_code": 0
    }

    try:
        with patch("routes.performance.check_snort_installed", return_value={"path": "/usr/sbin/snort", "version": "Snort 2.9.20"}), \
             patch("routes.performance.run_snort_on_pcap", return_value=mock_snort_res), \
             patch("routes.performance.parse_snort_alerts_text", return_value=mock_alerts):

            resp = client.post("/performance/run", data={
                "rule_id": 1,
                "pcap_file": "traffic.pcap"
            }, follow_redirects=True)

            assert resp.status_code == 200

        with app.app_context():
            m = PerformanceMeasurement.query.first()
            assert m is not None
            assert m.rule_id == 1
            assert m.packets_processed == 2000
            assert m.alerts_generated == 1
            assert m.measurement_type == "REAL_SNORT"
            assert m.data_source == "REAL"
            assert m.snort_version == "Snort 2.9.20"
            # 1 alert per 2000 packets = 0.5 alerts/1000 packets
            assert m.alerts_per_1000_packets == 0.5
    finally:
        if os.path.exists(test_pcap_path):
            os.remove(test_pcap_path)


def test_pdf_reports_include_source_and_lineage_metadata(app):
    """Verify generated PDF reports clearly label data sources and audit lineage."""
    with app.app_context():
        rules = Rule.query.all()
        evals = DetectionEvaluation.query.all()
        measurements = PerformanceMeasurement.query.all()

        import tempfile
        # 1. Rules Spec PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            pdf1_path = f.name
        try:
            generate_rules_pdf(rules, pdf1_path)
            assert os.path.exists(pdf1_path)
            assert os.path.getsize(pdf1_path) > 500
        finally:
            if os.path.exists(pdf1_path):
                os.remove(pdf1_path)

        # 2. Coverage Matrix PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            pdf2_path = f.name
        try:
            generate_coverage_pdf([], {"detection_rate": "N/A", "false_positive_rate": "N/A", "precision": "N/A", "accuracy": "N/A", "f1_score": "N/A", "sample_size": 0}, pdf2_path)
            assert os.path.exists(pdf2_path)
            assert os.path.getsize(pdf2_path) > 500
        finally:
            if os.path.exists(pdf2_path):
                os.remove(pdf2_path)

        # 3. Performance Benchmark PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            pdf3_path = f.name
        try:
            generate_performance_pdf(measurements, pdf3_path)
            assert os.path.exists(pdf3_path)
            assert os.path.getsize(pdf3_path) > 500
        finally:
            if os.path.exists(pdf3_path):
                os.remove(pdf3_path)


def test_csv_exports_include_data_source_column(client):
    """Verify CSV export routes return valid CSV with Data Source auditing columns."""
    client.post("/login", data={"username": "admin", "password": "admin123"})

    # Rules export
    resp_rules = client.get("/rules/export")
    assert resp_rules.status_code == 200

    # Coverage export
    resp_cov = client.get("/coverage/export-csv")
    assert resp_cov.status_code == 200
    assert "text/csv" in resp_cov.headers["Content-Type"]
    assert b"Test Case ID" in resp_cov.data
    assert b"Data Source" in resp_cov.data

    # Performance export
    resp_perf = client.get("/reports/export-performance-csv")
    assert resp_perf.status_code == 200
    assert "text/csv" in resp_perf.headers["Content-Type"]
    assert b"Data Source" in resp_perf.data
