import pytest
from app import create_app
from config import TestingConfig
from models import db
from models.models import (
    User, Rule, TestCase, PCAPAnalysis, SnortExecution,
    TestExecution, DetectionEvaluation, Alert, FalsePositiveRecord
)
from analyzer.detection_metrics import (
    classify_detection_outcome, compute_metrics_from_evaluations, safe_div
)


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_classify_detection_outcome():
    """Verify standard confusion matrix mappings per Phase 6 & Phase 7."""
    assert classify_detection_outcome("Alert", "Alert") == "TP"
    assert classify_detection_outcome("Alert", "No Alert") == "FN"
    assert classify_detection_outcome("No Alert", "No Alert") == "TN"
    assert classify_detection_outcome("No Alert", "Alert") == "FP"
    assert classify_detection_outcome("Alert", "Untested") == "UNKNOWN"
    assert classify_detection_outcome("No Alert", "Untested") == "UNKNOWN"


def test_unified_confusion_matrix_population(app):
    """Verify TP, FP, TN, FN derive strictly from one coherent DetectionEvaluation cohort."""
    with app.app_context():
        rule = Rule(
            sid=1000001,
            rule_text='alert tcp any any -> any 80 (msg:"SQLi Attack Detection"; sid:1000001;)',
            message="SQLi Attack Detection",
            severity="High",
            enabled=True
        )
        db.session.add(rule)
        db.session.commit()

        evals = [
            DetectionEvaluation(rule_id=rule.id, expected_detection="Alert", actual_detection="Alert", classification="TP"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="Alert", actual_detection="Alert", classification="TP"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="Alert", actual_detection="Alert", classification="TP"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="Alert", actual_detection="No Alert", classification="FN"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="No Alert", actual_detection="No Alert", classification="TN"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="No Alert", actual_detection="No Alert", classification="TN"),
            DetectionEvaluation(rule_id=rule.id, expected_detection="No Alert", actual_detection="Alert", classification="FP"),
        ]
        db.session.add_all(evals)
        db.session.commit()

        metrics = compute_metrics_from_evaluations(evals)

        # TP=3, FN=1, TN=2, FP=1, Total=7
        assert metrics["true_positives"] == 3
        assert metrics["false_negatives"] == 1
        assert metrics["true_negatives"] == 2
        assert metrics["false_positives"] == 1
        assert metrics["sample_size"] == 7

        # Detection Rate (Recall) = TP / (TP + FN) = 3 / 4 = 75.0%
        assert metrics["detection_rate"] == 75.0

        # False Positive Rate = FP / (FP + TN) = 1 / 3 = 33.33%
        assert metrics["false_positive_rate"] == 33.33

        # Precision = TP / (TP + FP) = 3 / 4 = 75.0%
        assert metrics["precision"] == 75.0

        # Accuracy = (TP + TN) / Total = 5 / 7 = 71.43%
        assert metrics["accuracy"] == 71.43

        # F1 = 2 * (75.0 * 75.0) / (75.0 + 75.0) = 75.0%
        assert metrics["f1_score"] == 75.0


def test_no_hardcoded_detection_rate_when_zero_attacks():
    """Verify detection rate returns 'N/A' rather than 0% when no attack samples exist."""
    # TP=0, FN=0, TN=5, FP=0 (Only benign samples evaluated)
    evals = [
        type("Obj", (), {"classification": "TN"})() for _ in range(5)
    ]
    metrics = compute_metrics_from_evaluations(evals)
    assert metrics["true_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["detection_rate"] == "N/A"
    assert metrics["precision"] == "N/A"
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["accuracy"] == 100.0


def test_unreviewed_alerts_remain_unknown(app):
    """Verify that unreviewed alerts are NOT automatically inferred as True Positives."""
    with app.app_context():
        # Insert 3 alerts without any FalsePositiveRecord triage
        a1 = Alert(sid=1000001, message="Alert 1", source_type="REAL_SNORT", data_source="REAL_SNORT")
        a2 = Alert(sid=1000002, message="Alert 2", source_type="REAL_SNORT", data_source="REAL_SNORT")
        a3 = Alert(sid=1000003, message="Alert 3", source_type="REAL_SNORT", data_source="REAL_SNORT")
        db.session.add_all([a1, a2, a3])
        db.session.commit()

        # Check classification state property
        assert a1.classification_state == "Unknown"
        assert a2.classification_state == "Unknown"
        assert a3.classification_state == "Unknown"

        # Explicit operator triage should be the ONLY way to make an alert TP or FP
        fp_rec = FalsePositiveRecord(alert_id=a1.id, classification="True Positive", reviewed_by="analyst", notes="Valid exploit")
        db.session.add(fp_rec)
        db.session.commit()

        assert a1.classification_state == "True Positive"
        assert a2.classification_state == "Unknown"
        assert a3.classification_state == "Unknown"


def test_snort_execution_and_alert_data_lineage(app):
    """Verify that alerts are traceable to concrete SnortExecution and PCAPAnalysis entities."""
    with app.app_context():
        pcap = PCAPAnalysis(
            filename="capture_audit.pcap",
            stored_filename="uuid_capture_audit.pcap",
            total_packets=500,
            data_source="REAL"
        )
        db.session.add(pcap)
        db.session.commit()

        snort_exec = SnortExecution(
            pcap_analysis_id=pcap.id,
            rule_set="custom_rules.rules",
            command_summary="snort -r capture_audit.pcap -c custom_rules.rules",
            execution_type="REAL_SNORT",
            packets_processed=500,
            alerts_generated=1,
            exit_code=0,
            status="SUCCESS"
        )
        db.session.add(snort_exec)
        db.session.commit()

        alert = Alert(
            sid=1000001,
            message="Suspicious Shell Command",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            snort_execution_id=snort_exec.id,
            pcap_analysis_id=pcap.id,
            data_source="REAL_SNORT"
        )
        db.session.add(alert)
        db.session.commit()

        # Audit trail verification
        retrieved_alert = db.session.get(Alert, alert.id)
        assert retrieved_alert.snort_execution_id == snort_exec.id
        assert retrieved_alert.pcap_analysis_id == pcap.id
        assert retrieved_alert.snort_execution.execution_type == "REAL_SNORT"
        assert retrieved_alert.pcap_analysis.filename == "capture_audit.pcap"


def test_demo_vs_real_data_separation(app):
    """Verify that demo simulations are strictly tagged DEMO and never REAL_SNORT."""
    with app.app_context():
        demo_exec = SnortExecution(
            rule_set="demo_rules.rules",
            execution_type="DEMO_SIMULATION",
            status="SUCCESS"
        )
        real_exec = SnortExecution(
            rule_set="live_rules.rules",
            execution_type="REAL_SNORT",
            status="SUCCESS"
        )
        db.session.add_all([demo_exec, real_exec])
        db.session.commit()

        assert demo_exec.execution_type != "REAL_SNORT"
        assert real_exec.execution_type == "REAL_SNORT"
        assert demo_exec.execution_type == "DEMO_SIMULATION"
