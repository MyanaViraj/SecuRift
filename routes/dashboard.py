from flask import Blueprint, render_template
from flask_login import login_required
from models.models import (
    Rule, TestCase, PCAPAnalysis, Alert, ValidationResult,
    FalsePositiveRecord, PerformanceMeasurement, MitreMapping,
    DetectionEvaluation
)
from analyzer.detection_metrics import compute_metrics, compute_metrics_from_evaluations

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    # 1. Rules Stats
    total_rules = Rule.query.count()
    active_rules = Rule.query.filter_by(enabled=True).count()

    # 2. PCAP Traffic Stats
    pcap_records = PCAPAnalysis.query.all()
    pcap_count = len(pcap_records)
    total_packets = sum(p.total_packets for p in pcap_records)

    # 3. Alerts Stats (Honest SOC triage: unreviewed alerts remain UNKNOWN)
    total_alerts = Alert.query.count()
    tp_count = FalsePositiveRecord.query.filter_by(classification="True Positive").count()
    fp_count = FalsePositiveRecord.query.filter_by(classification="False Positive").count()
    reviewed_alerts = tp_count + fp_count
    unknown_alerts = max(0, total_alerts - reviewed_alerts)

    # 4. Confusion Matrix counts strictly from unified DetectionEvaluation records
    evals = DetectionEvaluation.query.all()
    metrics = compute_metrics_from_evaluations(evals)

    # 5. MITRE Techniques
    mitre_count = len(set(
        m.technique_id for m in MitreMapping.query.all()
    ))

    # 6. Severity Distribution
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in Alert.query.all():
        sev = a.severity or "Medium"
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["Medium"] += 1

    # 7. Performance Benchmarks for Chart
    perf_records = PerformanceMeasurement.query.order_by(PerformanceMeasurement.id.desc()).limit(6).all()
    perf_labels = [f"SID {p.rule.sid}" if p.rule else f"Rule #{p.rule_id}" for p in perf_records]
    perf_values = [p.alerts_per_1000_packets for p in perf_records]

    # 8. MITRE Distribution for Chart
    mitre_dist = {}
    for m in MitreMapping.query.all():
        t = m.technique_id
        mitre_dist[t] = mitre_dist.get(t, 0) + 1

    # 9. Recent Activity Table
    recent_vals = ValidationResult.query.order_by(ValidationResult.id.desc()).limit(6).all()
    recent_activity = []
    for r in recent_vals:
        recent_activity.append({
            "test_name": r.test_case.name if r.test_case else "Direct Signature Verification",
            "sid": r.rule.sid if r.rule else "—",
            "expected": r.expected_result,
            "actual": r.actual_result,
            "status": r.status,
            "severity": r.rule.severity if r.rule else "Medium",
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else ""
        })

    stats = {
        "total_rules": total_rules,
        "active_rules": active_rules,
        "pcap_count": pcap_count,
        "total_packets_analyzed": total_packets,
        "total_alerts": total_alerts,
        "reviewed_alerts": reviewed_alerts,
        "unknown_alerts": unknown_alerts,
        "true_positives": metrics["true_positives"],
        "false_positives": metrics["false_positives"],
        "false_negatives": metrics["false_negatives"],
        "true_negatives": metrics["true_negatives"],
        "detection_rate": metrics["detection_rate"],
        "false_positive_rate": metrics["false_positive_rate"],
        "evaluation_sample_size": metrics["sample_size"],
        "mitre_covered": mitre_count
    }

    chart_data = {
        "severity": sev_counts,
        "perf_labels": perf_labels or ["No Benchmarks"],
        "perf_values": perf_values or [0],
        "mitre_labels": list(mitre_dist.keys()) or ["None"],
        "mitre_values": list(mitre_dist.values()) or [0]
    }

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        stats=stats,
        chart_data=chart_data,
        recent_activity=recent_activity
    )
