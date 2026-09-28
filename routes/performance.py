import os
import time
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required
from models.models import (
    PerformanceMeasurement, Rule, PCAPAnalysis, Alert,
    SnortExecution, DetectionEvaluation
)
from models import db
from analyzer.performance_analyzer import calculate_performance_metrics
from analyzer.pcap_analyzer import analyze_pcap_file
from analyzer.snort_runner import check_snort_installed, run_snort_on_pcap
from analyzer.snort_parser import parse_snort_alerts_text

performance_bp = Blueprint("performance", __name__)


def get_rule_detection_rate(rule_id):
    """
    Empirically calculates detection rate from DetectionEvaluation records for a specific rule.
    Returns float percentage or None if insufficient evaluation data.
    """
    evals = DetectionEvaluation.query.filter_by(rule_id=rule_id).all()
    if not evals:
        return None
    tp = sum(1 for e in evals if e.classification == "TP")
    fn = sum(1 for e in evals if e.classification == "FN")
    if tp + fn == 0:
        return None
    return round((tp / (tp + fn)) * 100.0, 2)


@performance_bp.route("/performance", methods=["GET"])
@login_required
def index():
    measurements = PerformanceMeasurement.query.order_by(PerformanceMeasurement.id.desc()).all()
    rules = Rule.query.order_by(Rule.sid.asc()).all()
    snort_info = check_snort_installed()

    # Get available pcaps
    pcap_dir = current_app.config.get("PCAP_FOLDER", "")
    available_pcaps = []
    if os.path.exists(pcap_dir):
        available_pcaps = [f for f in os.listdir(pcap_dir) if f.endswith((".pcap", ".pcapng", ".cap"))]

    # Chart data
    chart_labels = [f"SID {m.rule.sid}" if m.rule else f"Rule #{m.rule_id}" for m in measurements[:8]]
    chart_values = [m.alerts_per_1000_packets for m in measurements[:8]]

    return render_template(
        "performance.html",
        active_page="performance",
        measurements=measurements,
        rules=rules,
        pcaps=available_pcaps,
        snort_installed=bool(snort_info),
        snort_version=snort_info.get("version", "N/A") if snort_info else "NOT INSTALLED — REAL SNORT BENCHMARKING UNAVAILABLE",
        chart_labels=chart_labels or ["No Benchmarks"],
        chart_values=chart_values or [0]
    )


@performance_bp.route("/performance/run", methods=["POST"])
@login_required
def run_benchmark():
    """
    MODE A — REAL SNORT BENCHMARK
    Requires actual Snort execution. Never estimates alerts from packet counts or heuristics.
    """
    snort_info = check_snort_installed()
    if not snort_info:
        flash(
            "Snort is unavailable. Real Snort benchmarking cannot be performed. "
            "PCAP traffic analysis remains available under Baseline Traffic.",
            "warning"
        )
        return redirect(url_for("performance.index"))

    rule_id_raw = request.form.get("rule_id", "").strip()
    pcap_filename = request.form.get("pcap_file", "").strip()

    if not rule_id_raw or not pcap_filename:
        flash("Please select both a rule and a target PCAP capture for benchmarking.", "warning")
        return redirect(url_for("performance.index"))

    rule = db.session.get(Rule, int(rule_id_raw))
    if not rule:
        flash("Target rule not found.", "danger")
        return redirect(url_for("performance.index"))

    pcap_path = os.path.join(current_app.config["PCAP_FOLDER"], pcap_filename)
    if not os.path.exists(pcap_path):
        flash(f"Target PCAP file '{pcap_filename}' not found in upload repository.", "danger")
        return redirect(url_for("performance.index"))

    # Find matching PCAPAnalysis record to obtain actual packet count
    pcap_rec = PCAPAnalysis.query.filter(
        (PCAPAnalysis.filename == pcap_filename) | (PCAPAnalysis.stored_filename == pcap_filename)
    ).first()
    if not pcap_rec:
        analysis_res = analyze_pcap_file(pcap_path)
        total_packets = analysis_res.get("total_packets", 0)
    else:
        total_packets = pcap_rec.total_packets

    # Execute actual Snort binary with the single selected rule
    snort_res = run_snort_on_pcap(pcap_path, rules_text=rule.rule_text)
    if not snort_res.get("success"):
        flash(f"Real Snort benchmark execution failed: {snort_res.get('error')}", "danger")
        return redirect(url_for("performance.index"))

    elapsed_time = snort_res.get("execution_time", 0.001)
    raw_alerts = snort_res.get("alerts_raw", "")
    parsed_alerts = parse_snort_alerts_text(raw_alerts) if raw_alerts else []
    actual_alert_count = len([a for a in parsed_alerts if a["sid"] == rule.sid])

    # Record actual SnortExecution
    snort_exec = SnortExecution(
        pcap_analysis_id=pcap_rec.id if pcap_rec else None,
        rule_set=f"Benchmark SID {rule.sid}",
        command_summary=f"snort -q -r {pcap_filename} -c custom.rules -A fast",
        snort_version=snort_info.get("version", "Snort 2.9+"),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        processing_time=elapsed_time,
        packets_processed=total_packets,
        alerts_generated=actual_alert_count,
        exit_code=snort_res.get("return_code", 0),
        status="SUCCESS",
        stdout=snort_res.get("stdout", ""),
        stderr=snort_res.get("stderr", ""),
        execution_type="REAL_SNORT"
    )
    db.session.add(snort_exec)
    db.session.flush()

    # Calculate performance metrics solely from real execution
    perf_data = calculate_performance_metrics(total_packets, actual_alert_count, elapsed_time)
    empirical_dr = get_rule_detection_rate(rule.id)

    perf_record = PerformanceMeasurement(
        rule_id=rule.id,
        pcap_analysis_id=pcap_rec.id if pcap_rec else None,
        snort_execution_id=snort_exec.id,
        packets_processed=total_packets,
        alerts_generated=actual_alert_count,
        processing_time=perf_data["processing_time"],
        alerts_per_1000_packets=perf_data["alerts_per_1000_packets"],
        throughput=perf_data.get("packets_per_second", 0.0),
        detection_rate=empirical_dr if empirical_dr is not None else 0.0,
        status=perf_data["status"],
        measurement_type="REAL_SNORT",
        snort_version=snort_info.get("version", "Snort 2.9+"),
        data_source="REAL",
        created_at=datetime.now(timezone.utc)
    )

    db.session.add(perf_record)
    db.session.commit()

    dr_label = f"{empirical_dr}%" if empirical_dr is not None else "Insufficient validated test cases"
    flash(
        f"REAL Snort benchmark completed for SID {rule.sid}: {total_packets} packets processed in {elapsed_time}s; "
        f"{actual_alert_count} actual alerts generated ({perf_data['alerts_per_1000_packets']} alerts/1k pkts). "
        f"Detection Rate: {dr_label}.",
        "success"
    )
    return redirect(url_for("performance.index"))

