import os
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
from models.models import Alert, Rule, FalsePositiveRecord, SnortExecution, PCAPAnalysis
from models import db
from analyzer.snort_runner import check_snort_installed, run_snort_on_pcap
from analyzer.snort_parser import parse_snort_alerts_text

snort_bp = Blueprint("snort", __name__)


@snort_bp.route("/snort", methods=["GET"])
@login_required
def index():
    snort_info = check_snort_installed()
    snort_status = {
        "installed": bool(snort_info),
        "path": snort_info.get("path") if snort_info else "",
        "version": snort_info.get("version") if snort_info else "NOT INSTALLED — REAL SNORT EXECUTION UNAVAILABLE"
    }

    # Available PCAPs
    pcap_dir = current_app.config.get("PCAP_FOLDER", "")
    available_pcaps = []
    if os.path.exists(pcap_dir):
        available_pcaps = [f for f in os.listdir(pcap_dir) if f.endswith((".pcap", ".pcapng", ".cap"))]

    available_rules = Rule.query.order_by(Rule.sid.asc()).all()
    enabled_rules_count = Rule.query.filter_by(enabled=True).count()
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    executions = SnortExecution.query.order_by(SnortExecution.id.desc()).limit(10).all()

    return render_template(
        "snort.html",
        active_page="snort",
        snort_status=snort_status,
        available_pcaps=available_pcaps,
        available_rules=available_rules,
        enabled_rules_count=enabled_rules_count,
        alerts=alerts,
        executions=executions
    )


@snort_bp.route("/snort/run", methods=["POST"])
@login_required
def run_snort():
    snort_info = check_snort_installed()
    if not snort_info:
        flash("Snort executable not detected. Real Snort benchmarking and execution unavailable. You can still import Snort log files.", "warning")
        return redirect(url_for("snort.index"))

    pcap_filename = request.form.get("pcap_file", "").strip()
    rule_scope = request.form.get("rule_scope", "all_enabled")

    pcap_path = os.path.join(current_app.config["PCAP_FOLDER"], pcap_filename)
    if not os.path.exists(pcap_path):
        flash(f"PCAP file '{pcap_filename}' not found.", "danger")
        return redirect(url_for("snort.index"))

    # Build rules text
    if rule_scope == "all_enabled":
        rules = Rule.query.filter_by(enabled=True).all()
    elif rule_scope.startswith("single_"):
        rule_id = int(rule_scope.split("_")[1])
        r = db.session.get(Rule, rule_id)
        rules = [r] if r else []
    else:
        rules = Rule.query.filter_by(enabled=True).all()

    rules_text = "\n".join([r.rule_text for r in rules])

    start_time = datetime.now(timezone.utc)
    res = run_snort_on_pcap(pcap_path, rules_text=rules_text)
    end_time = datetime.now(timezone.utc)

    # Find matching PCAP record if already analyzed
    pcap_rec = PCAPAnalysis.query.filter(
        (PCAPAnalysis.filename == pcap_filename) | (PCAPAnalysis.stored_filename == pcap_filename)
    ).first()

    raw_alerts = res.get("alerts_raw", "") if res.get("success") else ""
    parsed_alerts = parse_snort_alerts_text(raw_alerts) if raw_alerts else []

    # Create auditable SnortExecution record
    snort_exec = SnortExecution(
        pcap_analysis_id=pcap_rec.id if pcap_rec else None,
        rule_set=f"Scope: {rule_scope} ({len(rules)} rules)",
        command_summary=f"snort -q -r {pcap_filename} -c custom.rules -A fast",
        snort_version=snort_info.get("version", "Snort 2.9+"),
        started_at=start_time,
        completed_at=end_time,
        processing_time=res.get("execution_time", 0.0),
        packets_processed=pcap_rec.total_packets if pcap_rec else 0,
        alerts_generated=len(parsed_alerts),
        exit_code=res.get("return_code", 0),
        status="SUCCESS" if res.get("success") else "FAILED",
        stdout=res.get("stdout", ""),
        stderr=res.get("stderr", res.get("error", "")),
        execution_type="REAL_SNORT"
    )
    db.session.add(snort_exec)
    db.session.flush()

    if not res.get("success"):
        db.session.commit()
        flash(f"Snort execution halted: {res.get('error')}", "danger")
        return redirect(url_for("snort.index"))

    stored_count = 0
    for pa in parsed_alerts:
        alert = Alert(
            timestamp=pa["timestamp"],
            sid=pa["sid"],
            message=pa["message"],
            protocol=pa["protocol"],
            source_ip=pa["source_ip"],
            source_port=pa["source_port"],
            destination_ip=pa["destination_ip"],
            destination_port=pa["destination_port"],
            classification=pa["classification"],
            severity=pa["severity"],
            raw_alert=pa["raw_alert"],
            pcap_file=pcap_filename,
            source_type="REAL_SNORT",
            data_source="REAL_SNORT",
            snort_execution_id=snort_exec.id,
            pcap_analysis_id=pcap_rec.id if pcap_rec else None,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(alert)
        stored_count += 1

    db.session.commit()
    flash(f"Snort executed successfully in {res.get('execution_time')}s (Execution #{snort_exec.id}). Ingested {stored_count} real alerts.", "success")
    return redirect(url_for("snort.index"))


@snort_bp.route("/snort/upload-log", methods=["POST"])
@login_required
def upload_log():
    if "log_file" not in request.files:
        flash("No log file uploaded.", "warning")
        return redirect(url_for("snort.index"))

    file = request.files["log_file"]
    if not file or file.filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("snort.index"))

    filename = secure_filename(file.filename)
    save_path = os.path.join(current_app.config["SNORT_LOG_FOLDER"], filename)
    file.save(save_path)

    try:
        with open(save_path, "r", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        flash(f"Failed to read uploaded log: {str(e)}", "danger")
        return redirect(url_for("snort.index"))

    parsed_alerts = parse_snort_alerts_text(content)
    if not parsed_alerts:
        flash(f"No valid Snort fast alerts could be parsed from '{filename}'.", "warning")
        return redirect(url_for("snort.index"))

    stored_count = 0
    for pa in parsed_alerts:
        alert = Alert(
            timestamp=pa["timestamp"],
            sid=pa["sid"],
            message=pa["message"],
            protocol=pa["protocol"],
            source_ip=pa["source_ip"],
            source_port=pa["source_port"],
            destination_ip=pa["destination_ip"],
            destination_port=pa["destination_port"],
            classification=pa["classification"],
            severity=pa["severity"],
            raw_alert=pa["raw_alert"],
            source_type=f"IMPORTED LOG ({filename})",
            data_source="IMPORTED_SNORT_LOG",
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(alert)
        stored_count += 1

    db.session.commit()
    flash(f"Successfully imported and parsed {stored_count} alerts from '{filename}' (Marked as IMPORTED).", "success")
    return redirect(url_for("snort.index"))


@snort_bp.route("/snort/paste-log", methods=["POST"])
@login_required
def paste_log():
    log_text = request.form.get("log_text", "").strip()
    if not log_text:
        flash("Please paste Snort alert lines before submitting.", "warning")
        return redirect(url_for("snort.index"))

    parsed_alerts = parse_snort_alerts_text(log_text)
    if not parsed_alerts:
        flash("No Snort alert patterns recognized in pasted text.", "warning")
        return redirect(url_for("snort.index"))

    stored_count = 0
    for pa in parsed_alerts:
        alert = Alert(
            timestamp=pa["timestamp"],
            sid=pa["sid"],
            message=pa["message"],
            protocol=pa["protocol"],
            source_ip=pa["source_ip"],
            source_port=pa["source_port"],
            destination_ip=pa["destination_ip"],
            destination_port=pa["destination_port"],
            classification=pa["classification"],
            severity=pa["severity"],
            raw_alert=pa["raw_alert"],
            source_type="MANUAL LOG INGESTION",
            data_source="IMPORTED_SNORT_LOG",
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(alert)
        stored_count += 1

    db.session.commit()
    flash(f"Successfully parsed and ingested {stored_count} alerts (Marked as IMPORTED).", "success")
    return redirect(url_for("snort.index"))

