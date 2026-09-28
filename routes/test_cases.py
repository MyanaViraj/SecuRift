import os
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from models.models import (
    TestCase, Rule, Alert, ValidationResult, TestExecution,
    SnortExecution, PCAPAnalysis, DetectionEvaluation
)
from models import db
from analyzer.detection_metrics import evaluate_test_case_result, classify_detection_outcome
from analyzer.snort_runner import check_snort_installed, run_snort_on_pcap
from analyzer.snort_parser import parse_snort_alerts_text
from routes.auth import role_required

test_cases_bp = Blueprint("test_cases", __name__)


def evaluate_test_case_lineage(tc, reviewer_name="Analyst"):
    """
    Evaluates a TestCase through explicit execution lineage:
    TestCase -> PCAP -> SnortExecution -> Alert -> TestExecution -> DetectionEvaluation
    """
    pcap_rec = None
    if tc.pcap_file:
        pcap_rec = PCAPAnalysis.query.filter(
            (PCAPAnalysis.filename == tc.pcap_file) | (PCAPAnalysis.stored_filename == tc.pcap_file)
        ).first()

    actual_state = "No Alert"
    snort_exec = None
    data_src = "DEMO" if "DEMO" in (tc.test_id or "") or "DEMO" in (tc.name or "") else "REAL"

    # Check if real Snort is available and we have a valid rule and PCAP
    snort_info = check_snort_installed()
    if snort_info and tc.rule and tc.pcap_file:
        pcap_path = os.path.join(current_app.config["PCAP_FOLDER"], tc.pcap_file)
        if os.path.exists(pcap_path):
            start_t = datetime.now(timezone.utc)
            res = run_snort_on_pcap(pcap_path, rules_text=tc.rule.rule_text)
            end_t = datetime.now(timezone.utc)
            if res.get("success"):
                raw_alerts = res.get("alerts_raw", "")
                parsed = parse_snort_alerts_text(raw_alerts) if raw_alerts else []
                matched = [a for a in parsed if a["sid"] == tc.rule.sid]
                if matched:
                    actual_state = "Alert"
                data_src = "REAL_SNORT"

                snort_exec = SnortExecution(
                    pcap_analysis_id=pcap_rec.id if pcap_rec else None,
                    rule_set=f"Rule SID {tc.rule.sid}",
                    command_summary=f"snort -q -r {tc.pcap_file} -c custom.rules -A fast",
                    snort_version=snort_info.get("version", "Snort 2.9+"),
                    started_at=start_t,
                    completed_at=end_t,
                    processing_time=res.get("execution_time", 0.0),
                    packets_processed=pcap_rec.total_packets if pcap_rec else 0,
                    alerts_generated=len(matched),
                    exit_code=res.get("return_code", 0),
                    status="SUCCESS",
                    stdout=res.get("stdout", ""),
                    stderr=res.get("stderr", ""),
                    execution_type="REAL_SNORT"
                )
                db.session.add(snort_exec)
                db.session.flush()

                # Save real alerts linked to this execution
                for pa in matched:
                    al = Alert(
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
                        pcap_file=tc.pcap_file,
                        source_type="REAL_SNORT",
                        data_source="REAL_SNORT",
                        snort_execution_id=snort_exec.id,
                        pcap_analysis_id=pcap_rec.id if pcap_rec else None,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.session.add(al)

    # If Snort was not executed live just now:
    if not snort_exec:
        if pcap_rec and tc.rule:
            prior_exec = SnortExecution.query.filter_by(pcap_analysis_id=pcap_rec.id).order_by(SnortExecution.id.desc()).first()
            if prior_exec:
                snort_exec = prior_exec
                al_match = Alert.query.filter_by(snort_execution_id=prior_exec.id, sid=tc.rule.sid).first()
                if al_match:
                    actual_state = "Alert"
        if not snort_exec and tc.actual_detection in ("Alert", "No Alert"):
            actual_state = tc.actual_detection

    tc.actual_detection = actual_state
    tc.status = evaluate_test_case_result(tc.expected_detection, tc.actual_detection)

    evidence_text = (
        f"Evaluated via lineage: Expected '{tc.expected_detection}', Actual '{tc.actual_detection}'. "
        f"Target SID: {tc.rule.sid if tc.rule else 'None'}, Capture: {tc.pcap_file or 'None'}, "
        f"Execution ID: {snort_exec.id if snort_exec else 'Historical/Baseline'}."
    )

    test_exec = TestExecution(
        test_case_id=tc.id,
        pcap_analysis_id=pcap_rec.id if pcap_rec else None,
        snort_execution_id=snort_exec.id if snort_exec else None,
        rule_id=tc.rule_id,
        expected_result=tc.expected_detection,
        actual_result=tc.actual_detection,
        status=tc.status,
        evidence=evidence_text,
        execution_type=data_src,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc)
    )
    db.session.add(test_exec)
    db.session.flush()

    # Create DetectionEvaluation for coherent confusion matrix
    cls_code = classify_detection_outcome(tc.expected_detection, tc.actual_detection)
    det_eval = DetectionEvaluation(
        test_execution_id=test_exec.id,
        rule_id=tc.rule_id,
        expected_detection=tc.expected_detection,
        actual_detection=tc.actual_detection,
        classification=cls_code,
        evidence=evidence_text,
        data_source=data_src,
        reviewed_by=reviewer_name,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(det_eval)

    # Legacy table for compatibility
    val_res = ValidationResult(
        test_case_id=tc.id,
        rule_id=tc.rule_id,
        expected_result=tc.expected_detection,
        actual_result=tc.actual_detection,
        status=tc.status,
        evidence=evidence_text,
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(val_res)
    return test_exec


@test_cases_bp.route("/test-cases", methods=["GET"])
@login_required
def index():
    status_filter = request.args.get("status", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    q = request.args.get("q", "").strip()

    query = TestCase.query

    if status_filter:
        query = query.filter_by(status=status_filter)
    if sev_filter:
        query = query.filter_by(severity=sev_filter)
    if q:
        query = query.filter(
            (TestCase.name.ilike(f"%{q}%")) |
            (TestCase.test_id.ilike(f"%{q}%")) |
            (TestCase.category.ilike(f"%{q}%"))
        )

    test_cases = query.order_by(TestCase.id.desc()).all()
    available_rules = Rule.query.order_by(Rule.sid.asc()).all()

    # Get available pcaps from upload folder
    pcap_dir = current_app.config.get("PCAP_FOLDER", "")
    available_pcaps = []
    if os.path.exists(pcap_dir):
        available_pcaps = [f for f in os.listdir(pcap_dir) if f.endswith((".pcap", ".pcapng", ".cap"))]

    return render_template(
        "test_cases.html",
        active_page="test_cases",
        test_cases=test_cases,
        available_rules=available_rules,
        available_pcaps=available_pcaps
    )


@test_cases_bp.route("/test-cases/create", methods=["POST"])
@login_required
def create():
    test_id = request.form.get("test_id", "").strip()
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "Network Inspection").strip()
    description = request.form.get("description", "").strip()
    expected_detection = request.form.get("expected_detection", "Alert").strip()
    rule_id_raw = request.form.get("rule_id", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    pcap_file = request.form.get("pcap_file", "").strip()

    rule_id = int(rule_id_raw) if rule_id_raw and rule_id_raw.isdigit() else None

    # Check for duplicate test_id
    if TestCase.query.filter_by(test_id=test_id).first():
        flash(f"Test Case ID '{test_id}' already exists. Please choose a unique identifier.", "warning")
        return redirect(url_for("test_cases.index"))

    tc = TestCase(
        test_id=test_id,
        name=name,
        category=category,
        description=description,
        expected_detection=expected_detection,
        actual_detection="Untested",
        rule_id=rule_id,
        severity=severity,
        pcap_file=pcap_file,
        status="PENDING"
    )

    try:
        db.session.add(tc)
        db.session.commit()
        flash(f"Test case '{test_id}: {name}' created successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error creating test case: {str(e)}", "danger")

    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/test-cases/edit/<int:test_case_id>", methods=["POST"])
@login_required
def edit(test_case_id):
    tc = db.session.get(TestCase, test_case_id)
    if not tc:
        flash("Test case not found.", "danger")
        return redirect(url_for("test_cases.index"))

    tc.name = request.form.get("name", tc.name).strip()
    tc.category = request.form.get("category", tc.category).strip()
    tc.description = request.form.get("description", tc.description).strip()
    tc.expected_detection = request.form.get("expected_detection", tc.expected_detection).strip()
    tc.actual_detection = request.form.get("actual_detection", tc.actual_detection).strip()

    rule_id_raw = request.form.get("rule_id", "").strip()
    tc.rule_id = int(rule_id_raw) if rule_id_raw and rule_id_raw.isdigit() else None
    tc.severity = request.form.get("severity", tc.severity).strip()
    tc.pcap_file = request.form.get("pcap_file", tc.pcap_file).strip()

    tc.status = evaluate_test_case_result(tc.expected_detection, tc.actual_detection)

    try:
        db.session.commit()
        flash(f"Test case '{tc.test_id}' updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating test case: {str(e)}", "danger")

    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/test-cases/delete/<int:test_case_id>", methods=["POST"])
@role_required("Administrator")
def delete(test_case_id):
    tc = db.session.get(TestCase, test_case_id)
    if not tc:
        flash("Test case not found.", "warning")
        return redirect(url_for("test_cases.index"))
    tid = tc.test_id
    try:
        db.session.delete(tc)
        db.session.commit()
        flash(f"Test case '{tid}' deleted.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting test case: {str(e)}", "danger")

    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/test-cases/evaluate/<int:test_case_id>", methods=["POST"])
@login_required
def evaluate_single(test_case_id):
    tc = db.session.get(TestCase, test_case_id)
    if not tc:
        flash("Test case not found.", "danger")
        return redirect(url_for("test_cases.index"))

    reviewer_name = current_user.username if current_user.is_authenticated else "Operator"
    evaluate_test_case_lineage(tc, reviewer_name=reviewer_name)
    db.session.commit()

    flash(f"Evaluated {tc.test_id}: Status {tc.status} (Expected: {tc.expected_detection}, Actual: {tc.actual_detection}).", "success")
    return redirect(url_for("test_cases.index"))


@test_cases_bp.route("/test-cases/evaluate-all", methods=["POST"])
@login_required
def run_all_evaluations():
    test_cases = TestCase.query.all()
    count = 0
    reviewer_name = current_user.username if current_user.is_authenticated else "Operator"
    for tc in test_cases:
        evaluate_test_case_lineage(tc, reviewer_name=reviewer_name)
        count += 1

    db.session.commit()
    flash(f"Systematically evaluated {count} test cases with complete data lineage.", "success")
    return redirect(url_for("test_cases.index"))

