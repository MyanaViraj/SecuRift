import os
from flask import Blueprint, render_template, request, Response, current_app
from flask_login import login_required
from models.models import TestCase, Rule
from analyzer.report_generator import generate_coverage_csv

coverage_bp = Blueprint("coverage", __name__)


def build_matrix_data():
    """Compiles the detection coverage matrix from stored database test cases and rules."""
    test_cases = TestCase.query.order_by(TestCase.id.asc()).all()
    rows = []

    for tc in test_cases:
        rule_sid = tc.rule.sid if tc.rule else "—"
        mitre_tech = tc.rule.mitre_technique if (tc.rule and tc.rule.mitre_technique) else "—"

        rows.append({
            "detection": tc.name,
            "sid": rule_sid,
            "test_id": tc.test_id,
            "expected": tc.expected_detection,
            "actual": tc.actual_detection,
            "severity": tc.severity,
            "mitre": mitre_tech,
            "status": tc.status
        })

    return rows


@coverage_bp.route("/coverage", methods=["GET"])
@login_required
def index():
    status_filter = request.args.get("status", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    mitre_filter = request.args.get("mitre", "").strip().upper()

    all_rows = build_matrix_data()
    filtered_rows = []

    for r in all_rows:
        if status_filter and r["status"] != status_filter:
            continue
        if sev_filter and r["severity"] != sev_filter:
            continue
        if mitre_filter and mitre_filter not in r["mitre"].upper():
            continue
        filtered_rows.append(r)

    return render_template(
        "coverage.html",
        active_page="coverage",
        matrix_rows=filtered_rows
    )


@coverage_bp.route("/coverage/export-csv", methods=["GET"])
@login_required
def export_csv():
    matrix_data = build_matrix_data()
    tmp_path = os.path.join(current_app.config["REPORTS_FOLDER"], "coverage_matrix_export.csv")
    generate_coverage_csv(matrix_data, tmp_path)

    with open(tmp_path, "r", encoding="utf-8") as f:
        csv_content = f.read()

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=securift_coverage_matrix.csv"}
    )
