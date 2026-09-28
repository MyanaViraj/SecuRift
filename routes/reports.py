import os
from datetime import datetime, timezone
from flask import Blueprint, render_template, send_file, flash, redirect, url_for, current_app
from flask_login import login_required
from models.models import Report, Rule, TestCase, PerformanceMeasurement, Alert, FalsePositiveRecord, DetectionEvaluation
from models import db
from analyzer.report_generator import (
    generate_rules_pdf, generate_coverage_pdf, generate_performance_pdf,
    generate_performance_csv, generate_rules_csv
)
from analyzer.detection_metrics import compute_metrics, compute_metrics_from_evaluations
from routes.coverage import build_matrix_data

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports", methods=["GET"])
@login_required
def index():
    reports = Report.query.order_by(Report.id.desc()).all()
    return render_template("reports.html", active_page="reports", reports=reports)


@reports_bp.route("/reports/generate-rules-pdf", methods=["GET"])
@login_required
def generate_rules_pdf_route():
    rules = Rule.query.order_by(Rule.sid.asc()).all()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"securift_custom_rules_{timestamp_str}.pdf"
    file_path = os.path.join(current_app.config["REPORTS_FOLDER"], filename)

    try:
        generate_rules_pdf(rules, file_path)

        rep_record = Report(
            report_type="Custom Snort Rules",
            filename=filename,
            file_format="PDF",
            file_path=file_path,
            generated_at=datetime.now(timezone.utc)
        )
        db.session.add(rep_record)
        db.session.commit()

        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f"Failed to generate Rules PDF report: {str(e)}", "danger")
        return redirect(url_for("reports.index"))


@reports_bp.route("/reports/generate-coverage-pdf", methods=["GET"])
@login_required
def generate_coverage_pdf_route():
    matrix_data = build_matrix_data()

    # Calculate metrics strictly from unified DetectionEvaluation population
    evals = DetectionEvaluation.query.all()
    metrics = compute_metrics_from_evaluations(evals)

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"securift_coverage_matrix_{timestamp_str}.pdf"
    file_path = os.path.join(current_app.config["REPORTS_FOLDER"], filename)

    try:
        generate_coverage_pdf(matrix_data, metrics, file_path)

        rep_record = Report(
            report_type="Detection Coverage Matrix",
            filename=filename,
            file_format="PDF",
            file_path=file_path,
            generated_at=datetime.now(timezone.utc)
        )
        db.session.add(rep_record)
        db.session.commit()

        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f"Failed to generate Coverage Matrix PDF report: {str(e)}", "danger")
        return redirect(url_for("reports.index"))


@reports_bp.route("/reports/generate-performance-pdf", methods=["GET"])
@login_required
def generate_performance_pdf_route():
    measurements = PerformanceMeasurement.query.order_by(PerformanceMeasurement.id.desc()).all()
    perf_data = []
    for m in measurements:
        perf_data.append({
            "sid": m.rule.sid if m.rule else "—",
            "message": m.rule.message if m.rule else "Unlinked",
            "packets_processed": m.packets_processed,
            "alerts_generated": m.alerts_generated,
            "processing_time": m.processing_time,
            "alerts_per_1000_packets": m.alerts_per_1000_packets,
            "throughput": m.throughput or 0.0,
            "detection_rate": m.detection_rate,
            "status": m.status,
            "measurement_type": m.measurement_type or "REAL_SNORT",
            "data_source": m.data_source or "REAL",
            "snort_version": m.snort_version or "N/A",
            "execution_id": m.snort_execution_id or "—",
            "pcap": m.pcap_analysis.filename if m.pcap_analysis else "N/A"
        })

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"securift_performance_benchmark_{timestamp_str}.pdf"
    file_path = os.path.join(current_app.config["REPORTS_FOLDER"], filename)

    try:
        generate_performance_pdf(perf_data, file_path)

        rep_record = Report(
            report_type="Performance Benchmark",
            filename=filename,
            file_format="PDF",
            file_path=file_path,
            generated_at=datetime.now(timezone.utc)
        )
        db.session.add(rep_record)
        db.session.commit()

        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        flash(f"Failed to generate Performance PDF report: {str(e)}", "danger")
        return redirect(url_for("reports.index"))


@reports_bp.route("/reports/export-performance-csv", methods=["GET"])
@login_required
def export_performance_csv_route():
    measurements = PerformanceMeasurement.query.order_by(PerformanceMeasurement.id.desc()).all()
    perf_data = []
    for m in measurements:
        perf_data.append({
            "sid": m.rule.sid if m.rule else "—",
            "message": m.rule.message if m.rule else "Unlinked",
            "packets_processed": m.packets_processed,
            "alerts_generated": m.alerts_generated,
            "processing_time": m.processing_time,
            "alerts_per_1000_packets": m.alerts_per_1000_packets,
            "throughput": m.throughput or 0.0,
            "detection_rate": m.detection_rate,
            "status": m.status,
            "measurement_type": m.measurement_type or "REAL_SNORT",
            "data_source": m.data_source or "REAL",
            "snort_version": m.snort_version or "N/A",
            "execution_id": m.snort_execution_id or "—",
            "pcap": m.pcap_analysis.filename if m.pcap_analysis else "N/A"
        })

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"securift_performance_benchmark_{timestamp_str}.csv"
    file_path = os.path.join(current_app.config["REPORTS_FOLDER"], filename)

    generate_performance_csv(perf_data, file_path)

    rep_record = Report(
        report_type="Performance Benchmark",
        filename=filename,
        file_format="CSV",
        file_path=file_path,
        generated_at=datetime.now(timezone.utc)
    )
    db.session.add(rep_record)
    db.session.commit()

    return send_file(file_path, as_attachment=True, download_name=filename)


@reports_bp.route("/reports/download/<int:report_id>", methods=["GET"])
@login_required
def download_report(report_id):
    rep = Report.query.get_or_404(report_id)
    if os.path.exists(rep.file_path):
        return send_file(rep.file_path, as_attachment=True, download_name=rep.filename)
    else:
        flash(f"Report file '{rep.filename}' was removed from storage.", "danger")
        return redirect(url_for("reports.index"))
