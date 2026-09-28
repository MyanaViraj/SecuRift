import os
import json
import uuid
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required
from werkzeug.utils import secure_filename
from models.models import PCAPAnalysis
from models import db
from analyzer.pcap_analyzer import analyze_pcap_file, validate_pcap_file_structure

baseline_bp = Blueprint("baseline", __name__)


@baseline_bp.route("/baseline", methods=["GET"])
@login_required
def index():
    analyses = PCAPAnalysis.query.order_by(PCAPAnalysis.id.desc()).all()
    current_analysis = analyses[0] if analyses else None
    return render_template(
        "baseline.html",
        active_page="baseline",
        analyses=analyses,
        current_analysis=current_analysis
    )


@baseline_bp.route("/baseline/view/<int:analysis_id>", methods=["GET"])
@login_required
def view_analysis(analysis_id):
    analyses = PCAPAnalysis.query.order_by(PCAPAnalysis.id.desc()).all()
    target_analysis = db.session.get(PCAPAnalysis, analysis_id)
    if not target_analysis:
        flash("Target PCAP analysis record not found.", "warning")
        return redirect(url_for("baseline.index"))
    return render_template(
        "baseline.html",
        active_page="baseline",
        analyses=analyses,
        current_analysis=target_analysis
    )


@baseline_bp.route("/baseline/upload", methods=["POST"])
@login_required
def upload():
    if "pcap_file" not in request.files:
        flash("No capture file uploaded.", "warning")
        return redirect(url_for("baseline.index"))

    file = request.files["pcap_file"]
    if not file or file.filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("baseline.index"))

    original_filename = secure_filename(file.filename)
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else ""

    allowed_exts = current_app.config.get("ALLOWED_PCAP_EXTENSIONS", {"pcap", "pcapng"})
    if ext not in allowed_exts:
        flash(f"Invalid file extension '.{ext}'. Only {', '.join(allowed_exts)} are permitted.", "danger")
        return redirect(url_for("baseline.index"))

    # Generate unique stored filename to prevent collisions and overwrites
    unique_prefix = uuid.uuid4().hex[:12]
    stored_filename = f"{unique_prefix}_{original_filename}"
    pcap_dir = os.path.abspath(current_app.config["PCAP_FOLDER"])
    save_path = os.path.abspath(os.path.join(pcap_dir, stored_filename))

    # Defensive path traversal check
    if not save_path.startswith(pcap_dir + os.sep):
        flash("Security violation: Invalid upload file path detected.", "danger")
        return redirect(url_for("baseline.index"))

    try:
        file.save(save_path)
    except Exception as e:
        flash(f"Failed to save uploaded file: {str(e)}", "danger")
        return redirect(url_for("baseline.index"))

    # Validate file structure & magic bytes
    is_valid, err = validate_pcap_file_structure(save_path)
    if not is_valid:
        if os.path.exists(save_path):
            os.remove(save_path)
        flash(f"Upload rejected: {err}", "danger")
        return redirect(url_for("baseline.index"))

    # Perform analysis
    analysis_res = analyze_pcap_file(save_path)
    if not analysis_res.get("success"):
        if os.path.exists(save_path):
            os.remove(save_path)
        flash(f"PCAP Analysis failed: {analysis_res.get('error')}", "danger")
        return redirect(url_for("baseline.index"))

    # Save to SQLite
    try:
        pcap_record = PCAPAnalysis(
            filename=original_filename,
            stored_filename=stored_filename,
            original_filename=original_filename,
            data_source="REAL",
            total_packets=analysis_res["total_packets"],
            source_ips=json.dumps(analysis_res["source_ips"]),
            destination_ips=json.dumps(analysis_res["destination_ips"]),
            source_ports=json.dumps(analysis_res["source_ports"]),
            destination_ports=json.dumps(analysis_res["destination_ports"]),
            protocols=json.dumps(analysis_res["protocols"]),
            tcp_packets=analysis_res["tcp_packets"],
            udp_packets=analysis_res["udp_packets"],
            dns_packets=analysis_res["dns_packets"],
            http_packets=analysis_res["http_packets"],
            https_packets=analysis_res["https_packets"],
            packet_frequency=json.dumps(analysis_res["packet_frequency"]),
            analysis_time=analysis_res["analysis_time"]
        )
        db.session.add(pcap_record)
        db.session.commit()
        flash(f"PCAP '{original_filename}' uploaded & analyzed ({analysis_res['total_packets']} packets in {analysis_res['analysis_time']}s).", "success")
        return redirect(url_for("baseline.view_analysis", analysis_id=pcap_record.id))
    except Exception as e:
        db.session.rollback()
        flash(f"Database error while saving analysis record: {str(e)}", "danger")
        return redirect(url_for("baseline.index"))

