from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from models.models import Alert, FalsePositiveRecord, Rule, TestCase, DetectionEvaluation
from models import db
from analyzer.detection_metrics import compute_metrics_from_evaluations, safe_div

false_positives_bp = Blueprint("false_positives", __name__)


@false_positives_bp.route("/false-positives", methods=["GET"])
@login_required
def index():
    alerts = Alert.query.order_by(Alert.id.desc()).all()

    # Honest alert triage counts: never infer TP for unreviewed alerts
    total_alerts = len(alerts)
    reviewed_tp = FalsePositiveRecord.query.filter_by(classification="True Positive").count()
    reviewed_fp = FalsePositiveRecord.query.filter_by(classification="False Positive").count()
    reviewed_alerts = reviewed_tp + reviewed_fp
    unknown_alerts = max(0, total_alerts - reviewed_alerts)

    # Compute controlled evaluation metrics from unified DetectionEvaluation records
    evals = DetectionEvaluation.query.all()
    metrics = compute_metrics_from_evaluations(evals)

    # Compute Rule-Wise Noise / FP breakdown strictly based on explicit operator triage
    rule_stats = []
    rules = Rule.query.all()
    for r in rules:
        r_alerts = Alert.query.filter_by(sid=r.sid).all()
        if r_alerts:
            r_tp = 0
            r_fp = 0
            r_unknown = 0
            for a in r_alerts:
                state = a.classification_state
                if state == "True Positive":
                    r_tp += 1
                elif state == "False Positive":
                    r_fp += 1
                else:
                    r_unknown += 1

            # FP rate within reviewed alerts for this rule
            reviewed_r = r_tp + r_fp
            r_fp_rate = safe_div(r_fp, reviewed_r) if reviewed_r > 0 else "N/A"
            rule_stats.append({
                "sid": r.sid,
                "message": r.message,
                "alerts": len(r_alerts),
                "tp": r_tp,
                "fp": r_fp,
                "unknown": r_unknown,
                "fp_rate": r_fp_rate
            })

    triage_summary = {
        "total_alerts": total_alerts,
        "reviewed_alerts": reviewed_alerts,
        "unknown_alerts": unknown_alerts,
        "true_positives": reviewed_tp,
        "false_positives": reviewed_fp
    }

    return render_template(
        "false_positives.html",
        active_page="false_positives",
        alerts=alerts,
        metrics=metrics,
        triage_summary=triage_summary,
        rule_stats=rule_stats
    )


@false_positives_bp.route("/false-positives/api/classify/<int:alert_id>", methods=["POST"])
@login_required
def api_classify(alert_id):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"success": False, "error": "Alert not found."}), 404

    data = request.get_json(silent=True) or {}
    new_class = data.get("classification", "Unknown").strip()

    if new_class not in ["True Positive", "False Positive", "Unknown"]:
        return jsonify({"success": False, "error": "Invalid classification option."}), 400

    reviewer = current_user.username if current_user.is_authenticated else "Operator"

    fp_record = FalsePositiveRecord.query.filter_by(alert_id=alert.id).first()
    if not fp_record:
        fp_record = FalsePositiveRecord(
            alert_id=alert.id,
            classification=new_class,
            notes=f"Classified by {reviewer} via SOC triage console",
            reviewed_at=datetime.now(timezone.utc)
        )
        db.session.add(fp_record)
    else:
        fp_record.classification = new_class
        fp_record.notes = f"Updated by {reviewer} via SOC triage console"
        fp_record.reviewed_at = datetime.now(timezone.utc)

    db.session.commit()

    # Recalculate metrics strictly from DetectionEvaluations
    evals = DetectionEvaluation.query.all()
    metrics = compute_metrics_from_evaluations(evals)

    # Return refreshed triage counts
    total_alerts = Alert.query.count()
    tp_count = FalsePositiveRecord.query.filter_by(classification="True Positive").count()
    fp_count = FalsePositiveRecord.query.filter_by(classification="False Positive").count()
    reviewed_count = tp_count + fp_count
    unknown_count = max(0, total_alerts - reviewed_count)

    return jsonify({
        "success": True,
        "classification": new_class,
        "metrics": metrics,
        "triage": {
            "total_alerts": total_alerts,
            "reviewed_alerts": reviewed_count,
            "unknown_alerts": unknown_count,
            "true_positives": tp_count,
            "false_positives": fp_count
        }
    })

