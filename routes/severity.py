from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from models.models import Rule, Alert
from models import db

severity_bp = Blueprint("severity", __name__)


@severity_bp.route("/severity", methods=["GET"])
@login_required
def index():
    rules = Rule.query.order_by(Rule.sid.asc()).all()

    # Severity distribution across all alerts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    alert_counts_per_sid = {}

    for a in Alert.query.all():
        sev = a.severity or "Medium"
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Medium"] += 1

        alert_counts_per_sid[a.sid] = alert_counts_per_sid.get(a.sid, 0) + 1

    return render_template(
        "severity.html",
        active_page="severity",
        counts=counts,
        rules=rules,
        alert_counts=alert_counts_per_sid
    )


@severity_bp.route("/severity/update-rule/<int:rule_id>", methods=["POST"])
@login_required
def update_rule_severity(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    new_sev = request.form.get("severity", "").strip()

    if new_sev in ["Critical", "High", "Medium", "Low"]:
        rule.severity = new_sev
        db.session.commit()
        flash(f"Severity for Rule SID {rule.sid} updated to {new_sev}.", "success")
    else:
        flash("Invalid severity level specified.", "warning")

    return redirect(url_for("severity.index"))
