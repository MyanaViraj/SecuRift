import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, Response, current_app
from flask_login import login_required
from models.models import Rule
from models import db
from analyzer.rule_validator import validate_snort_rule, parse_snort_rule_text
from routes.auth import role_required

rules_bp = Blueprint("rules", __name__)


@rules_bp.route("/rules", methods=["GET"])
@login_required
def index():
    proto_filter = request.args.get("protocol", "").strip().lower()
    sev_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip().lower()
    q = request.args.get("q", "").strip()

    query = Rule.query

    if proto_filter:
        query = query.filter_by(protocol=proto_filter)
    if sev_filter:
        query = query.filter_by(severity=sev_filter)
    if status_filter == "enabled":
        query = query.filter_by(enabled=True)
    elif status_filter == "disabled":
        query = query.filter_by(enabled=False)

    if q:
        query = query.filter(
            (Rule.message.ilike(f"%{q}%")) |
            (Rule.rule_text.ilike(f"%{q}%")) |
            (Rule.classification.ilike(f"%{q}%"))
        )

    rules = query.order_by(Rule.sid.asc()).all()
    return render_template("rules.html", active_page="rules", rules=rules)


@rules_bp.route("/rules/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        rule_text = request.form.get("rule_text", "").strip()
        val_res = validate_snort_rule(rule_text)

        if not val_res["is_valid"]:
            error_str = " | ".join(val_res["errors"])
            flash(f"Rule syntax error: {error_str}", "danger")
            return render_template("rule_form.html", active_page="rules", rule=None, next_sid=1000001)

        sid = int(request.form.get("sid", 1000001))
        # Check duplicate SID
        if Rule.query.filter_by(sid=sid).first():
            flash(f"A rule with SID {sid} already exists. Please choose a unique SID.", "warning")
            return render_template("rule_form.html", active_page="rules", rule=None, next_sid=sid + 1)

        action = request.form.get("action", "alert").strip().lower()
        protocol = request.form.get("protocol", "tcp").strip().lower()
        source_ip = request.form.get("source_ip", "any").strip()
        source_port = request.form.get("source_port", "any").strip()
        direction = request.form.get("direction", "->").strip()
        destination_ip = request.form.get("destination_ip", "any").strip()
        destination_port = request.form.get("destination_port", "any").strip()
        message = request.form.get("message", "SecuRift Detection").strip()
        revision = int(request.form.get("revision", 1))
        classification = request.form.get("classification", "attempted-admin").strip()
        severity = request.form.get("severity", "Medium").strip()
        enabled = bool(request.form.get("enabled"))
        purpose = request.form.get("purpose", "").strip()
        trigger_condition = request.form.get("trigger_condition", "").strip()
        expected_behavior = request.form.get("expected_behavior", "").strip()
        mitre_technique = request.form.get("mitre_technique", "").strip().upper()

        new_rule = Rule(
            sid=sid,
            rule_text=rule_text,
            action=action,
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            direction=direction,
            destination_ip=destination_ip,
            destination_port=destination_port,
            message=message,
            revision=revision,
            classification=classification,
            severity=severity,
            enabled=enabled,
            purpose=purpose,
            trigger_condition=trigger_condition,
            expected_behavior=expected_behavior,
            mitre_technique=mitre_technique
        )

        try:
            db.session.add(new_rule)
            db.session.commit()
            flash(f"Snort Rule SID {sid} created and registered successfully ({val_res['mode']}).", "success")
            return redirect(url_for("rules.index"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error registering rule: {str(e)}", "danger")

    # Suggested next SID
    max_rule = Rule.query.order_by(Rule.sid.desc()).first()
    next_sid = (max_rule.sid + 1) if max_rule else 1000001
    return render_template("rule_form.html", active_page="rules", rule=None, next_sid=next_sid)


@rules_bp.route("/rules/edit/<int:rule_id>", methods=["GET", "POST"])
@login_required
def edit(rule_id):
    rule = Rule.query.get_or_404(rule_id)

    if request.method == "POST":
        rule_text = request.form.get("rule_text", "").strip()
        val_res = validate_snort_rule(rule_text)

        if not val_res["is_valid"]:
            flash(f"Rule syntax invalid: {' | '.join(val_res['errors'])}", "danger")
            return render_template("rule_form.html", active_page="rules", rule=rule)

        new_sid = int(request.form.get("sid", rule.sid))
        # If SID changed, ensure unique
        if new_sid != rule.sid and Rule.query.filter_by(sid=new_sid).first():
            flash(f"SID {new_sid} is already assigned to another rule.", "warning")
            return render_template("rule_form.html", active_page="rules", rule=rule)

        rule.sid = new_sid
        rule.rule_text = rule_text
        rule.action = request.form.get("action", rule.action).strip().lower()
        rule.protocol = request.form.get("protocol", rule.protocol).strip().lower()
        rule.source_ip = request.form.get("source_ip", rule.source_ip).strip()
        rule.source_port = request.form.get("source_port", rule.source_port).strip()
        rule.direction = request.form.get("direction", rule.direction).strip()
        rule.destination_ip = request.form.get("destination_ip", rule.destination_ip).strip()
        rule.destination_port = request.form.get("destination_port", rule.destination_port).strip()
        rule.message = request.form.get("message", rule.message).strip()
        rule.revision = int(request.form.get("revision", rule.revision))
        rule.classification = request.form.get("classification", rule.classification).strip()
        rule.severity = request.form.get("severity", rule.severity).strip()
        rule.enabled = bool(request.form.get("enabled"))
        rule.purpose = request.form.get("purpose", rule.purpose).strip()
        rule.trigger_condition = request.form.get("trigger_condition", rule.trigger_condition).strip()
        rule.expected_behavior = request.form.get("expected_behavior", rule.expected_behavior).strip()
        rule.mitre_technique = request.form.get("mitre_technique", rule.mitre_technique).strip().upper()

        try:
            db.session.commit()
            flash(f"Snort Rule SID {rule.sid} updated successfully.", "success")
            return redirect(url_for("rules.index"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error updating rule: {str(e)}", "danger")

    return render_template("rule_form.html", active_page="rules", rule=rule)


@rules_bp.route("/rules/delete/<int:rule_id>", methods=["POST"])
@role_required("Administrator")
def delete(rule_id):
    rule = db.session.get(Rule, rule_id)
    if not rule:
        flash("Rule not found.", "warning")
        return redirect(url_for("rules.index"))
    sid = rule.sid
    try:
        db.session.delete(rule)
        db.session.commit()
        flash(f"Snort Rule SID {sid} deleted.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting rule: {str(e)}", "danger")

    return redirect(url_for("rules.index"))


@rules_bp.route("/rules/toggle/<int:rule_id>", methods=["POST"])
@login_required
def toggle(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    flash(f"Rule SID {rule.sid} {'enabled' if rule.enabled else 'disabled'}.", "success")
    return redirect(url_for("rules.index"))


@rules_bp.route("/rules/detail/<int:rule_id>", methods=["GET"])
@login_required
def detail(rule_id):
    return redirect(url_for("detection_logic.index", rule_id=rule_id))


@rules_bp.route("/rules/export", methods=["GET"])
@login_required
def export_rules_file():
    """Generates standard Snort rules file format."""
    rules = Rule.query.filter_by(enabled=True).order_by(Rule.sid.asc()).all()
    content = [
        "# ============================================================",
        "# SecuRift Defensive Snort Detection Rules Export",
        "# Advanced Network Defence and Security Architecture",
        "# ============================================================\n"
    ]
    for r in rules:
        content.append(f"# SID: {r.sid} | Severity: {r.severity} | MITRE: {r.mitre_technique or 'N/A'}")
        content.append(r.rule_text)
        content.append("")

    rules_data = "\n".join(content)
    return Response(
        rules_data,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=securift_custom.rules"}
    )


@rules_bp.route("/rules/api/validate", methods=["POST"])
@login_required
def api_validate():
    """Live syntax checker endpoint for async validation."""
    data = request.get_json(silent=True) or {}
    rule_text = data.get("rule_text", "")
    res = validate_snort_rule(rule_text)
    return jsonify(res)
