from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from models.models import MitreMapping, Rule
from models import db
from analyzer.mitre_mapping import MITRE_TECHNIQUES_CATALOG

mitre_bp = Blueprint("mitre", __name__)


@mitre_bp.route("/mitre", methods=["GET"])
@login_required
def index():
    mappings = MitreMapping.query.order_by(MitreMapping.id.asc()).all()
    available_rules = Rule.query.order_by(Rule.sid.asc()).all()
    return render_template(
        "mitre.html",
        active_page="mitre",
        mappings=mappings,
        available_rules=available_rules,
        catalog=MITRE_TECHNIQUES_CATALOG
    )


@mitre_bp.route("/mitre/create", methods=["POST"])
@login_required
def create():
    technique_id = request.form.get("technique_id", "").strip().upper()
    technique_name = request.form.get("technique_name", "").strip()
    tactic = request.form.get("tactic", "Discovery").strip()
    rule_id_raw = request.form.get("rule_id", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    validation_status = request.form.get("validation_status", "Validated").strip()
    detection_logic = request.form.get("detection_logic", "").strip()

    if not rule_id_raw or not rule_id_raw.isdigit():
        flash("Please associate this MITRE technique with a valid Snort rule.", "warning")
        return redirect(url_for("mitre.index"))

    rule_id = int(rule_id_raw)

    # Ensure detection engineering philosophy phrasing
    standard_prefix = "Detection mapping based on the documented detection logic:"
    if not detection_logic.startswith("Detection mapping based"):
        detection_logic = f"{standard_prefix} {detection_logic}"

    mapping = MitreMapping(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        rule_id=rule_id,
        detection_logic=detection_logic,
        severity=severity,
        validation_status=validation_status
    )

    try:
        db.session.add(mapping)
        # Also update rule's mitre_technique field if empty
        r = db.session.get(Rule, rule_id)
        if r and not r.mitre_technique:
            r.mitre_technique = technique_id
        db.session.commit()
        flash(f"MITRE ATT&CK mapping '{technique_id} — {technique_name}' registered.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error registering MITRE mapping: {str(e)}", "danger")

    return redirect(url_for("mitre.index"))


@mitre_bp.route("/mitre/edit/<int:mapping_id>", methods=["POST"])
@login_required
def edit(mapping_id):
    mapping = MitreMapping.query.get_or_404(mapping_id)

    mapping.technique_id = request.form.get("technique_id", mapping.technique_id).strip().upper()
    mapping.technique_name = request.form.get("technique_name", mapping.technique_name).strip()
    mapping.tactic = request.form.get("tactic", mapping.tactic).strip()
    mapping.severity = request.form.get("severity", mapping.severity).strip()
    mapping.validation_status = request.form.get("validation_status", mapping.validation_status).strip()

    rule_id_raw = request.form.get("rule_id", "").strip()
    if rule_id_raw and rule_id_raw.isdigit():
        mapping.rule_id = int(rule_id_raw)

    logic = request.form.get("detection_logic", mapping.detection_logic).strip()
    if not logic.startswith("Detection mapping based"):
        logic = f"Detection mapping based on the documented detection logic: {logic}"
    mapping.detection_logic = logic

    try:
        db.session.commit()
        flash(f"MITRE mapping '{mapping.technique_id}' updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating MITRE mapping: {str(e)}", "danger")

    return redirect(url_for("mitre.index"))


@mitre_bp.route("/mitre/delete/<int:mapping_id>", methods=["POST"])
@login_required
def delete(mapping_id):
    mapping = MitreMapping.query.get_or_404(mapping_id)
    tid = mapping.technique_id
    try:
        db.session.delete(mapping)
        db.session.commit()
        flash(f"MITRE mapping '{tid}' removed.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting mapping: {str(e)}", "danger")

    return redirect(url_for("mitre.index"))
