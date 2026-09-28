from flask import Blueprint, render_template, request
from flask_login import login_required
from models.models import Rule
from models import db

detection_logic_bp = Blueprint("detection_logic", __name__)


@detection_logic_bp.route("/detection-logic", methods=["GET"])
@login_required
def index():
    rule_id_raw = request.args.get("rule_id", "").strip()
    all_rules = Rule.query.order_by(Rule.sid.asc()).all()

    selected_rule = None
    if rule_id_raw and rule_id_raw.isdigit():
        selected_rule = db.session.get(Rule, int(rule_id_raw))

    if selected_rule:
        displayed_rules = [selected_rule]
    else:
        displayed_rules = all_rules

    return render_template(
        "detection_logic.html",
        active_page="detection_logic",
        all_rules=all_rules,
        selected_rule=selected_rule,
        displayed_rules=displayed_rules
    )
