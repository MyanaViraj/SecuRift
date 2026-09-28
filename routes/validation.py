from datetime import datetime, timezone
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models.models import ValidationResult, TestCase, Rule, Alert, DetectionEvaluation, TestExecution
from models import db
from analyzer.detection_metrics import compute_metrics_from_evaluations
from routes.test_cases import evaluate_test_case_lineage

validation_bp = Blueprint("validation", __name__)


@validation_bp.route("/validation", methods=["GET"])
@login_required
def index():
    results = ValidationResult.query.order_by(ValidationResult.id.desc()).all()
    evals = DetectionEvaluation.query.all()

    # Calculate confusion matrix metrics strictly from the unified DetectionEvaluation population
    metrics = compute_metrics_from_evaluations(evals)

    return render_template(
        "validation.html",
        active_page="validation",
        results=results,
        evaluations=evals,
        metrics=metrics,
        population_size=len(evals)
    )


@validation_bp.route("/validation/run", methods=["POST"])
@login_required
def run_validation():
    test_cases = TestCase.query.all()
    count = 0
    reviewer_name = current_user.username if current_user.is_authenticated else "Operator"

    for tc in test_cases:
        evaluate_test_case_lineage(tc, reviewer_name=reviewer_name)
        count += 1

    db.session.commit()
    flash(f"Systematic validation completed across {count} test vectors with auditable data lineage.", "success")
    return redirect(url_for("validation.index"))

