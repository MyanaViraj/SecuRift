"""
Detection Metrics & Statistical Formulas for SecuRift
Calculates detection accuracy, false positive rates, recall, precision, and F1-score.
Strictly requires that all confusion matrix metrics derive from the SAME evaluation population.
"""


def safe_div(numerator, denominator, multiplier=100.0, default="N/A"):
    """
    Safely performs division and returns percentage.
    If denominator is 0, returns 'N/A' (or specified default) rather than a misleading 0%.
    """
    try:
        if denominator == 0:
            return default
        return round((float(numerator) / float(denominator)) * multiplier, 2)
    except Exception:
        return default


def classify_detection_outcome(expected_detection, actual_detection):
    """
    Classifies a single test evaluation into standard confusion matrix outcomes:
    - TP: Expected alert AND alert actually generated.
    - FN: Expected alert BUT no alert generated (missed detection).
    - TN: Expected no alert AND no alert generated (benign pass).
    - FP: Expected no alert BUT alert generated (spurious trigger).
    - UNKNOWN: Insufficient evidence or untested.
    """
    exp = (expected_detection or "").strip().lower()
    act = (actual_detection or "").strip().lower()

    if act in ("untested", "unknown", "", "pending"):
        return "UNKNOWN"

    is_exp_alert = exp in ("alert", "true", "yes", "1")
    is_act_alert = act in ("alert", "true", "yes", "1")

    if is_exp_alert and is_act_alert:
        return "TP"
    elif is_exp_alert and not is_act_alert:
        return "FN"
    elif not is_exp_alert and not is_act_alert:
        return "TN"
    elif not is_exp_alert and is_act_alert:
        return "FP"
    else:
        return "UNKNOWN"


def compute_metrics(true_positives, false_positives, false_negatives, true_negatives, unknown_count=0):
    """
    Computes comprehensive detection engineering metrics based on confusion matrix parameters:
    - TP: True Positives (Attack traffic correctly alerted)
    - FP: False Positives (Benign traffic erroneously alerted)
    - FN: False Negatives (Attack traffic missed)
    - TN: True Negatives (Benign traffic correctly not alerted)
    - Unknown: Unreviewed or indeterminate cases

    All parameters must be from the SAME unified evaluation population.
    """
    tp = max(0, int(true_positives))
    fp = max(0, int(false_positives))
    fn = max(0, int(false_negatives))
    tn = max(0, int(true_negatives))
    unknown = max(0, int(unknown_count))

    total_evaluated = tp + fp + fn + tn
    sample_size = total_evaluated + unknown
    total_alerts = tp + fp
    total_attacks = tp + fn
    total_benign = fp + tn

    # Detection Rate (Recall / Sensitivity) = TP / (TP + FN) * 100
    detection_rate = safe_div(tp, total_attacks)

    # False Positive Rate (Fall-out) = FP / (FP + TN) * 100
    false_positive_rate = safe_div(fp, total_benign)

    # Precision (Positive Predictive Value) = TP / (TP + FP) * 100
    precision = safe_div(tp, total_alerts)

    # Accuracy = (TP + TN) / (TP + TN + FP + FN) * 100
    accuracy = safe_div(tp + tn, total_evaluated)

    # F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
    f1_score = "N/A"
    if isinstance(precision, (int, float)) and isinstance(detection_rate, (int, float)):
        if precision + detection_rate > 0:
            f1_score = round(
                2 * (precision * detection_rate) / (precision + detection_rate), 2
            )
        else:
            f1_score = 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "unknown": unknown,
        "sample_size": sample_size,
        "total_evaluated": total_evaluated,
        "total_alerts": total_alerts,
        "detection_rate": detection_rate,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "accuracy": accuracy,
        "f1_score": f1_score,
        "formulas": {
            "detection_rate": "Detection Rate (Recall) = [TP / (TP + FN)] × 100",
            "false_positive_rate": "False Positive Rate = [FP / (FP + TN)] × 100",
            "precision": "Precision = [TP / (TP + FP)] × 100",
            "accuracy": "Accuracy = [(TP + TN) / (TP + TN + FP + FN)] × 100",
            "f1_score": "F1-Score = 2 × [(Precision × Recall) / (Precision + Recall)]"
        }
    }


def compute_metrics_from_evaluations(evaluation_records):
    """
    Computes confusion matrix metrics from an iterable of DetectionEvaluation records.
    Guarantees population coherence.
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    unknown = 0

    for ev in evaluation_records:
        cls = (getattr(ev, "classification", None) or "").upper()
        if cls == "TP":
            tp += 1
        elif cls == "FP":
            fp += 1
        elif cls == "TN":
            tn += 1
        elif cls == "FN":
            fn += 1
        else:
            unknown += 1

    return compute_metrics(tp, fp, fn, tn, unknown)


def evaluate_test_case_result(expected_detection, actual_detection):
    """
    Evaluates test case outcome:
    - PASS: (Expected Alert and got Alert) OR (Expected No Alert and got No Alert)
    - FAIL: Generic mismatch
    - NOT DETECTED: Expected Alert but got No Alert (FN)
    - UNEXPECTED ALERT: Expected No Alert but got Alert (FP)
    """
    exp = (expected_detection or "").strip().lower()
    act = (actual_detection or "").strip().lower()

    if act in ("untested", "unknown", "", "pending"):
        return "PENDING"

    is_exp = exp in ("alert", "true", "yes", "1")
    is_act = act in ("alert", "true", "yes", "1")

    if is_exp and is_act:
        return "PASS"
    elif not is_exp and not is_act:
        return "PASS"
    elif is_exp and not is_act:
        return "NOT DETECTED"
    elif not is_exp and is_act:
        return "UNEXPECTED ALERT"
    else:
        return "FAIL"
