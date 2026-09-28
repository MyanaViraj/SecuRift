import pytest
from analyzer.detection_metrics import compute_metrics, safe_div, evaluate_test_case_result
from analyzer.performance_analyzer import calculate_performance_metrics


def test_safe_div_zero_division():
    assert safe_div(10, 0) == "N/A"
    assert safe_div(0, 0) == "N/A"
    assert safe_div(10, 0, default=0.0) == 0.0
    assert safe_div(5, 10) == 50.0


def test_detection_metrics_calculations():
    # TP=80, FP=10, FN=20, TN=90
    m = compute_metrics(true_positives=80, false_positives=10, false_negatives=20, true_negatives=90)

    # Detection Rate = TP / (TP + FN) = 80 / 100 = 80.0%
    assert m["detection_rate"] == 80.0

    # FP Rate = FP / (FP + TN) = 10 / 100 = 10.0%
    assert m["false_positive_rate"] == 10.0

    # Precision = TP / (TP + FP) = 80 / 90 = 88.89%
    assert round(m["precision"], 1) == 88.9

    # Accuracy = (TP + TN) / Total = 170 / 200 = 85.0%
    assert m["accuracy"] == 85.0

    # F1-Score > 0
    assert m["f1_score"] > 80.0


def test_evaluate_test_case_result_mapping():
    assert evaluate_test_case_result("Alert", "Alert") == "PASS"
    assert evaluate_test_case_result("No Alert", "No Alert") == "PASS"
    assert evaluate_test_case_result("Alert", "No Alert") == "NOT DETECTED"
    assert evaluate_test_case_result("No Alert", "Alert") == "UNEXPECTED ALERT"
    assert evaluate_test_case_result("Alert", "Untested") == "PENDING"


def test_performance_analyzer_metrics():
    perf = calculate_performance_metrics(packets_processed=10000, alerts_generated=20, processing_time=0.5)
    # alerts_per_1000 = (20 / 10000) * 1000 = 2.0
    assert perf["alerts_per_1000_packets"] == 2.0
    assert perf["status"] == "Optimal"
    assert perf["packets_per_second"] == 20000.0

    noisy_perf = calculate_performance_metrics(packets_processed=1000, alerts_generated=300, processing_time=1.0)
    # alerts_per_1000 = 300.0 -> Resource-Heavy
    assert noisy_perf["alerts_per_1000_packets"] == 300.0
    assert noisy_perf["status"] == "Resource-Heavy"
