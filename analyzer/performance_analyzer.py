"""
Rule Performance & Benchmarking Analyzer for SecuRift
Calculates packet throughput, alerts per 1000 packets, processing times, and efficiency ratings.
"""


def calculate_performance_metrics(packets_processed, alerts_generated, processing_time):
    """
    Computes performance benchmarks:
    - alerts_per_1000_packets = (alerts / packets) * 1000
    - processing_time (measured in seconds)
    - status classification: Optimal, Warning, or Resource-Heavy
    """
    packets = max(0, int(packets_processed))
    alerts = max(0, int(alerts_generated))
    time_taken = max(0.0001, float(processing_time))

    if packets > 0:
        alerts_per_1k = round((float(alerts) / float(packets)) * 1000.0, 2)
        pkts_per_sec = round(float(packets) / time_taken, 2)
    else:
        alerts_per_1k = 0.0
        pkts_per_sec = 0.0

    # Determine status rating
    # Highly noisy rules triggering on every packet degrade IDS performance
    if alerts_per_1k > 200:
        status = "Resource-Heavy"
    elif alerts_per_1k > 50:
        status = "Warning"
    else:
        status = "Optimal"

    return {
        "packets_processed": packets,
        "alerts_generated": alerts,
        "processing_time": round(time_taken, 4),
        "alerts_per_1000_packets": alerts_per_1k,
        "packets_per_second": pkts_per_sec,
        "status": status,
        "formula": "Alerts per 1000 Packets = (Total Alerts / Total Packets) × 1000"
    }
