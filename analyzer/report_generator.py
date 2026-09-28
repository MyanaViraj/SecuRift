import os
import csv
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)


def generate_rules_csv(rules, output_path):
    """Exports custom Snort rules list to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "SID", "Action", "Protocol", "Source", "Direction", "Destination",
            "Message", "Severity", "Classification", "MITRE Technique", "Purpose", "Status", "Rule Text"
        ])
        for r in rules:
            writer.writerow([
                r.sid,
                r.action,
                r.protocol,
                f"{r.source_ip}:{r.source_port}",
                r.direction,
                f"{r.destination_ip}:{r.destination_port}",
                r.message,
                r.severity,
                r.classification,
                r.mitre_technique or "N/A",
                r.purpose or "N/A",
                "Enabled" if r.enabled else "Disabled",
                r.rule_text
            ])
    return output_path


def generate_coverage_csv(matrix_data, output_path):
    """Exports detection coverage matrix data to CSV."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Detection Name", "Rule ID (SID)", "Test Case ID", "Data Source", "Expected Result",
            "Actual Result", "Detection Status", "Severity", "MITRE Technique"
        ])
        for row in matrix_data:
            writer.writerow([
                row.get("detection", "N/A"),
                row.get("sid", "N/A"),
                row.get("test_id", "N/A"),
                row.get("data_source", "DEMO"),
                row.get("expected", "N/A"),
                row.get("actual", "N/A"),
                row.get("status", "N/A"),
                row.get("severity", "N/A"),
                row.get("mitre", "N/A")
            ])
    return output_path


def generate_performance_csv(perf_data, output_path):
    """Exports performance benchmarks to CSV with auditable data source and execution fields."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Rule SID", "Rule Message", "Packets Processed", "Alerts Generated",
            "Processing Time (s)", "Alerts per 1000 Pkts", "Throughput (pkts/s)",
            "Detection Rate (%)", "Status", "Measurement Type", "Data Source",
            "Snort Version", "Execution ID", "Target PCAP"
        ])
        for p in perf_data:
            dr = p.get("detection_rate")
            dr_str = f"{dr}%" if dr is not None and dr != 0.0 else ("0.0%" if dr == 0.0 else "N/A (Insufficient samples)")
            writer.writerow([
                p.get("sid", "N/A"),
                p.get("message", "N/A"),
                p.get("packets_processed", 0),
                p.get("alerts_generated", 0),
                p.get("processing_time", 0.0),
                p.get("alerts_per_1000_packets", 0.0),
                p.get("throughput", 0.0),
                dr_str,
                p.get("status", "N/A"),
                p.get("measurement_type", "REAL_SNORT"),
                p.get("data_source", "REAL"),
                p.get("snort_version", "N/A"),
                p.get("execution_id", "—"),
                p.get("pcap", "N/A")
            ])
    return output_path


def generate_rules_pdf(rules, output_path):
    """Generates Report 1: Custom Snort Rules Specification PDF using ReportLab."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        leading=14
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=12,
        spaceAfter=6
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10
    )
    code_cell_style = ParagraphStyle(
        "TableCodeCell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        fontName="Courier",
        textColor=colors.HexColor("#0F766E")
    )

    story = []

    # Header block
    story.append(Paragraph("SecuRift — Defensive Detection Engineering Platform", title_style))
    story.append(Paragraph(
        f"Custom Snort Detection Rules Specification | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=15))

    # Summary
    story.append(Paragraph(f"<b>Total Rules Documented:</b> {len(rules)}", styles["Normal"]))
    story.append(Spacer(1, 10))

    # Rules Table
    table_data = [
        [
            Paragraph("<b>SID</b>", cell_style),
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>MITRE</b>", cell_style),
            Paragraph("<b>Rule Message & Purpose</b>", cell_style),
            Paragraph("<b>Rule Syntax</b>", cell_style),
        ]
    ]

    for r in rules:
        msg_text = f"<b>{r.message}</b><br/><font color='#475569'>{r.purpose or 'N/A'}</font>"
        syntax_text = r.rule_text[:140] + ("..." if len(r.rule_text) > 140 else "")
        table_data.append([
            Paragraph(str(r.sid), cell_style),
            Paragraph(f"<font color='{'#DC2626' if r.severity in ['Critical', 'High'] else '#D97706'}'><b>{r.severity}</b></font>", cell_style),
            Paragraph(r.mitre_technique or "—", cell_style),
            Paragraph(msg_text, cell_style),
            Paragraph(syntax_text, code_cell_style),
        ])

    col_widths = [0.8 * inch, 0.8 * inch, 0.9 * inch, 2.5 * inch, 2.8 * inch]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(t)
    doc.build(story)
    return output_path


def generate_coverage_pdf(matrix_data, metrics, output_path):
    """Generates Report 2: Detection Coverage Matrix PDF using ReportLab."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        leading=14
    )
    cell_style = ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=8, leading=10)

    story = []

    story.append(Paragraph("SecuRift — Detection Coverage Matrix", title_style))
    story.append(Paragraph(
        f"Validation & MITRE ATT&CK Mapping Audit | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=15))

    # Metrics Summary Row
    sample_size = metrics.get("sample_size", 0)
    if sample_size > 0:
        dr = metrics.get("detection_rate", "N/A")
        dr_str = f"{dr}%" if dr != "N/A" else "N/A"
        fpr = metrics.get("false_positive_rate", "N/A")
        fpr_str = f"{fpr}%" if fpr != "N/A" else "N/A"
        summary_text = (
            f"<b>Evaluation Population:</b> {sample_size} validated test executions | "
            f"<b>Detection Rate:</b> <b>{dr_str}</b> | <b>FPR:</b> <b>{fpr_str}</b><br/>"
            f"<b>Confusion Matrix:</b> TP: <b>{metrics.get('true_positives', 0)}</b> | "
            f"FP: <b>{metrics.get('false_positives', 0)}</b> | FN: <b>{metrics.get('false_negatives', 0)}</b> | "
            f"TN: <b>{metrics.get('true_negatives', 0)}</b> | Unknown: <b>{metrics.get('unknown', 0)}</b>"
        )
    else:
        summary_text = "<b>Evaluation Population:</b> Insufficient validated samples."

    story.append(Paragraph(summary_text, styles["Normal"]))
    story.append(Spacer(1, 12))

    # Coverage Table
    table_data = [
        [
            Paragraph("<b>Detection / Test</b>", cell_style),
            Paragraph("<b>Rule SID</b>", cell_style),
            Paragraph("<b>Expected</b>", cell_style),
            Paragraph("<b>Actual</b>", cell_style),
            Paragraph("<b>Status</b>", cell_style),
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>MITRE Technique</b>", cell_style),
        ]
    ]

    for row in matrix_data:
        st = row.get("status", "PENDING")
        st_color = "#16A34A" if st == "PASS" else ("#DC2626" if st in ["FAIL", "NOT DETECTED"] else "#D97706")
        table_data.append([
            Paragraph(f"<b>{row.get('detection', 'N/A')}</b><br/><font color='#64748B'>{row.get('test_id', '')}</font>", cell_style),
            Paragraph(str(row.get("sid", "N/A")), cell_style),
            Paragraph(row.get("expected", "N/A"), cell_style),
            Paragraph(row.get("actual", "N/A"), cell_style),
            Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", cell_style),
            Paragraph(row.get("severity", "N/A"), cell_style),
            Paragraph(row.get("mitre", "N/A"), cell_style),
        ])

    col_widths = [2.0 * inch, 0.8 * inch, 0.9 * inch, 0.9 * inch, 1.1 * inch, 0.8 * inch, 1.3 * inch]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(t)
    doc.build(story)
    return output_path


def generate_performance_pdf(perf_data, output_path):
    """Generates Report 3: Performance Benchmark PDF using ReportLab with auditable data sources."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        leading=14
    )
    cell_style = ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=8, leading=10)

    story = []
    story.append(Paragraph("SecuRift — Snort Rule Performance Benchmarks", title_style))
    story.append(Paragraph(
        f"Throughput, Execution Time, and Noise Analysis | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=15))

    story.append(Paragraph(
        "<b>Benchmark Formula:</b> Alerts per 1000 Packets = (Total Alerts / Total Packets) × 1000<br/>"
        "<i>Note: Measurements reflect actual Snort executions or explicitly labeled demo simulation data.</i>",
        styles["Normal"]
    ))
    story.append(Spacer(1, 12))

    table_data = [
        [
            Paragraph("<b>Rule SID</b>", cell_style),
            Paragraph("<b>Rule Message</b>", cell_style),
            Paragraph("<b>Packets</b>", cell_style),
            Paragraph("<b>Alerts</b>", cell_style),
            Paragraph("<b>Time (s)</b>", cell_style),
            Paragraph("<b>Alerts / 1k</b>", cell_style),
            Paragraph("<b>Detection %</b>", cell_style),
            Paragraph("<b>Data Source</b>", cell_style),
            Paragraph("<b>Status</b>", cell_style),
        ]
    ]

    for p in perf_data:
        st = p.get("status", "Optimal")
        st_color = "#16A34A" if st == "Optimal" else ("#DC2626" if st == "Resource-Heavy" else "#D97706")
        dr = p.get("detection_rate")
        dr_str = f"{dr}%" if dr is not None and dr != 0.0 else ("0.0%" if dr == 0.0 else "N/A")
        src = p.get("data_source", "REAL")
        src_color = "#16A34A" if src == "REAL" or src == "REAL_SNORT" else ("#0284C7" if "IMPORTED" in src else "#D97706")

        table_data.append([
            Paragraph(str(p.get("sid", "N/A")), cell_style),
            Paragraph(p.get("message", "N/A")[:30], cell_style),
            Paragraph(str(p.get("packets_processed", 0)), cell_style),
            Paragraph(str(p.get("alerts_generated", 0)), cell_style),
            Paragraph(f"{float(p.get('processing_time', 0.0)):.4f}", cell_style),
            Paragraph(str(p.get("alerts_per_1000_packets", 0.0)), cell_style),
            Paragraph(dr_str, cell_style),
            Paragraph(f"<font color='{src_color}'><b>{src}</b></font>", cell_style),
            Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", cell_style),
        ])

    col_widths = [0.7 * inch, 1.8 * inch, 0.7 * inch, 0.6 * inch, 0.7 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(t)
    doc.build(story)
    return output_path
