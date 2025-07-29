import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT

INPUT_JSON = "output/results.json"
OUTPUT_PDF = "output/cve-report.pdf"
NEW_IDS_PATH = "new_ids.txt"

# Ensure output folder exists
os.makedirs("output", exist_ok=True)

# Load JSON data
with open(INPUT_JSON, "r") as f:
    data = json.load(f)

# Load new CVE IDs
new_ids = set()
if os.path.exists(NEW_IDS_PATH):
    with open(NEW_IDS_PATH, "r") as f:
        new_ids = set(line.strip() for line in f)

# ReportLab styles
styles = getSampleStyleSheet()
wrap_style = ParagraphStyle(
    name='Wrap',
    fontSize=7,
    leading=9,
    alignment=TA_LEFT,
)

def format_row(entry):
    return [
        Paragraph(entry.get("sdk", "N/A"), wrap_style),
        Paragraph(entry.get("id", "N/A"), wrap_style),
        Paragraph(entry.get("severity", "N/A"), wrap_style),
        Paragraph(str(entry.get("cvss", "N/A")), wrap_style),
        Paragraph(entry.get("cwe", "N/A"), wrap_style),
        Paragraph(entry.get("published", "N/A").split("T")[0], wrap_style),
        Paragraph(entry.get("description", "N/A"), wrap_style),
        Paragraph(entry.get("reference", "N/A"), wrap_style),
    ]

# Separate new vs existing
new_cves = []
existing_cves = []
for entry in data["results"]:
    row = format_row(entry)
    severity = entry.get("severity", "").upper()
    style = []
    if severity in {"HIGH", "CRITICAL"}:
        style = [('BACKGROUND', (0, 0), (-1, 0), colors.red), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]
    if entry["id"] in new_ids:
        new_cves.append((row, style))
    else:
        existing_cves.append((row, style))

# Build PDF
story = []

def add_table(title, entries):
    if not entries:
        return
    story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    header = [
        Paragraph(h, wrap_style) for h in
        ["SDK", "CVE ID", "Severity", "CVSS", "CWE", "Published", "Description", "Reference"]
    ]
    data = [header] + [e[0] for e in entries]

    col_widths = [60, 70, 45, 35, 60, 55, 180, 160]
    table = Table(data, colWidths=col_widths, repeatRows=1)

    base_style = [
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]
    # Apply row highlighting
    for idx, (_, row_style) in enumerate(entries, start=1):  # +1 for header row
        if row_style:
            base_style.extend([
                ('BACKGROUND', (0, idx), (-1, idx), colors.whitesmoke),
                ('TEXTCOLOR', (0, idx), (-1, idx), colors.red),
            ])
    table.setStyle(TableStyle(base_style))
    story.append(table)
    story.append(Spacer(1, 20))

doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=A4, leftMargin=10, rightMargin=10, topMargin=20, bottomMargin=20)
add_table("🚨 New CVEs", new_cves)
add_table("📋 Existing CVEs", existing_cves)
doc.build(story)

print(f"✅ PDF report generated at: {OUTPUT_PDF}")
