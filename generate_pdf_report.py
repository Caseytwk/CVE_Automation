import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

INPUT_JSON = "output/results.json"
NEW_IDS_FILE = "new_ids.txt"
OUTPUT_PDF = "output/cve_report.pdf"

with open(INPUT_JSON, "r") as f:
    data = json.load(f)

new_ids = set()
if os.path.exists(NEW_IDS_FILE):
    with open(NEW_IDS_FILE) as f:
        new_ids = set(line.strip() for line in f if line.strip())

results = data["results"]
styles = getSampleStyleSheet()
story = []

def make_table(cves, title):
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Spacer(1, 12))

    table_data = [[
        "CVE ID", "SDK", "Severity", "CVSS", "CWE", "Description", "Reference"
    ]]
    
    for entry in cves:
        row = [
            Paragraph(entry.get("id", ""), styles["Normal"]),
            Paragraph(entry.get("sdk", ""), styles["Normal"]),
            Paragraph(entry.get("severity", ""), styles["Normal"]),
            Paragraph(str(entry.get("cvss", "")), styles["Normal"]),
            Paragraph(entry.get("cwe", ""), styles["Normal"]),
            Paragraph(entry.get("description", ""), styles["Normal"]),
            Paragraph(f'<a href="{entry.get("reference", "")}">{entry.get("reference", "")}</a>', styles["Normal"])
        ]
        table_data.append(row)

    t = Table(table_data, repeatRows=1, colWidths=[
        65,   # CVE ID
        75,   # SDK
        55,   # Severity
        35,   # CVSS
        55,   # CWE
        200,  # Description
        130   # Reference
    ])
    
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F81BD")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    
    story.append(t)
    story.append(Spacer(1, 24))


new_cves = [entry for entry in results if entry["id"] in new_ids]
existing_cves = [entry for entry in results if entry["id"] not in new_ids]

doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=A4)
if new_cves:
    make_table(new_cves, "🔔 New CVEs Detected")
if existing_cves:
    make_table(existing_cves, "Existing CVEs")

doc.build(story)
print(f"PDF report generated: {OUTPUT_PDF}")
