import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

INPUT_JSON = "output/results.json"
OUTPUT_PDF = "output/cve-report.pdf"

# Ensure output folder exists
os.makedirs("output", exist_ok=True)

# Load JSON data
with open(INPUT_JSON, "r") as f:
    data = json.load(f)

# Mark new CVEs if a file exists
new_ids_path = "new_ids.txt"
new_ids = set()
if os.path.exists(new_ids_path):
    with open(new_ids_path, "r") as f:
        new_ids = set(line.strip() for line in f)

# Separate into new and existing CVEs
new_cves = []
existing_cves = []

for entry in data["results"]:
    row = [
        entry.get("sdk", "N/A"),
        entry.get("id", "N/A"),
        entry.get("severity", "N/A"),
        str(entry.get("cvss", "N/A")),
        entry.get("cwe", "N/A"),
        entry.get("published", "N/A").split("T")[0],
        entry.get("description", "")[:100] + "...",  # shorten
        entry.get("reference", "N/A")
    ]
    if entry["id"] in new_ids:
        new_cves.append(row)
    else:
        existing_cves.append(row)

# PDF Styles
styles = getSampleStyleSheet()
story = []

def add_table(title, rows):
    if not rows:
        return
    story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))
    table_data = [["SDK", "CVE ID", "Severity", "CVSS", "CWE", "Published", "Description", "Reference"]] + rows
    col_widths = [80, 70, 50, 40, 60, 60, 200, 160]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BOX', (0,0), (-1,-1), 0.25, colors.black),
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

# Build PDF
add_table("🚨 New CVEs", new_cves)
add_table("📋 Existing CVEs", existing_cves)

doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=A4, rightMargin=10, leftMargin=10, topMargin=20, bottomMargin=20)
doc.build(story)
print(f"✅ PDF report generated: {OUTPUT_PDF}")
