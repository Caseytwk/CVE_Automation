import json
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

INPUT_JSON = "output/results.json"
OUTPUT_PDF = "output/cve_report.pdf"

def make_table(data, columns, col_widths=None):
    table_data = [columns]
    for item in data:
        row = [str(item.get(col, "")) for col in columns]
        table_data.append(row)
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    return t

def main():
    with open(INPUT_JSON) as f:
        data = json.load(f)

    results = data.get("results", [])

    # Split CVEs into new and existing
    new_cves = [cve for cve in results if cve.get("is_new")]
    existing_cves = [cve for cve in results if not cve.get("is_new")]

    doc = SimpleDocTemplate(OUTPUT_PDF, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("CVE Vulnerability Report", styles['Title']))
    story.append(Spacer(1, 12))

    # Timestamp
    timestamp = data.get("timestamp", "N/A")
    story.append(Paragraph(f"Report generated at: {timestamp}", styles['Normal']))
    story.append(Spacer(1, 24))

    # Section 1: New CVEs (Detailed)
    story.append(Paragraph("New CVEs Detected", styles['Heading2']))
    story.append(Spacer(1, 12))

    if new_cves:
        for cve in new_cves:
            ptext = f"<b>{cve.get('id')}</b> - Severity: {cve.get('severity')} - CVSS: {cve.get('cvss')}"
            story.append(Paragraph(ptext, styles['Heading4']))
            story.append(Paragraph(f"<b>SDK:</b> {cve.get('sdk')}", styles['Normal']))
            story.append(Paragraph(f"<b>Description:</b> {cve.get('description')}", styles['Normal']))
            story.append(Paragraph(f"<b>Published:</b> {cve.get('published')}", styles['Normal']))
            story.append(Paragraph(f"<b>Reference:</b> <a href='{cve.get('reference')}'>{cve.get('reference')}</a>", styles['Normal']))
            story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("No new CVEs detected.", styles['Normal']))
        story.append(Spacer(1, 12))

    story.append(Spacer(1, 24))

    # Section 2: Existing CVEs (Summary Table)
    story.append(Paragraph("Existing CVEs", styles['Heading2']))
    story.append(Spacer(1, 12))

    if existing_cves:
        # Show summary table with fewer columns
        columns = ["id", "severity", "cvss", "sdk", "published"]
        col_widths = [80, 60, 50, 100, 90]  # adjust widths to fit nicely
        table = make_table(existing_cves, columns, col_widths)
        story.append(table)
    else:
        story.append(Paragraph("No existing CVEs.", styles['Normal']))

    doc.build(story)
    print(f"PDF report generated: {OUTPUT_PDF}")

if __name__ == "__main__":
    main()
