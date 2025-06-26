import requests
import json
from datetime import datetime, timezone

# --- CONFIG ---
KEYWORDS = [
    {"sdk": "RTL8720CM", "search": "RTL8720CM"},
    {"sdk": "Ameba SDK", "search": "Ameba"},
    {"sdk": "RT", "search": "RT"},
]

headers = {"User-Agent": "cve-monitor/1.0"}
results = []

for item in KEYWORDS:
    res = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers,
        params={"keywordSearch": item["search"], "resultsPerPage": 20},
    )
    data = res.json()

    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        refs = cve.get("references", [])
        metrics = cve.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        weaknesses = cve.get("weaknesses", [])
        cwes = weaknesses[0]["description"][0]["value"] if weaknesses else "N/A"

        results.append({
            "sdk": item["sdk"],
            "id": cve["id"],
            "title": cve.get("titles", [{}])[0].get("title", ""),
            "description": cve.get("descriptions", [{}])[0].get("value", "N/A"),
            "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
            "cvss": cvss_data.get("baseScore", "N/A"),
            "cwe": cwes,
            "published": cve.get("published", "N/A"),
            "reference": refs[0]["url"] if refs else "N/A"
        })

output = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "results": results
}

with open("output/results.json", "w") as f:
    json.dump(output, f, indent=2)
