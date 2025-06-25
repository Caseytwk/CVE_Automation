import requests
import json
from datetime import datetime

headers = {"User-Agent": "cve-monitor/1.0"}

params = {
    "keywordSearch": "realtek",  # Change to your keyword or CPE
    "resultsPerPage": 10,
}

res = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params)
data = res.json()

output = {
    "timestamp": datetime.utcnow().isoformat() + "Z",
    "results": []
}

for item in data.get("vulnerabilities", []):
    cve = item["cve"]
    output["results"].append({
        "id": cve["id"],
        "description": cve["descriptions"][0]["value"],
        "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
        "published": cve["published"],
    })

with open("results.json", "w") as f:
    json.dump(output, f, indent=2)
