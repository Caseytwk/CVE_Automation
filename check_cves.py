import requests
import json
from datetime import datetime, timezone
from packaging import version
import os
import re

# --- CONFIG ---
KEYWORDS = [
    {"sdk": "RTL8720CM", "search": "RTL8720CM"},
    {"sdk": "Ameba SDK", "search": "Ameba"},
    {"sdk": "FreeRTOS v10.2.0", "search": "FreeRTOS", "version": "10.2.0"},
    {"sdk": "Bluetooth Core Specification 4.2", "search": "Bluetooth Core Specification 4.2"},
    {"sdk": "cJSON v1.6.0", "search": "cJSON", "version": "1.6.0"},
    {"sdk": "IwIP 2.0.2", "search": "lwIP", "version": "2.0.2"},
    {"sdk": "mbed TLS 2.16.4", "search": "mbedtls", "version": "2.16.4"},
    {"sdk": "Newlib 2.5.0", "search": "Newlib", "version": "2.5.0"},
    {"sdk": "wpa_supplicant 2.2", "search": "wpa_supplicant", "version": "2.2"},
    {"sdk": "IEEE 802.1X, WPA, WPA2, RSN, IEEE 802.11i", "search": "IEEE 802.1X"},
]

VULNERS_API_KEY = "AHUJLKYXPT47G6BJ3YHAJUML81D3142WKQTOLQ52LQ14JSF2MC0GQL5BGKVGRLEX"
headers = {"User-Agent": "cve-monitor/1.0"}
results = []

def is_version_vulnerable(cpe_config, target_version):
    if not target_version:
        return True
    try:
        target_v = version.parse(target_version)
    except:
        return False

    if isinstance(cpe_config, list):
        configs = cpe_config
    elif isinstance(cpe_config, dict):
        configs = [cpe_config]
    else:
        return False

    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                vs = cpe.get("versionStartIncluding") or cpe.get("versionStartExcluding")
                ve = cpe.get("versionEndExcluding") or cpe.get("versionEndIncluding")
                try:
                    if vs:
                        start = version.parse(vs)
                        if cpe.get("versionStartExcluding") and not (start < target_v):
                            continue
                        elif not (start <= target_v):
                            continue
                    if ve:
                        end = version.parse(ve)
                        if cpe.get("versionEndExcluding") and not (target_v < end):
                            continue
                        elif not (target_v <= end):
                            continue
                    return True
                except:
                    continue
    return False

def search_nvd(keyword, target_version):
    index = 0
    nvd_results = []

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 200,
            "startIndex": index
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, params=params)
        data = r.json()
        vulns = data.get("vulnerabilities", [])

        for vuln in vulns:
            cve = vuln["cve"]
            configs = cve.get("configurations", {})
            if not is_version_vulnerable(configs, target_version):
                continue

            title = cve.get("titles", [{}])[0].get("title", "")
            description = cve.get("descriptions", [{}])[0].get("value", "N/A")

            # Extra filter to skip unrelated versions explicitly mentioned
            if target_version and target_version not in description and target_version not in title:
                found_versions = re.findall(r"v?(\d+\.\d+(?:\.\d+)?)", description)
                if found_versions and all(v != target_version for v in found_versions):
                    continue

            refs = cve.get("references", [])
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData") or
                metrics.get("cvssMetricV30", [{}])[0].get("cvssData") or
                metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
            )
            weaknesses = cve.get("weaknesses", [])
            cwes = weaknesses[0]["description"][0]["value"] if weaknesses else "N/A"

            # Skip if wpa_supplicant version is not 2.x but SDK is wpa_supplicant 2.2
            if "wpa_supplicant" in keyword.lower() and "2.2" in sdk:
                found_versions = re.findall(r"wpa_supplicant[_ ]?([0-9]+(?:\.[0-9]+)*)", description.lower())
                if found_versions:
                    if all(not v.startswith("2") for v in found_versions):
                        continue
                # elif "wpa_supplicant_8" in description.lower():  # fallback catch for _8 format
                #     continue



            nvd_results.append({
                "source": "NVD",
                "id": cve["id"],
                "title": title,
                "description": description,
                "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                "cvss": cvss_data.get("baseScore", "N/A"),
                "cwe": cwes,
                "published": cve.get("published", "N/A"),
                "reference": refs[0]["url"] if refs else "N/A"
            })

        index += 200
        if index >= data.get("totalResults", 0):
            break

    return nvd_results

def search_osv(keyword, version):
    if not version:
        return []
    payload = {
        "package": {"name": keyword.lower()},
        "version": version
    }
    try:
        r = requests.post("https://api.osv.dev/v1/query", json=payload)
        data = r.json()
        if not data.get("vulns"):
            print(f"[OSV] No CVEs found for {keyword} {version}")
        results = []
        for vuln in data.get("vulns", []):
            results.append({
                "source": "OSV",
                "id": vuln["id"],
                "title": vuln.get("summary", ""),
                "description": vuln.get("details", "N/A"),
                "cvss": vuln.get("severity", [{}])[0].get("score", "N/A"),
                "published": vuln.get("published", "N/A"),
                "reference": vuln.get("references", [{}])[0].get("url", "N/A")
            })
        return results
    except Exception as e:
        print(f"[OSV ERROR] {e}")
        return []

def search_vulners(keyword):
    if not VULNERS_API_KEY:
        return []
    try:
        r = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": keyword},
            headers={"User-Agent": "cve-monitor", "X-Api-Key": VULNERS_API_KEY}
        )
        data = r.json()
        results = []
        for doc in data.get("data", {}).get("search", []):
            if not doc.get("id") or not doc.get("type"):
                continue
            results.append({
                "source": "Vulners",
                "id": doc.get("id"),
                "title": doc.get("title", ""),
                "description": doc.get("description", "N/A"),
                "cvss": doc.get("cvss", "N/A"),
                "published": doc.get("published", "N/A"),
                "reference": f"https://vulners.com/{doc.get('type')}/{doc.get('id')}"
            })
        return results
    except Exception as e:
        print(f"[VULNERS ERROR] {e}")
        return []

for item in KEYWORDS:
    sdk = item["sdk"]
    keyword = item["search"]
    version_str = item.get("version")

    print(f"\n[INFO] Searching CVEs for {sdk} using keyword '{keyword}' and version '{version_str}'")
    r1 = search_nvd(keyword, version_str)
    r2 = search_osv(keyword, version_str) if not r1 else []
    r3 = search_vulners(keyword) if not (r1 or r2) else []

    for result in r1 + r2 + r3:
        result["sdk"] = sdk
        results.append(result)

output = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "results": results
}

os.makedirs("output", exist_ok=True)
with open("output/results.json", "w") as f:
    json.dump(output, f, indent=2)
