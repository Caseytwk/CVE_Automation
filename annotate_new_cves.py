import json
import os

new_ids_path = "output/new_ids.txt"

new_ids = set()
if os.path.exists(new_ids_path):
    with open(new_ids_path) as f:
        new_ids = set(line.strip() for line in f if line.strip())

with open("output/results.json") as f:
    data = json.load(f)

for entry in data["results"]:
    if entry["id"] in new_ids:
        entry["is_new"] = True
        print(f"✅ Marked {entry['id']} as new")

print(f"🔍 Total new CVEs marked: {marked}")

with open("output/results.json", "w") as f:
    json.dump(data, f, indent=2)
