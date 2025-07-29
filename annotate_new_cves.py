import json
import os

new_ids = set()
if os.path.exists("new_ids.txt"):
    with open("new_ids.txt") as f:
        new_ids = set(f.read().split())

with open("output/results.json") as f:
    data = json.load(f)

for entry in data["results"]:
    if entry["id"] in new_ids:
        entry["is_new"] = True

with open("output/results.json", "w") as f:
    json.dump(data, f, indent=2)
