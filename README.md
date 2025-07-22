.github/
└── workflows/
    ├── cve-monitor.yml       # Workflow that scans for CVEs and updates output/results.json
    └── alert.yml             # Workflow that alerts via Teams when new CVEs are found

output/
└── results.json              # Latest CVE results
check_cves.py                 # CVE scanning script
index.html                    # Dashboard deployed to GitHub Pages
