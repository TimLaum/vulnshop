#!/usr/bin/env python3
"""Résume un rapport Trivy JSON : compte par sévérité + détails CRITICAL/HIGH."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "trivy-fs.json"

with open(path, encoding="utf-8") as f:
    data = json.load(f)

sev_count = {}
crit_high = []
pkgs = {}

for res in data.get("Results", []):
    for v in res.get("Vulnerabilities", []) or []:
        s = v.get("Severity", "?")
        sev_count[s] = sev_count.get(s, 0) + 1
        pkgs.setdefault(v.get("PkgName"), set()).add(v.get("InstalledVersion"))
        if s in ("CRITICAL", "HIGH"):
            crit_high.append({
                "id": v.get("VulnerabilityID"),
                "pkg": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion", "N/A"),
                "severity": s,
                "cvss": (v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score", "")
                        or (v.get("CVSS", {}).get("redhat", {}) or {}).get("V3Score", ""),
                "title": (v.get("Title") or "")[:70],
            })

print("=== FICHIER:", path, "===")
print("Severites:", sev_count, "| TOTAL:", sum(sev_count.values()))
print()
# Tri par CVSS décroissant
crit_high.sort(key=lambda x: (x["severity"] != "CRITICAL", -(x["cvss"] or 0)))
for v in crit_high:
    print(f"[{v['severity']}] CVSS={v['cvss']} {v['id']} | {v['pkg']} {v['installed']} -> fix {v['fixed']}")
    print(f"        {v['title']}")

# Détail PyYAML
print()
for v in crit_high:
    if "yaml" in (v["pkg"] or "").lower():
        print("PyYAML:", v)
