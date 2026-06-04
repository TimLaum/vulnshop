#!/usr/bin/env python3
"""
generate_report.py - Génère un rapport HTML consolidé à partir des rapports Bandit et Trivy
Étape 'report' du pipeline GitLab CI
"""

import json
import os
from datetime import datetime

BANDIT_JSON = "bandit-report.json"
TRIVY_JSON  = "trivy-image-report.json"
OUTPUT_HTML = "security-report.html"


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None


def parse_bandit(data):
    if not data:
        return [], {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    results = data.get("results", [])
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        sev = r.get("issue_severity", "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return results, counts


def parse_trivy(data):
    if not data:
        return [], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vulns = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            sev = v.get("Severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
            vulns.append({
                "id": v.get("VulnerabilityID", ""),
                "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", "N/A"),
                "severity": sev,
                "title": v.get("Title", v.get("Description", "")[:80]),
            })
    return vulns, counts


def sev_color(sev):
    return {
        "CRITICAL": "#7a1a1a", "HIGH": "#b34700",
        "MEDIUM": "#7a5c00", "LOW": "#2d5a1b"
    }.get(sev.upper(), "#555")


def build_html(bandit_results, bandit_counts, trivy_vulns, trivy_counts):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_issues = sum(bandit_counts.values()) + sum(trivy_counts.values())

    bandit_rows = ""
    for r in bandit_results[:50]:
        sev = r.get("issue_severity", "LOW").upper()
        bandit_rows += f"""
        <tr>
          <td style="color:{sev_color(sev)};font-weight:600">{sev}</td>
          <td>{r.get('issue_text','')}</td>
          <td><code>{r.get('filename','').split('/')[-1]}:{r.get('line_number','')}</code></td>
          <td>{r.get('test_id','')}</td>
        </tr>"""

    trivy_rows = ""
    for v in trivy_vulns[:60]:
        trivy_rows += f"""
        <tr>
          <td style="color:{sev_color(v['severity'])};font-weight:600">{v['severity']}</td>
          <td><code>{v['id']}</code></td>
          <td>{v['pkg']}</td>
          <td>{v['installed']}</td>
          <td>{v['fixed']}</td>
          <td style="font-size:12px">{v['title'][:70]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport Sécurité - VulnShop</title>
<style>
  body {{ font-family: -apple-system, sans-serif; margin: 0; background: #f5f5f5; color: #222; }}
  .header {{ background: #1a1a2e; color: white; padding: 2rem 3rem; }}
  .header h1 {{ margin: 0; font-size: 1.8rem; }}
  .header p  {{ margin: 0.3rem 0 0; opacity: 0.7; font-size: 0.9rem; }}
  .body {{ padding: 2rem 3rem; max-width: 1100px; margin: auto; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: white; border-radius: 8px; padding: 1rem; text-align: center; border: 1px solid #ddd; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; }}
  .stat .lbl {{ font-size: 0.75rem; color: #666; text-transform: uppercase; }}
  section {{ background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #ddd; }}
  h2 {{ margin: 0 0 1rem; font-size: 1.1rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px; background: #f8f8f8; border-bottom: 2px solid #ddd; }}
  td {{ padding: 7px 8px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>Rapport Sécurité DevSecOps — VulnShop</h1>
  <p>Généré le {now} · Pipeline GitLab CI · {total_issues} problèmes détectés</p>
</div>
<div class="body">
  <div class="stats">
    <div class="stat"><div class="num" style="color:#b34700">{bandit_counts.get('HIGH',0)}</div><div class="lbl">Bandit HIGH</div></div>
    <div class="stat"><div class="num" style="color:#7a5c00">{bandit_counts.get('MEDIUM',0)}</div><div class="lbl">Bandit MEDIUM</div></div>
    <div class="stat"><div class="num" style="color:#7a1a1a">{trivy_counts.get('CRITICAL',0)}</div><div class="lbl">Trivy CRITICAL</div></div>
    <div class="stat"><div class="num" style="color:#b34700">{trivy_counts.get('HIGH',0)}</div><div class="lbl">Trivy HIGH</div></div>
    <div class="stat"><div class="num" style="color:#7a5c00">{trivy_counts.get('MEDIUM',0)}</div><div class="lbl">Trivy MEDIUM</div></div>
    <div class="stat"><div class="num">{total_issues}</div><div class="lbl">Total</div></div>
  </div>

  <section>
    <h2>Bandit SAST — Vulnérabilités dans le code source ({sum(bandit_counts.values())} issues)</h2>
    <table>
      <thead><tr><th>Sévérité</th><th>Description</th><th>Fichier:Ligne</th><th>Test ID</th></tr></thead>
      <tbody>{bandit_rows or '<tr><td colspan="4">Aucun rapport Bandit disponible</td></tr>'}</tbody>
    </table>
  </section>

  <section>
    <h2>Trivy — Vulnérabilités dans l'image Docker ({sum(trivy_counts.values())} CVEs)</h2>
    <table>
      <thead><tr><th>Sévérité</th><th>CVE</th><th>Package</th><th>Version</th><th>Fix</th><th>Description</th></tr></thead>
      <tbody>{trivy_rows or '<tr><td colspan="6">Aucun rapport Trivy disponible</td></tr>'}</tbody>
    </table>
  </section>
</div>
</body>
</html>"""


if __name__ == "__main__":
    bandit_data = load_json(BANDIT_JSON)
    trivy_data  = load_json(TRIVY_JSON)

    bandit_results, bandit_counts = parse_bandit(bandit_data)
    trivy_vulns,    trivy_counts  = parse_trivy(trivy_data)

    html = build_html(bandit_results, bandit_counts, trivy_vulns, trivy_counts)
    with open(OUTPUT_HTML, "w") as f:
        f.write(html)

    print(f"Rapport généré : {OUTPUT_HTML}")
    print(f"Bandit : {bandit_counts}")
    print(f"Trivy  : {trivy_counts}")
