#!/usr/bin/env python3
"""
security_gate.py

Reads scanner outputs placed under ./security-reports and enforces a security gate:
- Semgrep: fail if any ERROR or HIGH
- Trivy (fs): fail if any CRITICAL or HIGH
- OWASP ZAP: fail if any High (configurable below)

Produces summary JSON files in ./security-reports:
- semgrep-summary.json
- trivy-summary.json
- zap-summary.json

Exit code 0 -> gate passed
Exit code 1 -> gate failed
"""

import json
import sys
import os
from collections import Counter

REPORT_DIR = "security-reports"

# Policy thresholds (adjust if needed)
FAIL_ON = {
    "semgrep": {"ERROR": 1, "HIGH": 1},        # if count >= value -> fail
    "trivy": {"CRITICAL": 1, "HIGH": 1},
    "zap": {"High": 1}                         # ZAP risk labels: High, Medium, Low, Informational
}

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def summarize_semgrep():
    p = os.path.join(REPORT_DIR, "semgrep.json")
    j = load_json(p) or {}
    counts = Counter()
    for r in j.get("results", []):
        # Semgrep severity may be under extra.metadata.severity or extra.severity
        sev = (r.get("extra", {}) or {}).get("metadata", {}).get("severity") or (r.get("extra", {}) or {}).get("severity") or r.get("severity") or "MEDIUM"
        sev = str(sev).upper()
        counts[sev] += 1
    out = {k: counts.get(k, 0) for k in ["ERROR", "HIGH", "MEDIUM", "LOW", "INFO"]}
    write_json(os.path.join(REPORT_DIR, "semgrep-summary.json"), out)
    return out

def summarize_trivy():
    p = os.path.join(REPORT_DIR, "trivy-vulns.json")
    j = load_json(p) or {}
    counts = Counter()
    # Trivy JSON format has "Results": [ { "Vulnerabilities": [ { "Severity": "HIGH" } ] } ]
    for res in j.get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            counts[sev] += 1
    out = {k: counts.get(k, 0) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]}
    write_json(os.path.join(REPORT_DIR, "trivy-summary.json"), out)
    return out

def summarize_zap():
    p = os.path.join(REPORT_DIR, "zap-report.json")
    j = load_json(p) or {}
    counts = Counter()
    # ZAP baseline JSON structure typically contains "site": [{ "alerts": [ { "riskdesc": "High (something)" } ] }]
    for site in j.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            # riskdesc often like "High (x)", or use 'risk' numeric or 'riskId'
            risk = alert.get("riskdesc") or alert.get("risk") or ""
            if isinstance(risk, str):
                sev = risk.split(" ")[0]
            else:
                sev = str(risk)
            if not sev:
                sev = "Informational"
            counts[sev] += 1
    out = {k: counts.get(k, 0) for k in ["High", "Medium", "Low", "Informational"]}
    write_json(os.path.join(REPORT_DIR, "zap-summary.json"), out)
    return out

def check_policy(sem, tri, zap):
    failures = []

    # Semgrep
    for key, threshold in FAIL_ON["semgrep"].items():
        if sem.get(key, 0) >= threshold:
            failures.append(f"Semgrep >= {key}: {sem.get(key)}")

    # Trivy
    for key, threshold in FAIL_ON["trivy"].items():
        if tri.get(key, 0) >= threshold:
            failures.append(f"Trivy >= {key}: {tri.get(key)}")

    # ZAP
    for key, threshold in FAIL_ON["zap"].items():
        if zap.get(key, 0) >= threshold:
            failures.append(f"ZAP >= {key}: {zap.get(key)}")

    return failures

def main():
    sem = summarize_semgrep()
    tri = summarize_trivy()
    zap = summarize_zap()

    print("Semgrep summary:", sem)
    print("Trivy summary:", tri)
    print("ZAP summary:", zap)

    failures = check_policy(sem, tri, zap)
    if failures:
        print("Security gate FAILED:")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    else:
        print("Security gate PASSED")
        sys.exit(0)

if __name__ == "__main__":
    main()
