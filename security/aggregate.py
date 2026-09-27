#!/usr/bin/env python3
"""
Security findings aggregator.

Reads the JSON output of every scanner in the pipeline, normalizes each finding
into one common shape, writes a consolidated JSON + HTML report, and sets the
process exit code so CI can fail the build on severity.

Standard-library only, so it runs anywhere (CI runner, laptop) with no install.

Supported inputs (all optional; missing or empty files are skipped):
  --bandit    bandit.json        SAST      (bandit -f json)
  --pip-audit pip-audit.json     SCA       (pip-audit -f json)
  --gitleaks  gitleaks.json      secrets   (gitleaks detect -f json)
  --trivy     trivy.json         container (trivy image -f json)
  --dast      dast-report.json   DAST      (security/dast_scanner.py)

Common finding shape:
  {tool, category, severity, title, location, detail, remediation, evidence}

Severity scale (high to low): CRITICAL, HIGH, MEDIUM, LOW, INFO
"""

import argparse
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEVERITY_COLORS = {
    "CRITICAL": "#7c1d1d",
    "HIGH": "#b42318",
    "MEDIUM": "#b54708",
    "LOW": "#175cd3",
    "INFO": "#475467",
    "UNKNOWN": "#667085",
}


def _load(path):
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [!] could not parse {path}: {exc}", file=sys.stderr)
        return None


def _norm_sev(value):
    return (value or "UNKNOWN").upper() if (value or "").upper() in SEVERITY_ORDER else "UNKNOWN"


def _finding(tool, category, severity, title, location, detail, remediation, evidence=""):
    return {
        "tool": tool,
        "category": category,
        "severity": _norm_sev(severity),
        "title": title,
        "location": location,
        "detail": detail,
        "remediation": remediation,
        "evidence": evidence,
    }


# ---------- per-tool parsers (match each tool's documented JSON schema) ----------

def parse_bandit(data):
    out = []
    for r in (data or {}).get("results", []):
        out.append(_finding(
            tool="bandit (SAST)",
            category=r.get("test_name") or r.get("test_id", "issue"),
            severity=r.get("issue_severity", "UNKNOWN"),
            title=r.get("issue_text", "Static analysis finding"),
            location=f"{r.get('filename','?')}:{r.get('line_number','?')}",
            detail=f"{r.get('test_id','')} confidence={r.get('issue_confidence','')}",
            remediation="Review flagged code; see Bandit rule docs for the test ID.",
            evidence=(r.get("code") or "").strip()[:400],
        ))
    return out


def parse_pip_audit(data):
    out = []
    # pip-audit -f json is either {"dependencies":[...]} (newer) or a bare list (older).
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    for dep in deps or []:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for v in dep.get("vulns", []) or []:
            fixes = ", ".join(v.get("fix_versions", []) or []) or "no fix listed"
            out.append(_finding(
                tool="pip-audit (SCA)",
                category="Vulnerable dependency",
                severity="HIGH",  # pip-audit does not emit CVSS; treat known CVEs as HIGH by default
                title=f"{name} {version}: {v.get('id','vuln')}",
                location=f"{name}=={version}",
                detail=(v.get("description") or "").strip()[:300],
                remediation=f"Upgrade to: {fixes}",
                evidence=", ".join(v.get("aliases", []) or []),
            ))
    return out


def parse_gitleaks(data):
    out = []
    # gitleaks -f json emits a list of leak objects.
    for leak in data or []:
        out.append(_finding(
            tool="gitleaks (secrets)",
            category="Hardcoded secret",
            severity="HIGH",
            title=leak.get("Description") or leak.get("RuleID", "Secret detected"),
            location=f"{leak.get('File','?')}:{leak.get('StartLine','?')}",
            detail=f"rule={leak.get('RuleID','')} commit={str(leak.get('Commit',''))[:12]}",
            remediation="Remove the secret, rotate it, and load it from env/secret manager.",
            evidence=(leak.get("Match") or "")[:80],
        ))
    return out


def parse_trivy(data):
    out = []
    for result in (data or {}).get("Results", []) or []:
        target = result.get("Target", "?")
        for v in result.get("Vulnerabilities", []) or []:
            out.append(_finding(
                tool="trivy (container/SCA)",
                category="Vulnerable package",
                severity=v.get("Severity", "UNKNOWN"),
                title=f"{v.get('PkgName','?')}: {v.get('VulnerabilityID','?')}",
                location=f"{target} -> {v.get('PkgName','?')} {v.get('InstalledVersion','')}",
                detail=(v.get("Title") or v.get("Description") or "").strip()[:300],
                remediation=f"Upgrade to {v.get('FixedVersion','(no fix)')}",
                evidence=v.get("PrimaryURL", ""),
            ))
    return out


def parse_dast(data):
    out = []
    for f in data or []:
        out.append(_finding(
            tool="dast (DAST)",
            category=f.get("category", "Dynamic finding"),
            severity=f.get("severity", "UNKNOWN"),
            title=f.get("category", "Dynamic finding"),
            location=f.get("location", "?"),
            detail=f.get("detail", ""),
            remediation=f.get("remediation", ""),
            evidence=f.get("evidence", ""),
        ))
    return out


# ---------- reporting ----------

def build_html(findings, counts, generated_at, gate_severity, gate_failed):
    rows = []
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#667085")
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{html.escape(f['severity'])}</span></td>"
            f"<td>{html.escape(f['tool'])}</td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td class='loc'>{html.escape(str(f['location']))}</td>"
            f"<td>{html.escape(f['detail'])}<div class='rem'>Fix: {html.escape(f['remediation'])}</div>"
            f"{('<div class=ev>'+html.escape(str(f['evidence']))+'</div>') if f['evidence'] else ''}</td>"
            "</tr>"
        )
    chips = "".join(
        f"<span class='chip' style='border-color:{SEVERITY_COLORS[s]};color:{SEVERITY_COLORS[s]}'>"
        f"{s}: {counts.get(s,0)}</span>"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    gate = (
        f"<div class='gate fail'>BUILD GATE: FAILED (found severity &ge; {gate_severity})</div>"
        if gate_failed else
        f"<div class='gate pass'>BUILD GATE: PASSED (no findings &ge; {gate_severity})</div>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Pipeline Report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#f8fafc; color:#101828; }}
  header {{ background:#0b1324; color:#fff; padding:24px 28px; }}
  header h1 {{ margin:0 0 4px; font-size:20px; }}
  header .meta {{ color:#94a3b8; font-size:13px; }}
  .wrap {{ padding:20px 28px 48px; }}
  .chip {{ display:inline-block; border:1px solid; border-radius:999px; padding:3px 10px; margin:4px 6px 0 0; font-size:13px; font-weight:600; }}
  .gate {{ margin:16px 0; padding:12px 16px; border-radius:8px; font-weight:700; }}
  .gate.fail {{ background:#fee4e2; color:#912018; }}
  .gate.pass {{ background:#dcfae6; color:#085d3a; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 1px 2px rgba(16,24,40,.06); }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #eaecf0; vertical-align:top; font-size:13px; }}
  th {{ background:#f2f4f7; font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#475467; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
  .loc {{ font-family: ui-monospace, monospace; font-size:12px; color:#344054; word-break:break-all; }}
  .rem {{ color:#085d3a; margin-top:4px; }}
  .ev {{ color:#667085; margin-top:4px; font-family:ui-monospace,monospace; font-size:11px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0b1220; color:#e5e7eb; }}
    table {{ background:#111827; }} th {{ background:#1f2937; color:#9ca3af; }}
    td {{ border-color:#1f2937; }} .loc {{ color:#cbd5e1; }}
  }}
</style></head>
<body>
<header>
  <h1>Security Pipeline Report</h1>
  <div class="meta">Generated {generated_at} &middot; {len(findings)} finding(s)</div>
</header>
<div class="wrap">
  <div>{chips}</div>
  {gate}
  <table>
    <thead><tr><th>Severity</th><th>Tool</th><th>Category</th><th>Location</th><th>Detail &amp; remediation</th></tr></thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan=5>No findings.</td></tr>'}
    </tbody>
  </table>
</div>
</body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Aggregate security scanner outputs into one report.")
    ap.add_argument("--bandit")
    ap.add_argument("--pip-audit", dest="pip_audit")
    ap.add_argument("--gitleaks")
    ap.add_argument("--trivy")
    ap.add_argument("--dast")
    ap.add_argument("--out-json", default="security-report.json")
    ap.add_argument("--out-html", default="security-report.html")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                    help="Fail (exit 1) if any finding is at or above this severity. NONE never fails.")
    args = ap.parse_args()

    findings = []
    findings += parse_bandit(_load(args.bandit))
    findings += parse_pip_audit(_load(args.pip_audit))
    findings += parse_gitleaks(_load(args.gitleaks))
    findings += parse_trivy(_load(args.trivy))
    findings += parse_dast(_load(args.dast))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["tool"]))
    counts = Counter(f["severity"] for f in findings)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    gate_failed = False
    if args.fail_on != "NONE":
        threshold = SEVERITY_ORDER[args.fail_on]
        gate_failed = any(SEVERITY_ORDER.get(f["severity"], 9) <= threshold for f in findings)

    summary = {
        "generated_at": generated_at,
        "total": len(findings),
        "by_severity": dict(counts),
        "fail_on": args.fail_on,
        "gate_failed": gate_failed,
        "findings": findings,
    }
    with open(args.out_json, "w") as fh:
        json.dump(summary, fh, indent=2)
    with open(args.out_html, "w") as fh:
        fh.write(build_html(findings, counts, generated_at, args.fail_on, gate_failed))

    print(f"[*] {len(findings)} finding(s): " +
          ", ".join(f"{s}={counts.get(s,0)}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
    print(f"[*] Reports: {args.out_json}, {args.out_html}")
    if gate_failed:
        print(f"[x] GATE FAILED: findings at or above {args.fail_on}", file=sys.stderr)
        return 1
    print(f"[ok] GATE PASSED (threshold {args.fail_on})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
