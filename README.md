# DevSecOps Security Pipeline

![Security Pipeline](https://github.com/Chaithra3-6/devsecops-security/actions/workflows/security.yml/badge.svg)

A CI pipeline that runs five classes of security scan on every push and pull
request, merges the results into one report, and can fail the build when
findings reach a chosen severity. Security runs inside the pipeline instead of
after release.

The DAST scanner and the report aggregator are written in Python. The other
scanners are open-source tools invoked from the workflow.

## Pipeline

```
 push / pull_request
        |
        v
 +-----------------------------------------------------------+
 |  GitHub Actions: Security Pipeline                        |
 |                                                           |
 |  SAST        Bandit          -> bandit.json               |
 |  SCA         pip-audit       -> pip-audit.json            |
 |  Secrets     Gitleaks        -> gitleaks.json             |
 |  Container   Trivy           -> trivy.json                |
 |  DAST        custom scanner  -> dast-report.json          |
 |                     |                                     |
 |                     v                                     |
 |            aggregate.py (stdlib only)                     |
 |                     |                                     |
 |      security-report.json  +  security-report.html       |
 |                     |                                     |
 |         gate: fail build if severity >= --fail-on         |
 +-----------------------------------------------------------+
```

Each scanner runs independently and never aborts the job on its own. The
aggregator is the single place that decides pass or fail, so the report is
always produced and every tool always runs.

## What each stage catches

| Stage | Tool | Type | Finds |
|-------|------|------|-------|
| SAST | Bandit | Static analysis of Python | Hardcoded secrets, `debug=True`, unsafe calls |
| SCA | pip-audit | Dependency audit | Known CVEs in Python packages |
| Secrets | Gitleaks | Secret scanning | Tokens and keys committed to the repo |
| Container | Trivy | Image scan | OS and library CVEs in the Docker image |
| DAST | custom scanner | Dynamic testing | Reflected XSS, error-based SQLi, open redirect, missing headers, insecure cookies |

## Run the DAST scanner locally

```bash
pip install requests beautifulsoup4 flask

# start the vulnerable demo target (leave running)
python security/demo_app/app.py         # serves http://127.0.0.1:5001

# in a second terminal:
python security/dast_scanner.py http://127.0.0.1:5001 -o dast-report.json
python security/aggregate.py --dast dast-report.json \
  --out-json security-report.json --out-html security-report.html --fail-on HIGH
```

Open `security-report.html` in a browser. The full five-tool run happens
automatically in GitHub Actions on every push. Download the `security-report`
artifact from the Actions run to see it.

## The severity gate

`aggregate.py --fail-on` sets the threshold. Any finding at or above it makes the
aggregator exit non-zero, which fails the CI job.

```
--fail-on CRITICAL   fail only on critical
--fail-on HIGH       fail on high or critical
--fail-on MEDIUM     stricter
--fail-on NONE       report only, never fail the build
```

The workflow runs in report-only mode against the demo app. Change `NONE` to
`HIGH` to enforce blocking on a real application.

## Repository layout

```
.github/workflows/security.yml     CI pipeline
requirements-security.txt          pinned SAST/SCA tooling
security/
  dast_scanner.py                  DAST scanner (requests + beautifulsoup4)
  aggregate.py                     findings aggregator + HTML report (stdlib only)
  demo_app/                        intentionally vulnerable target for the demo
SECURITY_PIPELINE.md               design and verification notes
INTEGRATION.md                     how to add this pipeline to another repo
```

## Scope and ethics

The DAST scanner sends live payloads, so it runs only against targets you own or
against intentionally vulnerable practice apps such as the bundled demo app,
OWASP Juice Shop, or DVWA. Scanning a system you do not have permission to test
is illegal. The bundled demo app is deliberately insecure and must never be
exposed to a public network.
