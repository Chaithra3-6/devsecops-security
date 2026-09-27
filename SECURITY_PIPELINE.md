# Secure-by-default CI/CD Security Pipeline

A CI pipeline that runs five classes of security scan on every push and pull
request, merges the results into one report, and fails the build when findings
reach a severity you choose. It follows the DevSecOps idea of shifting security
left: the checks run inside the pipeline instead of after release.

The custom DAST scanner and the report aggregator are written in Python. The
other scanners are recognised open-source tools invoked from the workflow.

## Pipeline at a glance

```
 push / pull_request
        |
        v
 +-----------------------------------------------------------+
 |  GitHub Actions job: Security Pipeline                    |
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

## Repository layout

```
.github/workflows/security.yml     CI pipeline
requirements-security.txt          pinned SAST/SCA tooling
security/
  dast_scanner.py                  DAST scanner (requests + beautifulsoup4)
  aggregate.py                     findings aggregator + HTML report (stdlib only)
  demo_app/                        intentionally vulnerable target for the demo
    app.py
    requirements.txt
    Dockerfile
sample-security-report.html        example of the generated report
```

## Run it locally

```bash
# 1. install the DAST scanner deps
pip install requests beautifulsoup4

# 2. start the vulnerable demo target
pip install -r security/demo_app/requirements.txt
python security/demo_app/app.py &        # serves http://127.0.0.1:5001

# 3. run the DAST scanner
python security/dast_scanner.py http://127.0.0.1:5001 -o dast-report.json

# 4. build the consolidated report and apply the gate
python security/aggregate.py --dast dast-report.json \
  --out-json security-report.json --out-html security-report.html --fail-on HIGH

# open security-report.html in a browser
```

To run the full five-tool set locally, install the other tools
(`pip install bandit pip-audit`, plus Gitleaks and Trivy binaries) and pass
each output file to `aggregate.py`. In CI this is already wired up.

## The severity gate

`aggregate.py --fail-on` sets the threshold. Any finding at or above it makes
the aggregator exit 1, which fails the CI job.

```
--fail-on CRITICAL   fail only on critical
--fail-on HIGH       fail on high or critical   (default)
--fail-on MEDIUM     stricter
--fail-on NONE       report only, never fail the build
```

## Scope and ethics

The DAST scanner sends live payloads, so it runs only against targets you own
or against intentionally vulnerable practice apps such as the bundled
`demo_app`, OWASP Juice Shop, or DVWA. Scanning a system you do not have
permission to test is illegal. The bundled demo app is deliberately insecure
and must never be exposed to a public network.

## What is verified

Built and run end to end in this environment:

- the DAST scanner against the demo app: it detects reflected XSS, error-based
  SQL injection, open redirect, insecure cookies, missing security headers, and
  server version banner leakage
- the aggregator against the output of all five tools: correct normalisation,
  severity counts, HTML rendering, and pass/fail gate, including the case where
  the injected XSS payload is safely escaped inside the report itself
- the workflow YAML is valid and the aggregate step command matches the files
  the scanners produce

Runs in CI only (needs open network and tool installs not available in the
build sandbox): the Bandit, pip-audit, Gitleaks, and Trivy steps, and the
Docker image build. These use standard invocations and pinned tool versions.

## Optional extension: OWASP ZAP

To add ZAP as a second DAST engine alongside the custom scanner, add this step
after the app is started in the workflow:

```yaml
- name: OWASP ZAP baseline
  uses: zaproxy/action-baseline@v0.12.0
  with:
    target: http://127.0.0.1:5001
    cmd_options: '-I'   # do not fail on warnings; the aggregator gates
```
