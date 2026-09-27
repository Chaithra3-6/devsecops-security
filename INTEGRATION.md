# Adding this pipeline to your existing repo

This targets the Async API Gateway repo, but the steps are the same for any
Python service. Total time is about 15 minutes.

## Step 1: copy these files in

Copy the following from this project into the root of your repo, keeping the
paths:

```
.github/workflows/security.yml
requirements-security.txt
security/dast_scanner.py
security/aggregate.py
security/__init__.py
SECURITY_PIPELINE.md
```

You do NOT need `security/demo_app/` in your real repo. It is only the practice
target. You can copy it in if you want the pipeline to stay green on the first
push before you wire in your own app, then remove it later.

## Step 2: point the container scan at your image

In `.github/workflows/security.yml`, the "Build image for scanning" step builds
the demo image. Change it to build your own:

```yaml
- name: Build image for scanning
  run: docker build -t app:ci .        # your Dockerfile at repo root
```

If your repo has no Dockerfile, either add one for your gateway, or switch Trivy
from image scan to filesystem scan by replacing the Trivy step with:

```yaml
- name: Trivy (filesystem scan)
  uses: aquasecurity/trivy-action@0.24.0
  with:
    scan-type: fs
    scan-ref: .
    format: json
    output: trivy.json
    severity: CRITICAL,HIGH,MEDIUM
    exit-code: "0"
```

## Step 3: point the DAST scan at your app

Replace the "Start app under test" and "DAST scan" steps with your app's start
command. For a FastAPI gateway run with uvicorn:

```yaml
- name: Start app under test
  run: |
    pip install -r requirements.txt
    uvicorn app.main:app --host 127.0.0.1 --port 8000 &
    for i in $(seq 1 20); do
      curl -sf http://127.0.0.1:8000/ >/dev/null && break
      sleep 1
    done

- name: DAST scan
  run: python security/dast_scanner.py http://127.0.0.1:8000 -o dast-report.json --delay 0
```

Change `app.main:app` to your actual module path and the port to match. If your
gateway needs env vars or a database, start them in the same step first.

## Step 4: choose the gate strictness

The aggregate step ends with `--fail-on HIGH`. Keep that to fail on high and
critical findings. Use `--fail-on NONE` first if you want the pipeline to report
without blocking merges while you triage the initial findings.

## Step 5: push and read the results

After you push, open the Actions tab, click the run, and download the
`security-report` artifact. Open `security-report.html` for the readable view.
The job passes or fails based on the gate.

## Turning your existing work into evidence

Point the DAST scanner at your running gateway once. It will exercise the JWT
auth, rate limiting, and headers you already built. That gives you a documented
security assessment of your own project, which is stronger to talk about in an
interview than a scan of someone else's demo app.

## Resume bullets, evidenced only

Use whichever matches what you actually run. Keep the numbers to what the report
shows.

- Built a GitHub Actions security pipeline integrating SAST (Bandit), SCA
  (pip-audit), secret scanning (Gitleaks), container scanning (Trivy), and a
  custom Python DAST scanner, with a single severity gate that fails the build
  on high-severity findings.
- Wrote a DAST scanner in Python (requests, BeautifulSoup) that crawls a target
  and detects reflected XSS, error-based SQL injection, open redirect, missing
  security headers, and insecure cookies, with JSON and HTML reporting.
- Consolidated multi-tool security output into one normalised report and applied
  a configurable severity gate to enforce a secure-by-default release process.
