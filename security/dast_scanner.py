#!/usr/bin/env python3
"""
Lightweight DAST scanner (Dynamic Application Security Testing).

Crawls a running web app, then runs passive and active checks and writes a
normalized JSON findings file that aggregate.py consumes.

Scope, stated plainly:
  - This is a focused teaching/portfolio scanner, not a Burp/ZAP replacement.
  - It only runs against targets you own or intentionally vulnerable practice
    apps (the bundled demo_app, OWASP Juice Shop, DVWA, etc.). Scanning systems
    you do not have permission to test is illegal.

Checks implemented:
  Passive (per response)
    - Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options,
      HSTS on https, Referrer-Policy)
    - Insecure cookies (missing HttpOnly / Secure / SameSite)
    - Server version banner leakage
  Active (per discovered parameter)
    - Reflected XSS (marker reflection, unescaped)
    - Error-based SQL injection (DB error signatures)
    - Open redirect (attacker-controlled Location on 30x)

Dependencies: requests, beautifulsoup4 (standard for this kind of tool).
"""

import argparse
import json
import re
import sys
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlsplit

import requests
from bs4 import BeautifulSoup

# Unique markers so we only flag OUR injected payload, not coincidental text.
XSS_MARKER = "xssprobe9137"
XSS_PAYLOAD = f"<{XSS_MARKER}>"
SQLI_PAYLOAD = "'"
REDIRECT_HOST = "dast-probe.example.com"
REDIRECT_PAYLOAD = f"https://{REDIRECT_HOST}/"

# Signatures that indicate a database error reflected to the client.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite3\.\w+error",
    r"sqlite error",
    r"near \".*\": syntax error",
    r"pg::syntaxerror",
    r"psql: error",
    r"ora-\d{5}",
    r"microsoft odbc",
    r"odbc sql server driver",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "No CSP; page is more exposed to XSS/injection."),
    "X-Frame-Options": ("MEDIUM", "No clickjacking protection (X-Frame-Options / frame-ancestors)."),
    "X-Content-Type-Options": ("LOW", "Missing X-Content-Type-Options: nosniff; MIME sniffing possible."),
    "Referrer-Policy": ("LOW", "No Referrer-Policy; referrer may leak to third parties."),
}


class Scanner:
    def __init__(self, base_url, max_pages=40, delay=0.2, timeout=8):
        self.base_url = base_url.rstrip("/")
        self.host = urlparse(self.base_url).netloc
        self.scheme = urlparse(self.base_url).scheme
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "dast-scanner/1.0 (authorized-test)"})
        self.findings = []
        self.visited = set()
        # param targets: list of (url_without_query, method, {param: sample_value})
        self.param_targets = []
        self._seen_targets = set()

    # ---------- helpers ----------
    def _same_host(self, url):
        return urlparse(url).netloc == self.host

    def _get(self, url, params=None, allow_redirects=True):
        try:
            return self.session.get(
                url, params=params, timeout=self.timeout, allow_redirects=allow_redirects
            )
        except requests.RequestException as exc:
            print(f"  [!] request failed: {url} ({exc})", file=sys.stderr)
            return None

    def _add_finding(self, severity, category, location, detail, remediation, evidence=""):
        self.findings.append(
            {
                "tool": "dast",
                "severity": severity,
                "category": category,
                "location": location,
                "detail": detail,
                "remediation": remediation,
                "evidence": evidence[:400],
            }
        )

    def _register_params(self, url, method, params):
        key = (url, method, tuple(sorted(params)))
        if params and key not in self._seen_targets:
            self._seen_targets.add(key)
            self.param_targets.append((url, method, params))

    # ---------- crawl ----------
    def crawl(self):
        queue = deque([self.base_url])
        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            resp = self._get(url)
            if resp is None:
                continue
            time.sleep(self.delay)

            self.passive_checks(resp)

            # capture query params on this URL itself
            parsed = urlsplit(url)
            if parsed.query:
                qp = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                base = url.split("?")[0]
                self._register_params(base, "GET", qp)

            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"]).split("#")[0]
                if self._same_host(link) and link not in self.visited:
                    queue.append(link)
                    lp = urlsplit(link)
                    if lp.query:
                        qp = {k: v[0] for k, v in parse_qs(lp.query).items()}
                        self._register_params(link.split("?")[0], "GET", qp)
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                if not self._same_host(action):
                    continue
                method = (form.get("method") or "GET").upper()
                inputs = {}
                for field in form.find_all(["input", "textarea", "select"]):
                    name = field.get("name")
                    if name:
                        inputs[name] = field.get("value") or "test"
                self._register_params(action, method, inputs)

    # ---------- passive ----------
    def passive_checks(self, resp):
        loc = resp.url
        headers = resp.headers

        for header, (sev, msg) in SECURITY_HEADERS.items():
            if header not in headers:
                self._add_finding(
                    sev, "Missing security header", loc, msg,
                    f"Add the {header} response header.",
                    evidence=f"{header} not present",
                )
        if self.scheme == "https" and "Strict-Transport-Security" not in headers:
            self._add_finding(
                "MEDIUM", "Missing security header", loc,
                "HTTPS response without HSTS; downgrade attacks possible.",
                "Add Strict-Transport-Security with a long max-age.",
                evidence="Strict-Transport-Security not present",
            )

        server = headers.get("Server", "")
        if re.search(r"\d", server):
            self._add_finding(
                "LOW", "Version banner leakage", loc,
                f"Server header exposes software/version: '{server}'.",
                "Suppress or genericize the Server header.",
                evidence=f"Server: {server}",
            )

        for cookie in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []:
            low = cookie.lower()
            missing = [f for f in ("httponly", "secure", "samesite") if f not in low]
            if missing:
                self._add_finding(
                    "MEDIUM", "Insecure cookie", loc,
                    f"Cookie set without {', '.join(missing)}.",
                    "Set HttpOnly, Secure, and SameSite on session cookies.",
                    evidence=cookie[:120],
                )

    # ---------- active ----------
    def active_checks(self):
        for url, method, params in self.param_targets:
            for pname in params:
                self._test_xss(url, method, params, pname)
                self._test_sqli(url, method, params, pname)
                self._test_open_redirect(url, method, params, pname)
                time.sleep(self.delay)

    def _send(self, url, method, data):
        try:
            if method == "POST":
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
            return self.session.get(url, params=data, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

    def _test_xss(self, url, method, params, pname):
        payload = dict(params)
        payload[pname] = XSS_PAYLOAD
        resp = self._send(url, method, payload)
        if resp is not None and XSS_PAYLOAD in resp.text:
            self._add_finding(
                "HIGH", "Reflected XSS",
                f"{url} [{method} param '{pname}']",
                "Injected script marker was reflected unescaped in the response.",
                "Context-encode all user input on output; add a Content-Security-Policy.",
                evidence=f"payload {XSS_PAYLOAD} reflected verbatim",
            )

    def _test_sqli(self, url, method, params, pname):
        payload = dict(params)
        payload[pname] = params[pname] + SQLI_PAYLOAD
        resp = self._send(url, method, payload)
        if resp is None:
            return
        body = resp.text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig, body):
                self._add_finding(
                    "HIGH", "SQL injection (error-based)",
                    f"{url} [{method} param '{pname}']",
                    "A single quote triggered a database error, indicating unsanitized input in a query.",
                    "Use parameterized queries / prepared statements; never concatenate input into SQL.",
                    evidence=f"matched DB error signature: {sig}",
                )
                return

    def _test_open_redirect(self, url, method, params, pname):
        payload = dict(params)
        payload[pname] = REDIRECT_PAYLOAD
        resp = self._send(url, method, payload)
        if resp is None:
            return
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if REDIRECT_HOST in location:
                self._add_finding(
                    "MEDIUM", "Open redirect",
                    f"{url} [{method} param '{pname}']",
                    "Redirect destination is fully attacker-controlled.",
                    "Allow-list redirect targets or use relative paths only.",
                    evidence=f"Location: {location}",
                )

    def run(self):
        print(f"[*] Target: {self.base_url}")
        print("[*] Crawling...")
        self.crawl()
        print(f"[*] Crawled {len(self.visited)} URL(s), found {len(self.param_targets)} parameterized target(s)")
        print("[*] Running active checks...")
        self.active_checks()
        print(f"[*] Done. {len(self.findings)} finding(s).")
        return self.findings


def main():
    ap = argparse.ArgumentParser(description="Lightweight DAST scanner (authorized targets only).")
    ap.add_argument("target", help="Base URL of the running app, e.g. http://127.0.0.1:5001")
    ap.add_argument("-o", "--output", default="dast-report.json", help="Findings JSON output path")
    ap.add_argument("--max-pages", type=int, default=40, help="Crawl page limit")
    ap.add_argument("--delay", type=float, default=0.2, help="Delay between requests (seconds)")
    args = ap.parse_args()

    scanner = Scanner(args.target, max_pages=args.max_pages, delay=args.delay)
    findings = scanner.run()
    with open(args.output, "w") as fh:
        json.dump(findings, fh, indent=2)
    print(f"[*] Wrote {args.output}")
    # Always exit 0: the aggregator owns the pass/fail gate for the whole pipeline.
    return 0


if __name__ == "__main__":
    sys.exit(main())
