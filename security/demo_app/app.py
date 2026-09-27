"""
Intentionally vulnerable demo app - DAST target ONLY.

This exists so the security pipeline has something to find. It is deliberately
insecure and must NEVER be deployed anywhere reachable from the internet.
It is the local/CI equivalent of OWASP Juice Shop, but tiny and dependency-light.

Vulnerabilities planted on purpose (each maps to a check in the pipeline):
  - Reflected XSS            (/search?q=)        -> DAST active check
  - Error-based SQL injection (/user?id=)        -> DAST active check
  - Open redirect            (/go?next=)         -> DAST active check
  - Missing security headers (all responses)     -> DAST passive check
  - Insecure session cookie  (no HttpOnly/Secure)-> DAST passive check
  - Hardcoded secret         (source code)       -> Bandit (SAST) + Gitleaks
  - debug=True               (source code)       -> Bandit (SAST)
"""

import sqlite3

from flask import Flask, request, make_response

app = Flask(__name__)

# Hardcoded secret on purpose: SAST (Bandit B105/B106) flags this.
app.config["SECRET_KEY"] = "hardcoded-super-secret-key-do-not-do-this-1234567890"
# Planted, obviously-fake token matching Gitleaks' default github-pat rule
# (ghp_ + 36 chars). Only exists so the secrets step reliably finds something.
GITHUB_TOKEN = "ghp_00000000000000000000000000000000DEMO"  # noqa - fake, do not use


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return conn


@app.route("/")
def index():
    # Links carry sample params so a crawler can discover the injectable endpoints.
    return (
        "<h1>Vulnerable Demo App</h1>"
        "<ul>"
        "<li><a href='/search?q=hello'>search</a></li>"
        "<li><a href='/user?id=1'>user</a></li>"
        "<li><a href='/go?next=/'>go</a></li>"
        "<li><a href='/login'>login</a></li>"
        "</ul>"
    )


@app.route("/search")
def search():
    # VULN: reflected XSS - user input echoed without escaping.
    q = request.args.get("q", "")
    return f"<html><body>You searched for: {q}</body></html>"


@app.route("/user")
def user():
    # VULN: SQL injection - input concatenated into the query, error surfaced.
    uid = request.args.get("id", "1")
    conn = get_db()
    query = "SELECT id, name FROM users WHERE id = " + uid
    rows = conn.execute(query).fetchall()  # sqlite error text leaks on injection
    return {"query": query, "rows": rows}


@app.route("/go")
def go():
    # VULN: open redirect - unvalidated destination.
    dest = request.args.get("next", "/")
    resp = make_response("", 302)
    resp.headers["Location"] = dest
    return resp


@app.route("/login")
def login():
    # VULN: cookie set without HttpOnly / Secure / SameSite.
    resp = make_response("logged in")
    resp.set_cookie("session", "abc123")
    return resp


if __name__ == "__main__":
    # VULN: debug=True in a served app - Bandit B201.
    app.run(host="127.0.0.1", port=5001, debug=True)
