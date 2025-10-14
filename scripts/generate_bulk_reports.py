#!/usr/bin/env python3
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple
import os

ROOT = Path(__file__).resolve().parents[1]
ENGAGEMENTS_FILE = ROOT / "fixtures" / "engagements.json"
REPORTS_DIR = ROOT / "fixtures" / "reports"

random.seed()

REPORTER_MSGS = [
    "Added sanitized PoC variant to avoid external calls.",
    "Provided HAR with response headers and CSP for reference.",
    "Confirmed behavior on latest build; attaching version string.",
    "Shared curl one-liner to help reproduce quickly.",
    "Uploaded redacted logs illustrating server-side trace.",
    "Re-tested on staging after patch; please confirm rollout window.",
    "Included additional payload variant covering alternate render path.",
    "Verified fix in Firefox and Safari; Chrome previously tested.",
    "Provided list of affected endpoints discovered during retest.",
    "Shared minimal HTML page to demonstrate issue reliably.",
]
TRIAGER_MSGS = [
    "Acknowledged; starting reproduction using reporter steps.",
    "Escalated to owning team; fix under review.",
    "Hotfix validated in staging; awaiting reporter confirmation.",
    "Added unit/e2e tests to prevent regression.",
    "Monitoring dashboards show no further exploit attempts.",
    "Coordinating CSP rollout across affected surfaces.",
    "Prepared backfill job to sanitize historical renders at runtime.",
    "Released configuration change; verifying headers and cache behavior.",
    "Risk accepted temporarily while mitigation is rolled out.",
    "Closing soon pending reporter confirmation of fix.",
]
PM_MSGS = [
    "Severity reviewed; aligns with program policy.",
    "Coordinating comms to impacted internal teams.",
    "Tracking remediation in current sprint milestones.",
    "Policy updated; rollout checklist amended accordingly.",
    "Compliance ticket opened to verify org-wide adoption.",
    "Customer advisory drafted; will publish post-remediation.",
    "Added item to quarterly audit for similar configurations.",
    "KPI defined to measure rollout completion across services.",
    "No data exposure confirmed; incident record updated accordingly.",
    "Closing criteria documented; awaiting validation evidence.",
]

OFFSET_RE = re.compile(r"^(?:(\d+)d\s*)?(?:(\d+)h)?$")


def parse_offset(offset_str: str) -> Tuple[int, int]:
    m = OFFSET_RE.match(offset_str.strip())
    if not m:
        return 0, 0
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    return days, hours


def format_offset(days: int, hours: int) -> str:
    if days and hours:
        return f"{days}d {hours}h"
    if days:
        return f"{days}d"
    return f"{hours}h"


def next_offsets(existing: List[Dict[str, str]], count: int) -> List[str]:
    last_days, last_hours = 0, 0
    for c in existing or []:
        d, h = parse_offset(c.get("offset", "0h"))
        if (d, h) > (last_days, last_hours):
            last_days, last_hours = d, h
    cur_days, cur_hours = last_days, last_hours
    res = []
    for _ in range(count):
        delta_h = random.randint(2, 36)
        cur_hours += delta_h
        while cur_hours >= 24:
            cur_days += 1
            cur_hours -= 24
        res.append(format_offset(cur_days, cur_hours))
    return res


@dataclass
class Engagement:
    id: str
    type: str  # Bug Bounty | Vulnerability Disclosure | Pentest
    in_scope: List[str]
    org_slug: str
    prefix: str  # e.g., ams, gvb, kead


VULN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "key": "stored_xss_admin",
        "title": "Stored XSS in admin-facing render path",
        "summary": (
            "User-provided content is persisted and rendered via an unsafe primitive in an admin-facing view, "
            "leading to JavaScript execution in a privileged context."
        ),
        "path": ["/admin/queue", "/admin/items", "/console/queue"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N",
        "score": 8.1,
        "owasp": "A03:2021 Injection",
        "mitigation": [
            "HTML-encode untrusted data before DOM insertion.",
            "Adopt strict CSP and remove inline/event handlers.",
        ],
        "steps": [
            "Create object with payload in a display field (e.g., subject/memo).",
            "Open the admin list/detail view and observe execution.",
        ],
        "poc_req": "GET {path}",
        "poc_resp": "<td class=\"field\"><svg onload=alert(1)></svg></td>",
    },
    {
        "key": "idor_download",
        "title": "Insecure Direct Object Reference in download endpoint",
        "summary": (
            "The download endpoint authorizes by session only and does not verify ownership, allowing enumeration of other users' resources."
        ),
        "path": ["/api/v2/documents/", "/api/documents/", "/statements/"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.7,
        "owasp": "A01:2021 Broken Access Control",
        "mitigation": [
            "Enforce object ownership checks and use opaque identifiers.",
            "Add rate limiting and monitoring of enumeration patterns.",
        ],
        "steps": [
            "Request your own resource by ID.",
            "Increment/decrement ID and observe cross-account access.",
        ],
        "poc_req": "GET {path}12345",
        "poc_resp": "%PDF-1.7 ... (content of a different user) ...",
    },
    {
        "key": "ssrf_import",
        "title": "SSRF via URL import fetch",
        "summary": (
            "A server-side fetch accepts attacker-controlled URLs without allowlist or private range blocking, enabling access to internal metadata/services."
        ),
        "path": ["/api/import", "/import", "/fetch"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "score": 7.7,
        "owasp": "A10:2021 Server-Side Request Forgery (SSRF)",
        "mitigation": [
            "Allowlist destinations and deny link-local/private ranges.",
            "Use an egress proxy with DNS pinning and strict timeouts.",
        ],
        "steps": [
            "POST url=http://169.254.169.254/latest/meta-data/ to the import endpoint.",
            "Observe internal metadata persisted in the created resource.",
        ],
        "poc_req": 'POST {path} {{"url": "http://169.254.169.254/latest/meta-data/"}}',
        "poc_resp": "Study created with internal metadata",
    },
    {
        "key": "cors_creds_wildcard",
        "title": "CORS misconfiguration allows credentialed cross-origin reads",
        "summary": (
            "The API returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true, allowing any origin to read responses with cookies."
        ),
        "path": ["/api/me", "/v2/me", "/profile"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "score": 8.6,
        "owasp": "A05:2021 Security Misconfiguration",
        "mitigation": [
            "Echo only trusted origins when credentials are allowed.",
            "Disallow wildcard with credentials.",
        ],
        "steps": [
            "Host malicious page and fetch protected endpoint with credentials.",
            "Observe successful JSON read in attacker origin.",
        ],
        "poc_req": 'fetch("{path}", {{credentials: "include"}})',
        "poc_resp": '{"email":"victim@example.foo"}',
    },
    {
        "key": "open_redirect",
        "title": "Open redirect via returnUrl parameter",
        "summary": (
            "The login flow accepts external URLs in the returnUrl parameter, enabling phishing chains and potential token leakage."
        ),
        "path": ["/login?returnUrl=https://evil.foo", "/auth/callback?next=https://evil.foo"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "score": 4.8,
        "owasp": "A01:2021 Broken Access Control",
        "mitigation": [
            "Restrict redirects to same-origin paths via allowlist.",
            "Strip fragments and enforce scheme/host checks.",
        ],
        "steps": [
            "Open login with external returnUrl.",
            "After authentication, observe 302 to attacker domain.",
        ],
        "poc_req": "GET {path}",
        "poc_resp": "302 Location: https://evil.foo",
    },
    {
        "key": "csv_injection",
        "title": "CSV injection in export enables formula execution",
        "summary": (
            "CSV export writes unescaped values; cells starting with =,+,-,@ are treated as formulas by spreadsheet apps, enabling exfiltration when opened."
        ),
        "path": ["/export?type=records", "/export"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
        "score": 3.9,
        "owasp": "A03:2021 Injection",
        "mitigation": [
            "Escape cells starting with =,+,-,@ by prefixing a space or apostrophe.",
            "Offer XLSX format by default.",
        ],
        "steps": [
            "Create a record with a field value beginning with a formula string.",
            "Export CSV and open in Excel/LibreOffice; observe formula execution.",
        ],
        "poc_req": "GET {path}",
        "poc_resp": '=HYPERLINK("https://evil.foo","click")',
    },
    {
        "key": "metrics_exposed",
        "title": "Prometheus metrics exposed with sensitive labels",
        "summary": (
            "The /metrics endpoint is publicly accessible and includes identifiers in labels, exposing sensitive metadata."
        ),
        "path": ["/metrics"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 3.7,
        "owasp": "A09:2021 Security Logging and Monitoring Failures",
        "mitigation": [
            "Restrict metrics behind auth/VPN and scrub PHI/PII from labels.",
        ],
        "steps": [
            "GET /metrics and observe labels with identifiers.",
        ],
        "poc_req": "GET {path}",
        "poc_resp": 'service_count{user_id="U123"} 1',
    },
    {
        "key": "path_traversal",
        "title": "Directory traversal in log download endpoint",
        "summary": (
            "A filename parameter is concatenated into a path without proper normalization, allowing traversal to system files."
        ),
        "path": ["/support/logs?file=../../../../etc/passwd", "/logs?file=../../../../etc/passwd"],
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.1,
        "owasp": "A01:2021 Broken Access Control",
        "mitigation": [
            "Resolve within an allowlisted directory and use file handles not raw paths.",
        ],
        "steps": [
            "Request with file parameter using ../ traversal to system file.",
            "Observe returned file content.",
        ],
        "poc_req": "GET {path}",
        "poc_resp": "root:x:0:0:root:/root:/bin/bash",
    },
]


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def pick_scope_path(in_scope: List[str], template_paths: List[str]) -> Tuple[str, str]:
    base = random.choice(in_scope)
    suffix = random.choice(template_paths)
    if suffix.startswith("/"):
        return base + suffix, suffix
    return base + "/" + suffix, "/" + suffix


def gen_reporter_block(eng: Engagement, prefix: str, report_id_num: int, tmpl: Dict[str, Any]) -> Dict[str, Any]:
    _, path_only = pick_scope_path(eng.in_scope, tmpl["path"])
    app_versions = [
        "API 2.3", "API v2", "Portal 2025.09", "Auth 2025.09", "Web 2025.09",
        "Mobile 2025.09", "Console 2025.09", "Service 1.8",
    ]
    browsers = ["Chrome 126", "Firefox 128", "Safari 17", "curl 8.7.1", "k6 0.49"]
    oss = ["Ubuntu 24.04", "Windows 11", "macOS 14.5", "Linux"]
    roles = ["unauthenticated", "authenticated user", "admin", "support agent", "radiologist", "citizen"]

    score = tmpl["score"] + random.uniform(-0.3, 0.3)
    score = max(0.0, min(10.0, round(score, 1)))

    reporter: Dict[str, Any] = {
        "id": f"{prefix}_report_{report_id_num:03d}",
        "title": tmpl["title"],
        "summary": tmpl["summary"],
        "context": {
            "target": random.choice(eng.in_scope) + path_only,
            "environment": {
                "browser": random.choice(browsers),
                "os": random.choice(oss),
                "app_version": random.choice(app_versions),
                "user_role": random.choice(roles),
            },
        },
        "steps_to_reproduce": tmpl["steps"],
        "proof_of_concept": {
            "http_request": tmpl["poc_req"].format(path=path_only),
            "http_response_excerpt": tmpl.get("poc_resp", ""),
        },
        "impact": {
            "description": tmpl["summary"],
            "cvss_vector": tmpl["vector"],
            "cvss_seeverity": cvss_severity(score),
            "cvss_score": score,
            "owasp25_category": tmpl["owasp"],
        },
        "mitigation": tmpl["mitigation"],
        "comments": [],
    }

    initial_msgs = [
        "Initial submission with PoC and reproduction steps.",
        "Initial report filed with screenshots and logs.",
        "Minimal PoC attached; scope limited to in-scope assets.",
    ]
    reporter["comments"].append({"offset": "0h", "message": random.choice(initial_msgs)})
    to_add = random.randint(0, 10)
    for off, msg in zip(next_offsets(reporter["comments"], to_add),
                        [random.choice(REPORTER_MSGS) for _ in range(to_add)]):
        reporter["comments"].append({"offset": off, "message": msg})

    return reporter


def gen_triager_block(tmpl: Dict[str, Any], reporter_score: float) -> Dict[str, Any]:
    tri_score = max(0.0, min(10.0, round(reporter_score - random.uniform(0.1, 0.8), 1)))
    triager: Dict[str, Any] = {
        "status": "accepted",
        "impact": {
            "cvss_vector": tmpl["vector"],
            "cvss_seeverity": cvss_severity(tri_score),
            "cvss_score": tri_score,
            "owasp25_category": tmpl["owasp"],
        },
        "timeline": [],
        "comments": [],
    }
    tl_count = random.randint(0, 2)
    if tl_count:
        triager["timeline"] = [
            {"offset": next_offsets([], 1)[0], "event": "Fix deployed to staging; awaiting reporter confirmation."}
        ]
        if tl_count == 2:
            triager["timeline"].append(
                {"offset": next_offsets(triager["timeline"], 1)[0], "event": "Tests added to prevent regression."}
            )
    to_add = random.randint(0, 10)
    for off, msg in zip(next_offsets([], to_add), [random.choice(TRIAGER_MSGS) for _ in range(to_add)]):
        triager["comments"].append({"offset": off, "message": msg})
    return triager


def gen_pm_block(tmpl: Dict[str, Any], tri_score: float) -> Dict[str, Any]:
    pm_score = max(0.0, min(10.0, round(tri_score - random.uniform(-0.2, 0.4), 1)))
    pm: Dict[str, Any] = {
        "impact": {
            "cvss_vector": tmpl["vector"],
            "cvss_seeverity": cvss_severity(pm_score),
            "cvss_score": pm_score,
            "owasp25_category": tmpl["owasp"],
        },
        "feedback": [
            "Align remediation with program policy; update checklists accordingly.",
        ],
        "comments": [],
    }
    to_add = random.randint(0, 10)
    for off, msg in zip(next_offsets([], to_add), [random.choice(PM_MSGS) for _ in range(to_add)]):
        pm["comments"].append({"offset": off, "message": msg})
    return pm


PREFIX_ID_RE = re.compile(r"^[a-z]{2,6}(?:-[a-z]+)?$")
REPORTER_ID_RE = re.compile(r"^([a-z]{2,6})_report_(\d+)$")


def load_json(path: Path):
    return json.loads(path.read_text())


def dump_json(path: Path, data: Any):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def build_prefix_to_file() -> Dict[str, Path]:
    mapping: Dict[str, Path] = {}
    for p in sorted(REPORTS_DIR.glob("*.json")):
        try:
            data = load_json(p)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            if not isinstance(entry, dict):
                continue
            eid = entry.get("engagement_id")
            if isinstance(eid, str) and "-" in eid:
                prefix = eid.split("-", 1)[0]
                if PREFIX_ID_RE.match(prefix):
                    mapping.setdefault(prefix, p)
            rep = entry.get("reporter", {})
            if isinstance(rep, dict):
                rid = rep.get("id")
                if isinstance(rid, str):
                    m = REPORTER_ID_RE.match(rid)
                    if m:
                        mapping.setdefault(m.group(1), p)
    return mapping


def build_existing_id_counters() -> Dict[str, int]:
    counters: Dict[str, int] = {}
    for p in sorted(REPORTS_DIR.glob("*.json")):
        try:
            data = load_json(p)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for entry in data:
            rep = entry.get("reporter", {})
            if isinstance(rep, dict):
                rid = rep.get("id")
                if isinstance(rid, str):
                    m = REPORTER_ID_RE.match(rid)
                    if m:
                        prefix = m.group(1)
                        num = int(m.group(2))
                        counters[prefix] = max(counters.get(prefix, 0), num)
    return counters


def load_engagements() -> List[Engagement]:
    raw = load_json(ENGAGEMENTS_FILE)
    engagements: List[Engagement] = []
    if not isinstance(raw, list):
        return engagements
    for org in raw:
        org_slug = org.get("organization_slug", "")
        for e in org.get("engagements", []) or []:
            eid = e.get("id")
            e_type = e.get("type")
            in_scope = e.get("in_scope", [])
            if not (isinstance(eid, str) and isinstance(in_scope, list) and in_scope):
                continue
            prefix = eid.split("-", 1)[0]
            engagements.append(Engagement(id=eid, type=e_type, in_scope=in_scope, org_slug=org_slug, prefix=prefix))
    return engagements


def pick_template_for(eng: Engagement) -> Dict[str, Any]:
    candidates = VULN_TEMPLATES
    if eng.type == "Vulnerability Disclosure":
        weights = [2, 2, 1, 2, 2, 2, 2, 1]
    elif eng.type == "Pentest":
        weights = [2, 3, 3, 2, 1, 1, 1, 3]
    else:  # Bug Bounty
        weights = [3, 3, 3, 3, 1, 2, 2, 2]
    idx = random.choices(range(len(candidates)), weights=weights, k=1)[0]
    return candidates[idx]


def ensure_file_array(path: Path) -> List[Dict[str, Any]]:
    try:
        data = load_json(path)
    except Exception:
        data = []
    if not isinstance(data, list):
        data = []
    return data


def main() -> int:
    if not REPORTS_DIR.exists():
        print(f"No reports dir found at {REPORTS_DIR}")
        return 1

    engagements = load_engagements()
    if not engagements:
        print("No engagements found; aborting")
        return 1

    prefix_to_file = build_prefix_to_file()
    id_counters = build_existing_id_counters()

    total_added = 0
    per_file_added: Dict[Path, int] = {}

    engagements_sorted = sorted(engagements, key=lambda e: e.prefix)

    # Optional filter: process only specific prefixes, e.g. ONLY_PREFIXES="abc,xyz"
    only_prefixes_raw = os.environ.get("ONLY_PREFIXES", "").strip()
    only_prefixes: List[str] = [p.strip() for p in only_prefixes_raw.split(",") if p.strip()]
    if only_prefixes:
        only_set = set(only_prefixes)
        engagements_sorted = [e for e in engagements_sorted if e.prefix in only_set]

    for eng in engagements_sorted:
        prefix = eng.prefix
        target_file = prefix_to_file.get(prefix)
        if not target_file:
            # Create a new file for this organization's reports based on org slug
            safe_name = eng.org_slug.replace('-', '_') + "_reports.json"
            target_file = REPORTS_DIR / safe_name
            if not target_file.exists():
                target_file.write_text("[]\n")
            # Note: not updating prefix_to_file mapping; using target_file variable directly

        existing_list = ensure_file_array(target_file)
        next_id = id_counters.get(prefix, 0) + 1

        to_add = random.randint(15, 50)
        for _ in range(to_add):
            tmpl = pick_template_for(eng)
            reporter_block = gen_reporter_block(eng, prefix, next_id, tmpl)
            triager_block = gen_triager_block(tmpl, reporter_block["impact"]["cvss_score"])
            pm_block = gen_pm_block(tmpl, triager_block["impact"]["cvss_score"])

            new_entry = {
                "engagement_id": eng.id,
                "reporter": reporter_block,
                "triager": triager_block,
                "program_manager": pm_block,
            }
            existing_list.append(new_entry)

            next_id += 1
            total_added += 1
            per_file_added[target_file] = per_file_added.get(target_file, 0) + 1

        dump_json(target_file, existing_list)
        id_counters[prefix] = next_id - 1
        print(f"Added {to_add:2d} reports for engagement {eng.id} into {target_file.name}")

    print("Done.")
    for p, n in sorted(per_file_added.items()):
        print(f"  {p.name}: +{n}")
    print(f"TOTAL added: {total_added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
