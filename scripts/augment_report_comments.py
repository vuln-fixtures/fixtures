#!/usr/bin/env python3
import json
import random
import re
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "fixtures" / "reports"

random.seed()

# Pools of plausible messages per role
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
    "Shared minimal HTML page to demonstrate issue reliably."
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
    "Closing soon pending reporter confirmation of fix."
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
    "Closing criteria documented; awaiting validation evidence."
]

OFFSET_RE = re.compile(r"^(?:(\d+)d\s*)?(?:(\d+)h)?$")

def parse_offset(offset_str: str) -> timedelta:
    m = OFFSET_RE.match(offset_str.strip())
    if not m:
        return timedelta(0)
    days = int(m.group(1) or 0)
    hours = int(m.group(2) or 0)
    return timedelta(days=days, hours=hours)

def format_offset(td: timedelta) -> str:
    days = td.days
    hours = td.seconds // 3600
    if days and hours:
        return f"{days}d {hours}h"
    if days:
        return f"{days}d"
    return f"{hours}h"

def next_offsets(existing:list, count:int) -> list:
    # Determine last offset and then add 2-36 hours between comments randomly
    last = timedelta(0)
    for c in existing:
        try:
            cur = parse_offset(c.get("offset", "0h"))
        except Exception:
            cur = timedelta(0)
        if cur > last:
            last = cur
    offsets = []
    cur = last
    for _ in range(count):
        delta_hours = random.randint(2, 36)
        cur += timedelta(hours=delta_hours)
        offsets.append(format_offset(cur))
    return offsets

def pick_msgs(pool, n):
    # Allow repeats if n > len(pool)
    return [random.choice(pool) for _ in range(n)]

def augment_comments(obj: dict) -> bool:
    changed = False
    # For each role section, decide how many comments to add (0..10)
    for role, pool in (("reporter", REPORTER_MSGS), ("triager", TRIAGER_MSGS), ("program_manager", PM_MSGS)):
        role_obj = obj.get(role)
        if not role_obj:
            continue
        # Initialize comments array if missing
        comments = role_obj.get("comments")
        if comments is None:
            comments = []
            role_obj["comments"] = comments
        # Decide how many to add
        to_add = random.randint(0, 10)
        if to_add == 0:
            continue
        new_offsets = next_offsets(comments, to_add)
        new_msgs = pick_msgs(pool, to_add)
        for off, msg in zip(new_offsets, new_msgs):
            comments.append({"offset": off, "message": msg})
            changed = True
    return changed


def process_file(path: Path) -> bool:
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"SKIP {path.name}: failed to read/parse: {e}")
        return False

    changed_any = False

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                if augment_comments(entry):
                    changed_any = True
    elif isinstance(data, dict):
        if augment_comments(data):
            changed_any = True
    else:
        print(f"SKIP {path.name}: unexpected JSON type {type(data)}")
        return False

    if changed_any:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print(f"UPDATED {path}")
    else:
        print(f"NOCHANGE {path}")
    return changed_any


def main():
    if not REPORTS_DIR.exists():
        print(f"No reports dir found at {REPORTS_DIR}")
        return 1
    changed = 0
    for p in sorted(REPORTS_DIR.glob("*.json")):
        if process_file(p):
            changed += 1
    print(f"Done. Files changed: {changed}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
