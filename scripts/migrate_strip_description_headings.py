#!/usr/bin/env python3
import json, os, re
REPORTS_DIR = os.path.join(os.getcwd(), "fixtures", "reports")

HEADING_RE = re.compile(r"^\s*#{1,6}\s*Description\s*\n+", re.I)
ALT_RE = re.compile(r"^\s*##\s*[Dd]escription\s*\n+", re.I)


def strip_heading(text: str) -> str:
    if not isinstance(text, str):
        return text
    # Remove leading '## Description' or variations
    new = HEADING_RE.sub("", text)
    new = ALT_RE.sub("", new)
    return new


def process_file(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    changed = 0

    def fix_report(r):
        nonlocal changed
        rep = r.get("reporter") if isinstance(r, dict) else None
        if not isinstance(rep, dict):
            return
        desc = rep.get("description")
        new_desc = strip_heading(desc) if isinstance(desc, str) else desc
        if isinstance(new_desc, str) and new_desc != desc:
            rep["description"] = new_desc
            changed += 1

    if isinstance(data, list):
        for r in data:
            fix_report(r)
    elif isinstance(data, dict):
        fix_report(data)

    if changed:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
    return changed


def main():
    total = 0
    files = [os.path.join(REPORTS_DIR, p) for p in os.listdir(REPORTS_DIR) if p.endswith('.json')]
    for fp in sorted(files):
        c = process_file(fp)
        print(f"{os.path.basename(fp)}: stripped {c}")
        total += c
    print(f"TOTAL stripped: {total}")

if __name__ == "__main__":
    main()
