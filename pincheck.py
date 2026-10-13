#!/usr/bin/env python3
"""
pincheck — find the unpinned actions in your GitHub workflows.

The Zod incident (Oct 2026) showed the repo is the attack surface: malicious
commits were pushed straight to colinhacks/zod on GitHub. npm-side scanning
held the line that time. But your CI is the other half of the supply chain —
a floating `uses: actions/checkout@v5` re-resolves every run, and a hijacked
tag (the exact play used against tj-actions and others) quietly turns your
pipeline into someone else's runner.

pincheck scans .github/workflows/*.yml|*.yaml, extracts every `uses:` ref,
and grades how many of them are pinned to an immutable commit SHA.

Usage:
    python3 pincheck.py [repo_root]
    python3 pincheck.py --strict ./myrepo

Stdlib only. No install needed.
"""
import os
import re
import sys
from collections import defaultdict

USES_RE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"\s#]+)['\"]?", re.IGNORECASE | re.MULTILINE
)
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA = re.compile(r"^[0-9a-fA-F]{7,39}$")
DOCKER = re.compile(r"^docker://", re.IGNORECASE)
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$", re.IGNORECASE)


def classify(ref):
    """Return (grade_letter, label) for a uses: ref's pinned part."""
    if ref.startswith("./") or ref.startswith("../"):
        return ("-", "local action, nothing to pin")
    if DOCKER.match(ref):
        if DIGEST.search(ref):
            return ("A", "pinned by image digest")
        return ("C", "docker image by tag, digest preferred")
    if "@" not in ref:
        return ("F", "no ref at all — resolves to default branch")
    repo, _, pin = ref.rpartition("@")
    if FULL_SHA.match(pin):
        return ("A", "pinned to immutable commit SHA")
    if SHORT_SHA.match(pin):
        return ("B", "short SHA — immutable but collides under adversarial pressure")
    low = pin.lower()
    if low in ("main", "master", "head", "latest", "stable", "edge") or low.startswith("heads/"):
        return ("F", "floating branch — re-resolves on every run")
    return ("C", f"mutable tag '{pin}' — retaggable by the action's publisher")


def find_workflows(root):
    wf = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf):
        return []
    out = []
    for name in sorted(os.listdir(wf)):
        if name.endswith((".yml", ".yaml")):
            out.append(os.path.join(wf, name))
    return out


def audit(root):
    rows = []
    files = find_workflows(root)
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        # drop full-line comments so we don't audit commented-out uses:
        text = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().startswith("#")
        )
        for m in USES_RE.finditer(text):
            ref = m.group(1).strip()
            grade, label = classify(ref)
            rows.append({
                "file": os.path.relpath(path, root),
                "ref": ref,
                "grade": grade,
                "label": label,
                "line": text[: m.start()].count("\n") + 1,
            })
    return files, rows


def grade_all(rows):
    auditable = [r for r in rows if r["grade"] != "-"]
    if not auditable:
        return "A", "no external actions to audit"
    pct = sum(1 for r in rows if r["grade"] == "A") / len(auditable) * 100
    if pct == 100:
        return "A", "every action pinned to a commit SHA — hijack-proof"
    if pct >= 75:
        return "B", "mostly pinned — a few mutable refs left"
    if pct >= 50:
        return "C", "half-floating — a hijacked tag would reach you"
    return "D", "floating CI — your pipeline re-resolves trust on every run"


RANK = {"F": 0, "C": 1, "B": 2, "A": 3, "-": 4}


def main(argv):
    strict = False
    args = [a for a in argv[1:] if a != "--strict"]
    if len(args) != len(argv) - 1:
        strict = True
    root = os.path.abspath(args[0]) if args else os.getcwd()

    files, rows = audit(root)
    if not files:
        print(f"pincheck: no workflow files found under {root}/.github/workflows")
        return 2
    grade, note = grade_all(rows)

    counts = defaultdict(int)
    for r in rows:
        counts[r["grade"]] += 1

    print(f"pincheck: auditing {len(rows)} action refs in {len(files)} workflow files ...\n")
    print("  SHA-pinned (A)      :", counts["A"])
    print("  short-SHA (B)       :", counts["B"])
    print("  mutable tag (C)     :", counts["C"])
    print("  floating branch (F) :", counts["F"])
    print("  local (-)           :", counts["-"])
    print(f"\n  CI trust grade        : {grade} — {note}")

    worst = sorted([r for r in rows if r["grade"] in ("F", "C")],
                   key=lambda r: (RANK[r["grade"]], r["file"]))
    if worst:
        print("\nUnpinned refs (worst first):")
        for r in worst:
            print(f"  [{r['grade']}] {r['file']}:{r['line']}  {r['ref']}")
            print(f"       ↳ {r['label']}")

    # fix-it hint for the worst offender
    if worst:
        r = worst[0]
        print(f"\nFix: pin to the action's current commit SHA, e.g.")
        print(f"  uses: {r['ref'].split('@')[0]}@<40-char-sha>  # {r['ref'].split('@')[-1]}")
        print("  (keep the tag in a trailing comment so humans still see the version)")

    if strict:
        sys.exit(0 if grade == "A" else 1)
    return 0


if __name__ == "__main__":
    main(sys.argv)
