#!/usr/bin/env python3
"""Summarise the guard's log, then list the excerpts to judge them by hand.

The log keeps one JSON line per event, with a short redacted excerpt for each
finding: enough to decide afterwards whether an alert was a real injection or
a false alarm, which the old log (pattern names only) could not tell.

    python3 tools/audit_log.py                    # summary of the default log
    python3 tools/audit_log.py --list             # every excerpt, newest last
    python3 tools/audit_log.py --list --shown     # only what the agent saw
    python3 tools/audit_log.py --log PATH --since 2026-11-01
"""
import argparse
import collections
import json
import os
from pathlib import Path

DEFAULT_LOG = (Path(os.environ.get("INJECTION_GUARD_DIR")
                    or Path.home() / ".claude" / "hooks") / "injection-guard.jsonl")


def records(log, since=""):
    for path in (log.with_name(log.name + ".1"), log):
        if not path.exists():
            continue
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("ts", "") >= since:
                    yield rec


def status(finding):
    if finding.get("shown"):
        return "shown"
    return "low" if finding.get("severity") == "low" else "repeat"


def summary(recs):
    events = collections.Counter(r.get("event", "?") for r in recs)
    table = collections.defaultdict(collections.Counter)
    agents = collections.Counter()
    for r in recs:
        if r.get("event") != "post":
            continue
        agents[r.get("agent", "?")] += 1
        for f in r.get("findings", []):
            table[f.get("name", "?")][status(f)] += 1
    days = sorted(r.get("ts", "")[:10] for r in recs)
    print(f"Log from {days[0] if days else '-'} to {days[-1] if days else '-'}")
    print("  events: " + ", ".join(f"{k} {v}" for k, v in events.most_common()))
    print("  agents: " + ", ".join(f"{k} {v}" for k, v in agents.most_common()))
    print(f"\n  {'pattern':<30}{'shown':>7}{'repeat':>8}{'low':>6}")
    for name, c in sorted(table.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"  {name:<30}{c['shown']:>7}{c['repeat']:>8}{c['low']:>6}")


def listing(recs, shown_only):
    for r in recs:
        if r.get("event") == "pre-block":
            print(f"{r.get('ts', '')}  BLOCK  {r.get('command', '')}")
            continue
        for f in r.get("findings", []):
            if shown_only and not f.get("shown"):
                continue
            print(f"{r.get('ts', '')}  {status(f):<6} {f.get('name', '?'):<26} "
                  f"{r.get('tool', '?')[:20]:<20} {f.get('excerpt', '')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--since", default="", help="ISO date, e.g. 2026-11-01")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--shown", action="store_true", help="with --list")
    args = ap.parse_args()
    recs = list(records(args.log, args.since))
    if args.list:
        listing(recs, args.shown)
    else:
        summary(recs)


if __name__ == "__main__":
    main()
