#!/usr/bin/env python3
"""Measure the guard's detection rules on labelled text.

Each document goes through the guard's scan() alone: no hook, no log, no
state. An *alert* is a finding the agent would actually be shown.

  attack documents   detection rate    = share with at least one alert
  benign documents   false-alarm rate  = share with at least one alert

Usage:
  python3 evaluate.py                     # committed corpus, repo guard
  python3 evaluate.py --guard OLD.py      # same corpus, another version
  python3 evaluate.py --json OUT.json     # machine-readable, for diffs
  python3 evaluate.py --transcripts DIR   # also replay local Claude Code
                                          # session logs (private: nothing is
                                          # written, excerpts are redacted)

Rule: no change to a pattern without these numbers before and after.
"""
import argparse
import collections
import importlib.util
import json
import random
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
DEFAULT_GUARD = ROOT / "prompt-injection-guard.py"
CORPUS = ROOT / "corpus"
SELF_GLOBS = ("*.py", "*.md", "tools/*.py", "tests/*.py", "docs/*.md")
# The tools the PostToolUse hook is registered for (settings.json matcher).
HOOKED = re.compile(r"WebFetch|WebSearch|Read|Grep|Bash|Task|Agent|mcp__.*")
# How each source is split in the report. deepset and Lakera keep their
# upstream train/test splits apart: patterns are tuned by reading train
# examples only, so the test rows stay an honest held-out measure.
GROUP_BY = {"deepset": ("lang", "variant"), "injecagent": ("variant",),
            "lakera": ("variant",)}


def load_guard(path):
    spec = importlib.util.spec_from_file_location("guard", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def alerts(guard, text):
    """Findings the agent would be shown (all of them, for older guards)."""
    shown = getattr(guard, "is_shown", None)
    return [f for f in guard.scan(text) if shown is None or shown(f)]


def load_corpus():
    docs = []
    for path in sorted(CORPUS.rglob("*.jsonl")):
        with path.open(encoding="utf-8") as fh:
            docs += [json.loads(line) for line in fh if line.strip()]
    # The repository's own files are benign documents too: the guard must stay
    # quiet when an agent reads its source, its tests or its documentation.
    for pattern in SELF_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            docs.append({"id": f"self-{path.relative_to(ROOT)}", "source": "self",
                         "variant": "", "label": "benign", "lang": "en",
                         "text": path.read_text(encoding="utf-8")})
    return docs


def group_of(doc):
    keys = GROUP_BY.get(doc["source"], ())
    return "/".join([doc["source"]] + [doc[k] for k in keys])


def evaluate(guard, docs):
    groups = collections.OrderedDict()
    patterns = collections.defaultdict(lambda: {"attack": 0, "benign": 0})
    benign_alerts = []
    for doc in docs:
        found = alerts(guard, doc["text"])
        # Keyed by label too: a source can hold both attacks and benign text.
        g = groups.setdefault(f"{doc['label']}:{group_of(doc)}",
                              {"label": doc["label"], "docs": 0, "alerted": 0})
        g["docs"] += 1
        if found:
            g["alerted"] += 1
        for name in sorted({f[0] for f in found}):
            patterns[name][doc["label"]] += 1
        if found and doc["label"] == "benign":
            benign_alerts.append({"id": doc["id"],
                                  "patterns": sorted({f[0] for f in found})})
    return {"groups": groups, "patterns": dict(sorted(patterns.items())),
            "benign_alerts": benign_alerts}


def totals(groups, label, sources=None):
    docs = alerted = 0
    for name, g in groups.items():
        source = name.split(":", 1)[1].split("/")[0]
        if g["label"] == label and (sources is None or source in sources):
            docs += g["docs"]
            alerted += g["alerted"]
    return docs, alerted


def pct(k, n):
    return f"{100 * k / n:5.1f}%" if n else "    -"


def print_report(res):
    for label, title in (("attack", "Detection (attack documents)"),
                         ("benign", "False alarms (benign documents)")):
        print(f"\n{title}")
        print(f"  {'group':<24}{'docs':>7}{'alerted':>9}{'rate':>8}")
        for name, g in res["groups"].items():
            if g["label"] == label:
                print(f"  {name.split(':', 1)[1]:<24}{g['docs']:>7}{g['alerted']:>9}"
                      f"{pct(g['alerted'], g['docs']):>8}")
        n, k = totals(res["groups"], label)
        print(f"  {'all':<24}{n:>7}{k:>9}{pct(k, n):>8}")

    print("\nPer pattern (documents with an alert from it)")
    print(f"  {'pattern':<30}{'attack':>8}{'benign':>8}")
    for name, c in res["patterns"].items():
        print(f"  {name:<30}{c['attack']:>8}{c['benign']:>8}")

    if res["benign_alerts"]:
        print("\nBenign documents that alerted")
        for item in res["benign_alerts"]:
            print(f"  {item['id']:<44}{', '.join(item['patterns'])}")


# --- Replay of real tool outputs ---------------------------------------------

_ASSIGNED = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|passphrase|authorization)"
    r"\b(\s*[:=]\s*|\s+)(\S{4,})")
_TOKEN = re.compile(
    r"\b(?:sk-|sk_|ghp_|gho_|ghs_|github_pat_|xox[abposr]-|AKIA|ASIA|AIza|"
    r"glpat-|hf_)[A-Za-z0-9_\-]{8,}|\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-.]+|"
    r"\b[A-Za-z0-9+/=_\-]{32,}")


def redact(text):
    """Mask anything that looks like a credential before it is printed."""
    text = _ASSIGNED.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)
    return _TOKEN.sub("[REDACTED]", text)


def tool_outputs(dirs):
    """Yield (tool, session, day, response) for each tool call, once."""
    seen = set()
    for root in dirs:
        for path in sorted(Path(root).expanduser().rglob("*.jsonl")):
            names = {}
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "tool_use" not in line:  # also matches tool_use_id
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    msg = rec.get("message")
                    content = msg.get("content") if isinstance(msg, dict) else None
                    if not isinstance(content, list):
                        continue
                    blocks = [b for b in content if isinstance(b, dict)]
                    for b in blocks:
                        if b.get("type") == "tool_use":
                            names[b.get("id")] = b.get("name", "?")
                    results = [b for b in blocks if b.get("type") == "tool_result"]
                    for b in results:
                        tid = b.get("tool_use_id")
                        if tid in seen:  # resumed and forked sessions repeat history
                            continue
                        seen.add(tid)
                        # The hook receives the structured result, not the text
                        # sent to the model; the log keeps it as toolUseResult.
                        body = (rec["toolUseResult"]
                                if len(results) == 1 and "toolUseResult" in rec
                                else b.get("content"))
                        yield (names.get(tid, "?"), rec.get("sessionId", path.stem),
                               str(rec.get("timestamp", ""))[:10], body)


def replay(guard, dirs, samples, seed=7):
    rng = random.Random(seed)
    stats = {"outputs": 0, "skipped": 0, "alerted": 0, "alerts": 0,
             "alerts_dedup": 0, "first_day": None, "last_day": None}
    by_pattern = collections.Counter()
    by_tool = collections.Counter()
    by_month = collections.Counter()
    seen_keys = set()
    reservoir = collections.defaultdict(list)
    counts = collections.Counter()
    for tool, session, day, body in tool_outputs(dirs):
        if not HOOKED.fullmatch(tool):
            stats["skipped"] += 1
            continue
        stats["outputs"] += 1
        if day:
            stats["first_day"] = min(stats["first_day"] or day, day)
            stats["last_day"] = max(stats["last_day"] or day, day)
        text = guard.flatten(body)
        if not text.strip():
            continue
        found = alerts(guard, text)
        if not found:
            continue
        stats["alerted"] += 1
        by_tool[tool.split("__")[0] if tool.startswith("mcp__") else tool] += 1
        by_month[day[:7]] += 1
        for name, severity, frag in found:
            stats["alerts"] += 1
            by_pattern[name] += 1
            key = (session, name, frag)
            if key not in seen_keys:
                seen_keys.add(key)
                stats["alerts_dedup"] += 1
            counts[name] += 1
            item = (day, tool, redact(frag))
            if len(reservoir[name]) < samples:
                reservoir[name].append(item)
            else:
                j = rng.randrange(counts[name])
                if j < samples:
                    reservoir[name][j] = item
    return {"stats": stats, "by_pattern": dict(by_pattern.most_common()),
            "by_tool": dict(by_tool.most_common(8)),
            "by_month": dict(sorted(by_month.items())),
            "samples": {k: v for k, v in sorted(reservoir.items())}}


def print_replay(rep):
    s = rep["stats"]
    print(f"\nReplay of real tool outputs ({s['first_day']} to {s['last_day']})")
    print(f"  tool outputs scanned      {s['outputs']:>8}"
          f"   (not hooked, skipped: {s['skipped']})")
    print(f"  outputs with an alert     {s['alerted']:>8}  {pct(s['alerted'], s['outputs'])}")
    print(f"  alerts                    {s['alerts']:>8}")
    print(f"  alerts, once per session  {s['alerts_dedup']:>8}")
    print("  by pattern: " + ", ".join(f"{k} {v}" for k, v in rep["by_pattern"].items()))
    print("  by tool:    " + ", ".join(f"{k} {v}" for k, v in rep["by_tool"].items()))
    print("  by month:   " + ", ".join(f"{k} {v}" for k, v in rep["by_month"].items()))
    for name, items in rep["samples"].items():
        print(f"\n  samples: {name}")
        for day, tool, frag in items:
            print(f"    {day} {tool[:28]:<28} {frag}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--guard", type=Path, default=DEFAULT_GUARD)
    ap.add_argument("--json", type=Path, metavar="OUT")
    ap.add_argument("--transcripts", type=Path, nargs="*", metavar="DIR")
    ap.add_argument("--samples", type=int, default=0,
                    help="redacted excerpts to print per pattern (replay only)")
    args = ap.parse_args()

    guard = load_guard(args.guard)
    print(f"Guard: {args.guard}")
    res = evaluate(guard, load_corpus())
    print_report(res)
    out = {"guard": str(args.guard), **res}
    if args.transcripts:
        rep = replay(guard, args.transcripts, args.samples)
        print_replay(rep)
        out["replay"] = {k: v for k, v in rep.items() if k != "samples"}
    if args.json:
        args.json.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n",
                             encoding="utf-8")


if __name__ == "__main__":
    main()
