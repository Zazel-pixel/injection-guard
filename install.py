#!/usr/bin/env python3
"""Install the guard once and point every agent's hook at that one copy.

There used to be two copies, one per agent, and they drifted: a fix applied
to one left the other agent interrupted on the same line. Now:

  ~/.local/share/injection-guard/injection_guard.py   the only installed copy
  ~/.claude/hooks/<name>  ->  symlink to it            (if ~/.claude exists)
  ~/.codex/hooks/<name>   ->  symlink to it            (if ~/.codex exists)

The installed file is a COPY of this checkout, not a link to it: editing the
repository or switching branches must not change the live guard.

    python3 install.py           install or update, back up what it replaces
    python3 install.py --check   exit 1 unless every hook is the installed copy
                                 and that copy matches this checkout
    python3 install.py --config  print the hook settings to add by hand

Existing hook files are kept as <name>.bak-YYYY-MM-DD before being replaced.
Settings files are never edited.
"""
import argparse
import hashlib
import os
import shutil
import sys
from datetime import date
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "injection_guard.py"
# The name the hooks are registered under. The first one is what existing
# setups use; both are linked when present, the second one otherwise.
LEGACY_NAME = "prompt-injection-guard.py"
NAME = "injection_guard.py"
AGENTS = (".claude", ".codex")


def installed_copy(home):
    xdg = os.environ.get("XDG_DATA_HOME") if home == Path.home() else None
    data = Path(xdg) if xdg else home / ".local" / "share"
    return data / "injection-guard" / NAME


def hook_paths(home):
    """Hook files to manage: the ones that exist, else the default name."""
    paths = []
    for agent in AGENTS:
        hooks = home / agent / "hooks"
        if not (home / agent).is_dir():
            continue
        found = [hooks / n for n in (LEGACY_NAME, NAME)
                 if (hooks / n).exists() or (hooks / n).is_symlink()]
        paths += found or [hooks / NAME]
    return paths


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def backup(path):
    stem = f"{path.name}.bak-{date.today().isoformat()}"
    target, k = path.with_name(stem), 1
    while target.exists():
        target, k = path.with_name(f"{stem}-{k}"), k + 1
    path.rename(target)
    return target


def install(home):
    target = installed_copy(home)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    shutil.copy2(SOURCE, tmp)
    tmp.chmod(0o755)
    os.replace(tmp, target)  # a running hook never sees a half-written file
    print(f"installed  {target}")
    for path in hook_paths(home):
        if path.is_symlink() and path.resolve() == target.resolve():
            print(f"ok         {path}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            print(f"backed up  {backup(path)}")
        path.symlink_to(target)
        print(f"linked     {path} -> {target}")
    return check(home)


def check(home):
    target = installed_copy(home)
    problems = []
    if not target.exists():
        problems.append(f"{target} is missing: run install.py")
    elif digest(target) != digest(SOURCE):
        problems.append(f"{target} differs from {SOURCE}: run install.py")
    paths = [p for p in hook_paths(home) if p.exists() or p.is_symlink()]
    if not paths:
        problems.append("no hook file found for any agent")
    for path in paths:
        if not path.is_symlink():
            problems.append(f"{path} is a separate copy, not a link: it will drift")
        elif path.resolve() != target.resolve():
            problems.append(f"{path} points to {path.resolve()}, not {target}")
    for p in problems:
        print(f"PROBLEM    {p}")
    if not problems:
        print(f"ok: {len(paths)} hook(s) run the installed copy, "
              f"identical to this checkout")
    return 1 if problems else 0


def print_config(home):
    print(f"""Claude Code, ~/.claude/settings.json, under "hooks":
  "PreToolUse":  [{{"matcher": "Bash", "hooks": [{{"type": "command",
      "command": "python3 {home}/.claude/hooks/{NAME}", "timeout": 10}}]}}],
  "PostToolUse": [{{"matcher": "WebFetch|WebSearch|Read|Grep|Bash|Task|mcp__.*",
      "hooks": [{{"type": "command",
      "command": "python3 {home}/.claude/hooks/{NAME}", "timeout": 10}}]}}]

Codex, ~/.codex/hooks.json: the same two entries, with
      "command": "python3 '{home}/.codex/hooks/{NAME}'"
""")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--config", action="store_true")
    ap.add_argument("--home", type=Path, default=Path.home(), help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.config:
        return print_config(args.home)
    return check(args.home) if args.check else install(args.home)


if __name__ == "__main__":
    sys.exit(main())
