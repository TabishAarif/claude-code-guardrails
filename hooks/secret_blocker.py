#!/usr/bin/env python3
"""
Secret Blocker for Claude Code (free sample from the Guardrails Kit).

Blocks two things:
  1. Claude writing a real API key / token / password URL into a source file.
  2. `git commit` when the staged changes contain a real secret.
Public keys (Stripe pk_, Supabase anon/publishable) are not flagged.
Put `guardrails:allow-secret` in a comment on a line to allow it on purpose.

Wire it up as a PreToolUse hook (see README.md). Python 3.8+, standard library only.
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gr_secrets as secrets  # noqa: E402


def block(findings, where):
    lines = "\n    ".join(secrets.summarize(findings))
    sys.stderr.write("BLOCKED: real-looking secret in {}:\n    {}\n"
                     "Move it to .env and read it with process.env / os.environ. "
                     "Do not work around this block; ask the user.\n".format(where, lines))
    sys.exit(2)


def main():
    try:
        data = json.load(sys.stdin)
        tool = data.get("tool_name", "")
        ti = data.get("tool_input") or {}
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            path = ti.get("file_path") or ti.get("notebook_path") or ""
            base = os.path.basename(path)
            if base.startswith(".env"):
                return
            text = ti.get("content") or ti.get("new_string") or ti.get("new_source") or ""
            if tool == "MultiEdit":
                text = "\n".join((e or {}).get("new_string") or "" for e in ti.get("edits") or [])
            high = [f for f in secrets.scan_text(text, base) if f["severity"] == "high"]
            if high:
                block(high, base or "a file")
        elif tool == "Bash" and re.search(r"\bgit\s+commit\b", ti.get("command") or ""):
            diff = subprocess.run(["git", "diff", "--staged", "--no-color", "-U0"], capture_output=True,
                                  text=True, errors="replace", timeout=20, cwd=data.get("cwd") or None).stdout
            added = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
            high = [f for f in secrets.scan_text(added, "staged changes") if f["severity"] == "high"]
            if high:
                block(high, "your staged changes")
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001  - never break the user's session on a bug
        return


if __name__ == "__main__":
    main()
