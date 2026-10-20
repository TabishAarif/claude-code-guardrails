#!/usr/bin/env python3
"""Tests for the free Command Guard Lite and Secret Blocker.  Run: python3 tests/test_lite.py"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(os.path.dirname(HERE), "hooks")


def run(script, event):
    p = subprocess.run([sys.executable, os.path.join(HOOKS, script)], input=json.dumps(event),
                       capture_output=True, text=True, timeout=30)
    if p.returncode == 2:
        return "BLOCK"
    if p.returncode != 0:
        return "CRASH"
    if p.stdout.strip():
        try:
            if json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask":
                return "ASK"
        except Exception:  # noqa: BLE001
            return "CRASH"
    return "ALLOW"


def bash(cmd):
    return run("command_guard_lite.py", {"tool_name": "Bash", "tool_input": {"command": cmd}})


CASES = [
    # must be BLOCKED
    ("rm -rf /", "BLOCK"), ("rm -rf ~", "BLOCK"), ("rm -rf $HOME", "BLOCK"), ("sudo rm -rf /etc", "BLOCK"),
    ("rm -rf .", "BLOCK"), ("rm -rf *", "BLOCK"), ("rm -fr ../", "BLOCK"), ("rm -r -f /", "BLOCK"),
    ("bash -c 'rm -rf /'", "BLOCK"), ("npm test && rm -rf /", "BLOCK"),
    ("git push --force origin main", "BLOCK"), ("git push -f origin master", "BLOCK"),
    ("git push origin +main", "BLOCK"), ("git push --force-with-lease origin main", "BLOCK"),
    ("psql -c 'DROP TABLE users'", "BLOCK"), ("psql -c 'DROP DATABASE app'", "BLOCK"),
    ("mysql -e 'truncate orders'", "BLOCK"), ("psql -c 'DELETE FROM users'", "BLOCK"),
    (":(){ :|:& };:", "BLOCK"), ("mkfs.ext4 /dev/sda1", "BLOCK"), ("dd if=/dev/zero of=/dev/sda", "BLOCK"),
    # must ASK
    ("prisma migrate reset", "ASK"), ("npx prisma migrate reset --force", "ASK"), ("supabase db reset", "ASK"),
    ("terraform destroy", "ASK"), ("git reset --hard HEAD~2", "ASK"),
    # must ALLOW (false-positive checks)
    ("rm -rf node_modules", "ALLOW"), ("rm -rf .next dist build", "ALLOW"), ("rm -rf ./build", "ALLOW"),
    ("rm file.txt", "ALLOW"), ("git push", "ALLOW"), ("git push origin feature/login", "ALLOW"),
    ("git push --force origin feature/login", "ALLOW"), ("git push --force-with-lease origin feature/login", "ALLOW"),
    ("git status", "ALLOW"), ("git reset --soft HEAD~1", "ALLOW"), ("prisma migrate dev", "ALLOW"),
    ("terraform plan", "ALLOW"), ("psql -c 'SELECT * FROM users'", "ALLOW"),
    ("psql -c 'DELETE FROM users WHERE id = 1'", "ALLOW"),
    ('grep "DROP TABLE" schema.sql', "ALLOW"), ('echo "rm -rf /"', "ALLOW"),
    ("git commit -m 'document rm -rf node_modules'", "ALLOW"),
    ("npm install", "ALLOW"), ("npm run build", "ALLOW"), ("pytest -q", "ALLOW"), ("ls -la", "ALLOW"),
]

FAKE_KEY = "sk_live_" + "a1B2c3D4e5" * 3


def main():
    passed, failed = 0, []
    for cmd, want in CASES:
        got = bash(cmd)
        if got == want:
            passed += 1
        else:
            failed.append("command guard: %r -> %s (wanted %s)" % (cmd, got, want))
    secret_cases = [
        ("Write", {"file_path": "src/a.ts", "content": "const k = '%s'" % FAKE_KEY}, "BLOCK"),
        ("Write", {"file_path": "src/a.ts", "content": "const k = process.env.STRIPE_KEY"}, "ALLOW"),
        ("Write", {"file_path": ".env", "content": "K=%s" % FAKE_KEY}, "ALLOW"),
        ("Edit", {"file_path": "src/a.ts", "old_string": "x", "new_string": "'%s'" % FAKE_KEY}, "BLOCK"),
    ]
    for tool, ti, want in secret_cases:
        got = run("secret_blocker.py", {"tool_name": tool, "tool_input": ti})
        if got == want:
            passed += 1
        else:
            failed.append("secret blocker: %s -> %s (wanted %s)" % (tool, got, want))
    for bad in ("not json", ""):
        for script in ("command_guard_lite.py", "secret_blocker.py"):
            p = subprocess.run([sys.executable, os.path.join(HOOKS, script)], input=bad, capture_output=True, text=True)
            if p.returncode == 0:
                passed += 1
            else:
                failed.append("%s crashed on bad input %r" % (script, bad))
    print("\n".join(failed))
    print("%d/%d checks passed" % (passed, passed + len(failed)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
