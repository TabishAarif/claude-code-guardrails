#!/usr/bin/env python3
"""
Command Guard Lite for Claude Code (free sample from the Guardrails Kit).

Stops the few commands that cause the most expensive accidents:
  BLOCKED:  rm -rf on /, your home folder, or the whole project (. * ..)
            git push --force to main / master / production
            DROP DATABASE / DROP TABLE / TRUNCATE / DELETE with no WHERE (in a SQL client)
            fork bombs, disk wipes (mkfs, dd to a disk)
  ASKS:     prisma migrate reset, supabase db reset, drizzle-kit push --force,
            terraform destroy, git reset --hard

Everyday commands pass: rm -rf node_modules, git push to a feature branch,
git push --force-with-lease on your own branch, grep "DROP TABLE" file.sql ...

It reads command text, so it is a seatbelt, not a vault. Keep backups.
Python 3.8+, standard library only, no network, nothing is logged or sent.
"""
import json
import re
import shlex
import sys

PROTECTED_BRANCHES = {"main", "master", "production", "prod", "release", "live"}
SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongosh", "mongo", "cockroach", "usql", "pgcli", "mycli"}
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "xargs"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
TEXT_ONLY = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "cat", "less", "more", "head", "tail",
             "wc", "diff", "man", "which", "type", "ls", "find", "sed", "awk", "git-log"}
WIDE_TARGETS = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "${HOME}", "${HOME}/", "$HOME/*", ".", "./", "./*",
                "*", "..", "../", "../*", "/home", "/usr", "/etc", "/var", "/bin", "/boot", "/lib", "/opt", "/root", "/sys"}
FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
SQL_DESTROY = re.compile(r"\b(drop\s+(database|schema|table)|truncate\s+(table\s+)?\w)", re.I)
SQL_DELETE_ALL = re.compile(r"\bdelete\s+from\s+[\w.\"`\[\]]+\s*(;|$|[\"'])", re.I)


def tokens(command):
    """Split into simple commands, respecting quotes. Returns a list of argv lists."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = command.split()
    segments, current = [], []
    for t in toks:
        if t and set(t) <= set(";&|\n()"):
            if current:
                segments.append(current)
            current = []
        else:
            current.append(t)
    if current:
        segments.append(current)
    return segments


def strip_wrappers(argv):
    argv = list(argv)
    while argv:
        head = argv[0]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head) or head.split("/")[-1] in WRAPPERS:
            argv.pop(0)
            while argv and argv[0].startswith("-") and head.split("/")[-1] in WRAPPERS:
                argv.pop(0)
            continue
        break
    return argv


def program(argv):
    return argv[0].split("/")[-1].lower() if argv else ""


def check_segment(argv, command_text, verdicts):
    argv = strip_wrappers(argv)
    if not argv:
        return
    prog = program(argv)
    args = argv[1:]

    # recurse into: bash -c "..."
    if prog in SHELLS and "-c" in args:
        i = args.index("-c")
        if i + 1 < len(args):
            for seg in tokens(args[i + 1]):
                check_segment(seg, args[i + 1], verdicts)
        return

    if prog in TEXT_ONLY and prog not in ("find", "sed"):
        return

    if prog == "rm":
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
        recursive = "r" in flags.lower() or "--recursive" in args
        if recursive:
            targets = [a for a in args if not a.startswith("-")]
            for t in targets:
                if t.rstrip() in WIDE_TARGETS or re.fullmatch(r"(\$HOME|~|\$\{HOME\})/?\*?", t):
                    verdicts.append(("block", "rm -r on '%s' would delete your whole project, home folder or system" % t))

    elif prog == "find" and "-delete" in args and any(a in ("/", "~", "$HOME") for a in args):
        verdicts.append(("block", "find ... -delete from the root or home folder"))

    elif prog == "git":
        sub_i = 0
        while sub_i < len(args) and args[sub_i].startswith("-"):
            sub_i += 2 if args[sub_i] in ("-C", "-c") else 1
        sub = args[sub_i] if sub_i < len(args) else ""
        rest = args[sub_i + 1:]
        if sub == "push":
            force = any(a in ("--force", "-f") or (re.fullmatch(r"-[a-zA-Z]+", a) and "f" in a) for a in rest)
            lease = any(a.startswith("--force-with-lease") for a in rest)
            refs = [a for a in rest if not a.startswith("-")][1:]
            plus = [r for r in refs if r.startswith("+")]
            targets = [r.lstrip("+").split(":")[-1].replace("refs/heads/", "").lower() for r in refs]
            hits = any(t in PROTECTED_BRANCHES for t in targets)
            if (force or lease or plus) and (hits or "--all" in rest or "--mirror" in rest):
                verdicts.append(("block", "force-push to a protected branch (%s) rewrites shared history" % ", ".join(t for t in targets if t in PROTECTED_BRANCHES) or "all branches"))
            elif (force or lease or plus) and not refs:
                verdicts.append(("ask", "force-push without a named branch: it may rewrite main. Name the branch."))
        elif sub == "reset" and "--hard" in rest:
            verdicts.append(("ask", "git reset --hard throws away uncommitted work"))

    elif prog in SQL_CLIENTS:
        if SQL_DESTROY.search(command_text) or SQL_DELETE_ALL.search(command_text):
            verdicts.append(("block", "destructive SQL (DROP / TRUNCATE / DELETE with no WHERE)"))

    elif prog in ("mkfs", "mkfs.ext4", "mkfs.ntfs", "mkfs.vfat") or prog.startswith("mkfs."):
        verdicts.append(("block", "mkfs formats a disk"))

    elif prog == "dd" and any(re.match(r"of=/dev/(sd|nvme|hd|disk)", a) for a in args):
        verdicts.append(("block", "dd writing straight to a disk"))

    else:
        joined = " ".join(argv)
        if re.search(r"\bprisma\s+migrate\s+reset\b", joined):
            verdicts.append(("ask", "prisma migrate reset drops and recreates the database"))
        elif re.search(r"\bsupabase\s+db\s+reset\b", joined):
            verdicts.append(("ask", "supabase db reset wipes the local database"))
        elif re.search(r"\bdrizzle-kit\s+push\b.*--force", joined):
            verdicts.append(("ask", "drizzle-kit push --force can drop tables"))
        elif re.search(r"\b(terraform|tofu)\s+destroy\b", joined):
            verdicts.append(("ask", "terraform destroy deletes real infrastructure"))


def analyse(command):
    verdicts = []
    if FORK_BOMB.search(command):
        verdicts.append(("block", "fork bomb"))
    for seg in tokens(command):
        check_segment(seg, command, verdicts)
    return verdicts


def main():
    try:
        data = json.load(sys.stdin)
        if data.get("tool_name") not in ("Bash", "PowerShell", None):
            return
        command = (data.get("tool_input") or {}).get("command") or ""
        verdicts = analyse(command)
    except Exception:  # noqa: BLE001 - never break the user's session because of a bug here
        return
    if not verdicts:
        return
    blocks = [m for lvl, m in verdicts if lvl == "block"]
    if blocks:
        sys.stderr.write("BLOCKED by Command Guard Lite:\n- " + "\n- ".join(blocks) +
                         "\nDo not work around this. Explain to the user what you wanted to do and let them run it themselves.\n")
        sys.exit(2)
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                  "permissionDecisionReason": "Please confirm:\n- " + "\n- ".join(m for _l, m in verdicts)}}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
