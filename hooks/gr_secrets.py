"""
Claude Code Guardrails Kit - secret detection.

Finds real credentials in text. Tuned for the leaks that actually hit
AI-built apps: Supabase service_role keys, Stripe live keys, OpenAI and
Anthropic keys, cloud keys, database URLs with passwords, private keys.

Keys that are MEANT to be public are ignored on purpose:
Stripe pk_live_/pk_test_, Supabase anon keys and sb_publishable_ keys,
Stripe test secret keys (sk_test_), placeholders like "your-key-here".

Add the text  guardrails:allow-secret  on a line to skip it (for example a
fake key in a test fixture).
"""

import base64
import json
import re

ALLOW_MARKER = "guardrails:allow-secret"

PLACEHOLDER_HINTS = (
    "your", "xxxx", "example", "changeme", "change-me", "placeholder", "dummy",
    "redacted", "<", ">", "${", "{{", "process.env", "os.environ", "getenv",
    "env(", "import.meta.env", "******", "...", "todo", "insert", "replace",
)

# (name, regex, severity)  severity: high -> block on commit, medium -> ask
PATTERNS = [
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"), "high"),
    ("AWS access key ID", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws_?secret_?access_?key\s*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"), "high"),
    ("Anthropic API key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}"), "high"),
    ("OpenAI API key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"), "high"),
    ("OpenRouter API key", re.compile(r"sk-or-v1-[A-Za-z0-9]{32,}"), "high"),
    ("OpenAI API key (legacy)", re.compile(r"(?<![A-Za-z0-9_\-])sk-[A-Za-z0-9]{32,}(?![A-Za-z0-9_\-])"), "high"),
    ("Stripe live secret key", re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{20,}"), "high"),
    ("Stripe webhook secret", re.compile(r"whsec_[0-9A-Za-z]{24,}"), "high"),
    ("Supabase secret key", re.compile(r"sb_secret_[0-9A-Za-z_\-]{20,}"), "high"),
    ("GitHub token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"), "high"),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{50,}"), "high"),
    ("GitLab token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "high"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "high"),
    ("SendGrid API key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "high"),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{34,}"), "high"),
    ("Google Cloud service account key", re.compile(r"\"type\"\s*:\s*\"service_account\""), "high"),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}"), "high"),
    ("Resend API key", re.compile(r"(?<![A-Za-z0-9])re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}"), "medium"),
    ("Twilio API key", re.compile(r"(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])"), "medium"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "medium"),
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

DB_URL_RE = re.compile(
    r"(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://"
    r"(?P<user>[^\s:/@'\"]+):(?P<pw>[^\s@'\"]+)@(?P<host>[^\s/:'\"?]+)"
)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "db", "postgres", "mysql", "redis", "mongo", "host.docker.internal", "::1"}

GENERIC_ASSIGN_RE = re.compile(
    r"(?i)\b(?:secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|password|passwd)\b"
    r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{16,})[\"']"
)

# Public-by-design env names that hold secrets = classic AI-app leak.
PUBLIC_PREFIX_SECRET_RE = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)"
    r"[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|SK_LIVE|STRIPE_SECRET|DATABASE_URL|DB_URL|DB_PASSWORD|OPENAI_API_KEY|ANTHROPIC_API_KEY|WEBHOOK_SECRET)[A-Z0-9_]*\b"
)


def _looks_placeholder(value):
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def _b64json(segment):
    pad = "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment + pad).decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return None


def mask(value):
    value = value.strip()
    if len(value) <= 10:
        return value[:2] + "..."
    return value[:6] + "..." + value[-3:]


def scan_text(text, filename=None):
    """Return a list of findings: dicts with name, severity, line, preview."""
    findings = []
    if not text:
        return findings
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        seen_spans = []

        def add(name, severity, match_text, span):
            for s in seen_spans:
                if span[0] < s[1] and s[0] < span[1]:
                    return
            seen_spans.append(span)
            findings.append({
                "name": name,
                "severity": severity,
                "line": lineno,
                "file": filename,
                "preview": mask(match_text),
            })

        for name, regex, severity in PATTERNS:
            for m in regex.finditer(line):
                token = m.group(0)
                if _looks_placeholder(token):
                    continue
                add(name, severity, token, m.span())

        for m in JWT_RE.finditer(line):
            payload = _b64json(m.group(0).split(".")[1])
            if isinstance(payload, dict) and payload.get("role") == "service_role":
                add("Supabase service_role key (full database access)", "high", m.group(0), m.span())

        for m in DB_URL_RE.finditer(line):
            pw, host = m.group("pw"), m.group("host").lower()
            if host in LOCAL_HOSTS or _looks_placeholder(pw) or pw in ("password", "pass", "postgres", "root", "secret"):
                continue
            add("Database URL with a password", "high", m.group(0), m.span())

        for m in GENERIC_ASSIGN_RE.finditer(line):
            value = m.group(1)
            if _looks_placeholder(value):
                continue
            # skip obvious non-secrets: pure words, paths, URLs without creds
            if re.fullmatch(r"[a-z_\-]+", value) or value.startswith(("http://", "https://", "/", "./")):
                continue
            add("Hard-coded secret value", "medium", value, m.span(1))

        for m in PUBLIC_PREFIX_SECRET_RE.finditer(line):
            add(
                "Secret in a PUBLIC env variable ({}) - it will ship to every browser".format(m.group(0)),
                "high", m.group(0), m.span(),
            )
    return findings


def summarize(findings, limit=8):
    lines = []
    for f in findings[:limit]:
        where = "{}:{}".format(f["file"], f["line"]) if f.get("file") else "line {}".format(f["line"])
        lines.append("{} at {} ({})".format(f["name"], where, f["preview"]))
    if len(findings) > limit:
        lines.append("...and {} more".format(len(findings) - limit))
    return lines
