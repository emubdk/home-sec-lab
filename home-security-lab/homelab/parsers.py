"""Turn raw log lines into small ECS-style documents.

Only the handful of log formats the lab produces are supported:
- /var/log/auth.log written by rsyslog (sshd, sudo, useradd)
- /var/log/nginx/access.log in nginx's default "combined" format

Field names follow the Elastic Common Schema (ECS) where possible, so the
Sigma pipeline in sigma/pipelines/homelab.yml can map rule fields onto them.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

# rsyslog on Debian 12 writes RFC 3339 timestamps:
#   2026-10-14T22:12:28.123456+00:00 victim sshd[42]: Invalid user admin from 172.20.0.5 port 50022
# Older systems use the traditional BSD format:
#   Oct 14 22:12:28 victim sshd[42]: ...
SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

SSH_INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+) port \d+")
SSH_FAILED_RE = re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
SSH_ACCEPTED_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
USERADD_RE = re.compile(r"^new user: name=(?P<user>[^,]+),")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+) : .*USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")

NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def _syslog_time(raw: str) -> str:
    if raw[:4].isdigit():
        return datetime.fromisoformat(raw).astimezone(UTC).isoformat()
    # BSD syslog has no year; assume the current one.
    parsed = datetime.strptime(f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S")
    return parsed.replace(tzinfo=UTC).isoformat()


def parse_auth_line(line: str) -> dict | None:
    """Parse one auth.log line. Returns None for lines that are not syslog."""
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None

    doc: dict = {
        "@timestamp": _syslog_time(m["ts"]),
        "event": {"dataset": "linux.auth"},
        "host": {"name": m["host"]},
        "process": {"name": m["proc"]},
        "message": m["msg"],
    }
    if m["pid"]:
        doc["process"]["pid"] = int(m["pid"])

    msg = m["msg"]
    if m["proc"] == "sshd":
        if hit := SSH_INVALID_USER_RE.match(msg):
            doc["event"].update(action="ssh_invalid_user", outcome="failure")
            doc["user"] = {"name": hit["user"]}
            doc["source"] = {"ip": hit["ip"]}
        elif hit := SSH_FAILED_RE.match(msg):
            doc["event"].update(action="ssh_login", outcome="failure")
            doc["user"] = {"name": hit["user"]}
            doc["source"] = {"ip": hit["ip"]}
        elif hit := SSH_ACCEPTED_RE.match(msg):
            doc["event"].update(action="ssh_login", outcome="success")
            doc["user"] = {"name": hit["user"]}
            doc["source"] = {"ip": hit["ip"]}
    elif m["proc"] == "useradd":
        if hit := USERADD_RE.match(msg):
            doc["event"].update(action="user_created", outcome="success")
            doc["user"] = {"name": hit["user"]}
    elif m["proc"] == "sudo":
        if hit := SUDO_RE.match(msg):
            doc["event"].update(action="sudo", outcome="success")
            doc["user"] = {"name": hit["user"], "target": {"name": hit["target"]}}
            doc["process"]["command_line"] = hit["cmd"].strip()

    return doc


def parse_nginx_line(line: str) -> dict | None:
    """Parse one nginx access.log line in the default "combined" format."""
    m = NGINX_RE.match(line.strip())
    if not m:
        return None

    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    return {
        "@timestamp": ts.isoformat(),
        "event": {"dataset": "nginx.access"},
        "source": {"ip": m["ip"]},
        "http": {
            "request": {"method": m["method"]},
            "response": {"status_code": int(m["status"])},
        },
        "url": {"original": m["url"]},
        "user_agent": {"original": m["ua"]},
        "message": line.strip(),
    }


PARSERS = {
    "auth.log": parse_auth_line,
    "access.log": parse_nginx_line,
}
