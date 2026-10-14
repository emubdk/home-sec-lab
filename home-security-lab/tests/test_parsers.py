from homelab.parsers import parse_auth_line, parse_nginx_line

# Real lines captured from the lab's Ubuntu 24.04 victim.
INVALID_USER = "2026-10-14T22:22:30.228152+00:00 victim sshd[33]: Invalid user deploy from 172.18.0.7 port 49904"
FAILED_INVALID = (
    "2026-10-14T22:22:29.843311+00:00 victim sshd[31]: "
    "Failed password for invalid user pi from 172.18.0.7 port 49898 ssh2"
)
ACCEPTED = "Oct 14 22:30:01 victim sshd[77]: Accepted password for labuser from 10.0.0.5 port 50000 ssh2"
USERADD = (
    "2026-10-14T22:21:54.100233+00:00 victim useradd[41]: new user: name=backdoor, UID=1002, "
    "GID=1002, home=/home/backdoor, shell=/bin/sh, from=none"
)
SUDO = "2026-10-14T22:21:54.182074+00:00 victim sudo:  labuser : PWD=/ ; USER=root ; COMMAND=/bin/bash -c id"
NGINX = (
    '172.18.0.7 - - [14/Oct/2026:22:21:12 +0000] "GET /admin HTTP/1.1" 404 162 "-" '
    '"sqlmap/1.8#stable (https://sqlmap.org)"'
)


def test_ssh_invalid_user():
    doc = parse_auth_line(INVALID_USER)
    assert doc["event"] == {"dataset": "linux.auth", "action": "ssh_invalid_user", "outcome": "failure"}
    assert doc["user"]["name"] == "deploy"
    assert doc["source"]["ip"] == "172.18.0.7"
    assert doc["process"] == {"name": "sshd", "pid": 33}
    assert doc["@timestamp"].startswith("2026-10-14T22:22:30")


def test_ssh_failed_password_for_invalid_user():
    doc = parse_auth_line(FAILED_INVALID)
    assert doc["event"]["action"] == "ssh_login"
    assert doc["event"]["outcome"] == "failure"
    assert doc["user"]["name"] == "pi"


def test_bsd_syslog_timestamp_and_success():
    doc = parse_auth_line(ACCEPTED)
    assert doc["event"]["outcome"] == "success"
    assert doc["user"]["name"] == "labuser"
    assert "T22:30:01" in doc["@timestamp"]


def test_useradd():
    doc = parse_auth_line(USERADD)
    assert doc["event"]["action"] == "user_created"
    assert doc["user"]["name"] == "backdoor"


def test_sudo():
    doc = parse_auth_line(SUDO)
    assert doc["event"]["action"] == "sudo"
    assert doc["user"] == {"name": "labuser", "target": {"name": "root"}}
    assert doc["process"]["command_line"] == "/bin/bash -c id"


def test_unrelated_auth_line_keeps_message_only():
    doc = parse_auth_line("2026-10-14T22:21:54+00:00 victim su[50]: (to labuser) root on none")
    assert "action" not in doc["event"]
    assert doc["message"] == "(to labuser) root on none"


def test_garbage_returns_none():
    assert parse_auth_line("not a syslog line") is None
    assert parse_nginx_line("not an access log line") is None


def test_nginx_combined():
    doc = parse_nginx_line(NGINX)
    assert doc["source"]["ip"] == "172.18.0.7"
    assert doc["url"]["original"] == "/admin"
    assert doc["http"]["response"]["status_code"] == 404
    assert doc["user_agent"]["original"].startswith("sqlmap/")
    assert doc["@timestamp"] == "2026-10-14T22:21:12+00:00"
