# Detections

Each rule is a normal [Sigma](https://sigmahq.io) rule. `homelab/sigma_convert.py`
converts it with pySigma's Elasticsearch backend and the lab pipeline in
`sigma/pipelines/homelab.yml`. The converted queries (output of
`python -m homelab.sigma_convert`) look like this:

| Rule | Lucene query |
| --- | --- |
| SSH login attempt for non-existent user | `event.dataset:linux.auth AND event.action:ssh_invalid_user` |
| New local user account created | `event.dataset:linux.auth AND event.action:user_created` |
| Root shell started via sudo | `event.dataset:linux.auth AND (event.action:sudo AND user.target.name:root AND (process.command_line:(\/bin\/bash* OR ...)))` |
| Web request with known scanner user-agent | `event.dataset:nginx.access AND (user_agent.original:(*nmap* OR *nikto* OR *sqlmap* OR ...))` |
| Path traversal attempt in web request | `event.dataset:nginx.access AND (url.original:(*..\/* OR *..%2f* OR *%2e%2e* OR ...))` |

## Result of one run of `scripts/simulate.sh`

| Rule | Alerts | Why this number |
| --- | --- | --- |
| SSH login attempt for non-existent user | 5 | 6 user names are tried, but `ubuntu` exists in the Ubuntu image, so sshd logs "Failed password for ubuntu" instead of "Invalid user". |
| Web request with known scanner user-agent | 7 | 3 requests from `attack.sh` plus 4 requests nmap's `-sV` probes send with the "Nmap Scripting Engine" user agent. The exact nmap count can vary. |
| Path traversal attempt in web request | 2 | One raw `../` path (nginx answers 400) and one URL-encoded `..%2f` parameter. |
| New local user account created | 1 | `useradd` in `simulate.sh`. |
| Root shell started via sudo | 1 | `sudo /bin/bash -c id` in `simulate.sh`. |

## Known gaps (what these rules do not catch)

- **SSH guessing against existing users** is not covered by the "invalid user" rule. That needs a
  threshold (many `event.action:ssh_login AND event.outcome:failure` from one IP), which is a
  correlation, not a single-event rule. Planned as the next rule.
- **Scanner user agents** are trivial to change (`nmap --script-args http.useragent=...`,
  `sqlmap --random-agent`). The rule only catches default configurations.
- **Path traversal** that is double-encoded (`%252e%252e`) or uses other encodings is missed.
- **Root shell via sudo** misses `sudo -i`, `sudo su -` and shells such as `zsh`. Matching on the
  command line is a weak signal; auditd/execve logging would be the better source.
- **User creation** with tools other than `useradd` (e.g. editing `/etc/passwd` directly) is not
  logged in `auth.log` at all.

Writing these down is part of the exercise: a detection is only useful if you
know where it stops working.
