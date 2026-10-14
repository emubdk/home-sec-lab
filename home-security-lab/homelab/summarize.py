"""Summarise recent alerts with a local LLM (Ollama).

Pulls the latest alerts from lab-alerts, groups them by rule and source IP,
and asks a local model for a short triage note. The model only sees the
compact grouped summary, never raw logs, which keeps the prompt small and
makes its claims easy to check against Kibana.

    python -m homelab.summarize --since 1h            # needs Ollama running
    python -m homelab.summarize --since 1h --dry-run  # only print the prompt
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import requests

from homelab import es

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

SYSTEM_PROMPT = """You are a SOC analyst writing a short triage note for a small home lab.
Use only the alert data you are given. Do not invent hosts, IPs, users or events.
Structure: 1) one-sentence overview, 2) likely attack story in time order,
3) what to check next (max 5 bullets), 4) severity: low / medium / high, with one reason.
If the data is not enough to conclude something, say so."""


def fetch_alerts(since: str, size: int = 1000) -> list[dict]:
    body = {
        "size": size,
        "sort": [{"event.time": "asc"}],
        "query": {"range": {"@timestamp": {"gte": f"now-{since}"}}},
    }
    return [hit["_source"] for hit in es.search(es.ALERT_INDEX, body)]


def group_alerts(alerts: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    users: dict[tuple, Counter] = defaultdict(Counter)
    for a in alerts:
        key = (a["rule"]["name"], a.get("source", {}).get("ip", "-"))
        g = groups.setdefault(
            key,
            {
                "rule": a["rule"]["name"],
                "level": a["rule"]["level"],
                "attack_tags": [t for t in a["rule"]["tags"] if t.startswith("attack.t")],
                "source_ip": key[1],
                "count": 0,
                "first_seen": a["event"]["time"],
                "last_seen": a["event"]["time"],
                "example": a.get("message", "")[:200],
            },
        )
        g["count"] += 1
        g["last_seen"] = a["event"]["time"]
        if name := a.get("user", {}).get("name"):
            users[key][name] += 1
    for key, g in groups.items():
        g["top_users"] = [u for u, _ in users[key].most_common(5)]
    return sorted(groups.values(), key=lambda g: g["first_seen"] or "")


def build_prompt(groups: list[dict]) -> str:
    return (
        "Alerts from the last period, grouped by rule and source IP (JSON):\n"
        + json.dumps(groups, indent=2)
        + "\n\nWrite the triage note."
    )


def ask_ollama(prompt: str, model: str = OLLAMA_MODEL) -> str:
    r = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        },
        timeout=600,
    )
    r.raise_for_status()
    return r.json()["response"].strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--since", default="1h", help="time window, e.g. 30m, 1h, 1d")
    parser.add_argument("--dry-run", action="store_true", help="print the prompt, do not call the LLM")
    parser.add_argument("--out-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()

    groups = group_alerts(fetch_alerts(args.since))
    if not groups:
        print(f"No alerts in the last {args.since}.")
        return
    prompt = build_prompt(groups)
    if args.dry_run:
        print(SYSTEM_PROMPT + "\n\n" + prompt)
        return

    note = ask_ollama(prompt)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"triage-{stamp}.md"
    out.write_text(
        f"# Alert triage {stamp} UTC\n\n_Model: {OLLAMA_MODEL}, window: {args.since}, "
        f"{sum(g['count'] for g in groups)} alerts in {len(groups)} groups._\n\n{note}\n",
        encoding="utf-8",
    )
    print(note)
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
