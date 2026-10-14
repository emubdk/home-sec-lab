"""Run the converted Sigma queries against lab-logs and store hits as alerts.

Every POLL_SECONDS the detector searches the last LOOKBACK of logs with each
rule's Lucene query. Each hit becomes an alert document in lab-alerts. The
alert id is sha1(rule id + event id), so overlapping search windows never
produce the same alert twice.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from homelab import es

DETECTIONS = Path(os.environ.get("DETECTIONS", "build/detections.json"))
LOOKBACK = os.environ.get("LOOKBACK", "15m")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "30"))

log = logging.getLogger("detector")


def alert_id(rule_id: str, event_id: str) -> str:
    return hashlib.sha1(f"{rule_id}:{event_id}".encode()).hexdigest()


def build_search(query: str, lookback: str, size: int = 500) -> dict:
    return {
        "size": size,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{lookback}"}}}],
            }
        },
    }


def make_alert(rule: dict, hit: dict) -> tuple[str, dict]:
    event = hit["_source"]
    return alert_id(rule["id"], hit["_id"]), {
        "@timestamp": datetime.now(UTC).isoformat(),
        "rule": {
            "id": rule["id"],
            "name": rule["title"],
            "level": rule["level"],
            "tags": rule["tags"],
        },
        "event": {"original_id": hit["_id"], "time": event.get("@timestamp")},
        "source": event.get("source", {}),
        "user": event.get("user", {}),
        "message": event.get("message", ""),
    }


def run_once(rules: list[dict], lookback: str = LOOKBACK) -> int:
    alerts = []
    for rule in rules:
        for hit in es.search(es.LOG_INDEX, build_search(rule["query"], lookback)):
            alerts.append(make_alert(rule, hit))
    result = es.bulk_index(es.ALERT_INDEX, alerts)
    new = [i["create"] for i in result["items"] if i["create"].get("result") == "created"]
    return len(new)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    rules = json.loads(DETECTIONS.read_text(encoding="utf-8"))
    log.info("loaded %d detections from %s", len(rules), DETECTIONS)
    es.wait_for_es()
    while True:
        count = run_once(rules)
        if count:
            log.info("%d new alerts", count)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
