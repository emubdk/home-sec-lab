"""Very small Elasticsearch helper built on plain HTTP (requests).

The official client would work too; plain HTTP keeps every request visible,
which is the point of a learning lab.
"""

from __future__ import annotations

import json
import os
import time

import requests

ES_URL = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
LOG_INDEX = os.environ.get("LOG_INDEX", "lab-logs")
ALERT_INDEX = os.environ.get("ALERT_INDEX", "lab-alerts")


def wait_for_es(timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{ES_URL}/_cluster/health", timeout=5)
            if r.ok and r.json().get("status") in ("yellow", "green"):
                return
        except requests.RequestException:
            pass
        time.sleep(3)
    raise TimeoutError(f"Elasticsearch at {ES_URL} not ready after {timeout}s")


def put_index_template(path: str) -> None:
    with open(path, encoding="utf-8") as fh:
        body = json.load(fh)
    r = requests.put(f"{ES_URL}/_index_template/homelab", json=body, timeout=10)
    r.raise_for_status()


def bulk_index(index: str, docs: list[tuple[str, dict]]) -> dict:
    """Index (doc_id, doc) pairs with op_type=create, so re-sending is harmless."""
    if not docs:
        return {"errors": False, "items": []}
    lines = []
    for doc_id, doc in docs:
        lines.append(json.dumps({"create": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc))
    r = requests.post(
        f"{ES_URL}/_bulk",
        data="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def search(index: str, body: dict) -> list[dict]:
    r = requests.post(f"{ES_URL}/{index}/_search", json=body, timeout=30)
    if r.status_code == 404:  # index does not exist yet
        return []
    r.raise_for_status()
    return r.json()["hits"]["hits"]
