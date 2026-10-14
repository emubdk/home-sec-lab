"""Tail the victim's log files and ship parsed events to Elasticsearch.

A tiny stand-in for Filebeat. Each event gets a deterministic id
(sha1 of file path + byte offset), so restarting the shipper and reading
the files again from the start does not create duplicates.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path

from homelab import es
from homelab.parsers import PARSERS

LOG_DIR = Path(os.environ.get("LOG_DIR", "/logs"))
FILES = [LOG_DIR / "auth.log", LOG_DIR / "nginx" / "access.log"]
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "2"))

log = logging.getLogger("shipper")


def event_id(path: Path, offset: int) -> str:
    return hashlib.sha1(f"{path}:{offset}".encode()).hexdigest()


def read_new_lines(path: Path, offset: int) -> tuple[list[tuple[int, str]], int]:
    """Return complete lines after `offset` as (line_offset, text) and the new offset."""
    if not path.exists():
        return [], offset
    if path.stat().st_size < offset:  # file was truncated or rotated
        offset = 0
    out = []
    with path.open("rb") as fh:
        fh.seek(offset)
        while True:
            start = fh.tell()
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):  # nothing new / partial line
                break
            out.append((start, raw.decode("utf-8", errors="replace")))
            offset = fh.tell()
    return out, offset


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    es.wait_for_es()
    es.put_index_template(os.environ.get("TEMPLATE", "/app/elastic/index-template.json"))
    offsets = {path: 0 for path in FILES}

    while True:
        for path in FILES:
            lines, offsets[path] = read_new_lines(path, offsets[path])
            parse = PARSERS[path.name]
            batch = []
            for line_offset, line in lines:
                doc = parse(line)
                if doc:
                    batch.append((event_id(path, line_offset), doc))
            if batch:
                result = es.bulk_index(es.LOG_INDEX, batch)
                created = sum(1 for i in result["items"] if i["create"].get("result") == "created")
                log.info("%s: %d new events", path.name, created)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
