"""Convert the Sigma rules in sigma/rules/ into Elasticsearch Lucene queries.

Uses pySigma with the Elasticsearch backend and the lab's own processing
pipeline (sigma/pipelines/homelab.yml). The result is written to
detections.json, which the detector loads.

    python -m homelab.sigma_convert --rules sigma/rules --out build/detections.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline


def convert(rules_dir: Path, pipeline_file: Path) -> list[dict]:
    pipeline = ProcessingPipeline.from_yaml(pipeline_file.read_text(encoding="utf-8"))
    backend = LuceneBackend(processing_pipeline=pipeline)
    rules = SigmaCollection.load_ruleset([str(rules_dir)])

    detections = []
    for rule in rules.rules:
        queries = backend.convert_rule(rule)
        detections.append(
            {
                "id": str(rule.id),
                "title": rule.title,
                "level": rule.level.name.lower() if rule.level else "informational",
                "tags": [str(tag) for tag in rule.tags],
                "description": (rule.description or "").strip(),
                "query": queries[0] if len(queries) == 1 else " OR ".join(f"({q})" for q in queries),
            }
        )
    return sorted(detections, key=lambda d: d["title"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", type=Path, default=Path("sigma/rules"))
    parser.add_argument("--pipeline", type=Path, default=Path("sigma/pipelines/homelab.yml"))
    parser.add_argument("--out", type=Path, default=Path("build/detections.json"))
    args = parser.parse_args()

    detections = convert(args.rules, args.pipeline)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(detections, indent=2), encoding="utf-8")
    for d in detections:
        print(f"[{d['level']:>6}] {d['title']}\n         {d['query']}")


if __name__ == "__main__":
    main()
