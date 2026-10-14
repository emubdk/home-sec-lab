# Design notes

Short explanations of decisions in the lab, and what I would change in a real setup.

## Own log shipper instead of Filebeat

Filebeat with the `system` and `nginx` modules would parse these logs out of the box.
I wrote a small shipper (`homelab/shipper.py`, `homelab/parsers.py`) instead because:

- the parsing step is where most detection problems start (wrong field, missing field,
  wrong timezone), and writing it by hand made that visible;
- it keeps every request to Elasticsearch readable (plain HTTP via `requests`);
- the parsers are unit-tested with real lines captured from the lab.

In a real environment I would use Filebeat or Elastic Agent.

## Restart-safe ingestion

Each event's `_id` is `sha1(file path + byte offset)` and documents are sent with
`op_type=create`. If the shipper restarts and reads a file again from the start,
Elasticsearch rejects the duplicates (HTTP 409) instead of storing them twice.
Alerts use the same idea: `sha1(rule id + event id)`. The detector can therefore
search an overlapping 15-minute window every 30 seconds without creating duplicate alerts.

## Sigma to Elasticsearch with a processing pipeline

Sigma rules use generic field names (`cs-user-agent` for web servers) or, for Linux
auth logs where Sigma has no standard field set, the lab's own names (`EventAction`,
`User`, `CommandLine`). The pySigma pipeline in `sigma/pipelines/homelab.yml`:

1. maps those names to ECS fields (`user_agent.original`, `event.action`, ...), and
2. adds `event.dataset:<dataset>` to each query, so a web rule never matches auth events.

This is the same job the official pySigma pipelines (`ecs_windows`, `ecs_zeek_beats`)
do for their log sources.

## Case-insensitive matching

Sigma's `contains` is case-insensitive, Lucene wildcard queries on `keyword` fields are not.
`elastic/index-template.json` gives `url.original` and `user_agent.original` a `lowercase`
normalizer, so `*nmap*` also matches `Nmap Scripting Engine`.

## LLM triage

The summarizer sends a grouped summary, not raw logs, to the model:

- the prompt stays small enough for a 3B model on a laptop;
- every number in the prompt can be checked in Kibana;
- the system prompt asks the model not to invent hosts or events and to say when the data
  is not enough.

This is the same approach as in my bachelor thesis (local Ollama agents for vulnerability
management): the LLM summarises and prioritises, the decision stays with a human.

## Things that are simplified on purpose

- Elasticsearch security (TLS, users) is disabled; ports are bound to localhost only.
- One victim, one attacker, no Windows host.
- The detector polls instead of using Elasticsearch's own alerting (needs a license
  for some features) or ElastAlert.
