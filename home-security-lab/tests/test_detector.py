from homelab import detector

RULE = {"id": "r1", "title": "Test rule", "level": "low", "tags": ["attack.t1110.001"], "query": "x:y"}
HIT = {
    "_id": "evt1",
    "_source": {
        "@timestamp": "2026-10-14T22:22:30+00:00",
        "source": {"ip": "172.18.0.7"},
        "user": {"name": "deploy"},
        "message": "Invalid user deploy from 172.18.0.7 port 49904",
    },
}


def test_alert_id_is_deterministic():
    assert detector.alert_id("r1", "evt1") == detector.alert_id("r1", "evt1")
    assert detector.alert_id("r1", "evt1") != detector.alert_id("r2", "evt1")


def test_build_search_has_time_filter():
    body = detector.build_search("event.action:sudo", "15m")
    assert body["query"]["bool"]["must"][0]["query_string"]["query"] == "event.action:sudo"
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-15m"


def test_make_alert():
    doc_id, alert = detector.make_alert(RULE, HIT)
    assert doc_id == detector.alert_id("r1", "evt1")
    assert alert["rule"]["name"] == "Test rule"
    assert alert["event"] == {"original_id": "evt1", "time": "2026-10-14T22:22:30+00:00"}
    assert alert["source"]["ip"] == "172.18.0.7"


def test_run_once_counts_only_new_alerts(monkeypatch):
    monkeypatch.setattr(detector.es, "search", lambda index, body: [HIT])
    sent = {}

    def fake_bulk(index, docs):
        sent["docs"] = docs
        # second alert already existed -> Elasticsearch answers 409 conflict
        return {"items": [{"create": {"result": "created"}}, {"create": {"status": 409}}]}

    monkeypatch.setattr(detector.es, "bulk_index", fake_bulk)
    assert detector.run_once([RULE, {**RULE, "id": "r2"}]) == 1
    assert len(sent["docs"]) == 2
