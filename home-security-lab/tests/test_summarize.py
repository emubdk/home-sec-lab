import json

from homelab import summarize


def alert(rule, ip, user, time):
    return {
        "rule": {"name": rule, "level": "low", "tags": ["attack.credential-access", "attack.t1110.001"]},
        "event": {"time": time},
        "source": {"ip": ip},
        "user": {"name": user},
        "message": f"Invalid user {user} from {ip}",
    }


ALERTS = [
    alert("SSH invalid user", "10.0.0.5", "admin", "2026-10-14T22:00:00+00:00"),
    alert("SSH invalid user", "10.0.0.5", "test", "2026-10-14T22:00:05+00:00"),
    alert("SSH invalid user", "10.0.0.9", "admin", "2026-10-14T22:01:00+00:00"),
]


def test_group_alerts_by_rule_and_ip():
    groups = summarize.group_alerts(ALERTS)
    assert [(g["source_ip"], g["count"]) for g in groups] == [("10.0.0.5", 2), ("10.0.0.9", 1)]
    first = groups[0]
    assert first["first_seen"] == "2026-10-14T22:00:00+00:00"
    assert first["last_seen"] == "2026-10-14T22:00:05+00:00"
    assert sorted(first["top_users"]) == ["admin", "test"]
    assert first["attack_tags"] == ["attack.t1110.001"]


def test_prompt_contains_only_grouped_json():
    prompt = summarize.build_prompt(summarize.group_alerts(ALERTS))
    payload = prompt.split("(JSON):\n", 1)[1].rsplit("\n\nWrite", 1)[0]
    assert len(json.loads(payload)) == 2


def test_ask_ollama_sends_system_prompt(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "  note  "}

    def fake_post(url, json, timeout):
        captured.update(url=url, body=json)
        return FakeResponse()

    monkeypatch.setattr(summarize.requests, "post", fake_post)
    assert summarize.ask_ollama("prompt", model="llama3.2:3b") == "note"
    assert captured["url"].endswith("/api/generate")
    assert captured["body"]["system"] == summarize.SYSTEM_PROMPT
    assert captured["body"]["stream"] is False
