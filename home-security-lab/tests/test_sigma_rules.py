from pathlib import Path

import pytest
import yaml

from homelab.sigma_convert import convert

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "sigma" / "rules"
PIPELINE = ROOT / "sigma" / "pipelines" / "homelab.yml"


@pytest.fixture(scope="module")
def detections():
    return {d["title"]: d for d in convert(RULES, PIPELINE)}


def test_every_rule_converts(detections):
    assert len(detections) == len(list(RULES.glob("*.yml")))
    for d in detections.values():
        assert d["query"]


@pytest.mark.parametrize("path", sorted(RULES.glob("*.yml")), ids=lambda p: p.stem)
def test_rule_metadata(path):
    rule = yaml.safe_load(path.read_text())
    for key in ("title", "id", "description", "logsource", "detection", "level", "falsepositives"):
        assert key in rule, f"{path.name} is missing {key}"
    assert any(t.startswith("attack.t") for t in rule["tags"]), "map every rule to an ATT&CK technique"


def test_pipeline_maps_fields_and_dataset(detections):
    q = detections["Web Request With Known Scanner User-Agent"]["query"]
    assert "event.dataset:nginx.access" in q
    assert "user_agent.original" in q and "cs-user-agent" not in q

    q = detections["Root Shell Started Via Sudo"]["query"]
    assert "event.dataset:linux.auth" in q
    assert "user.target.name:root" in q


def test_rule_ids_are_unique(detections):
    ids = [d["id"] for d in detections.values()]
    assert len(ids) == len(set(ids))
