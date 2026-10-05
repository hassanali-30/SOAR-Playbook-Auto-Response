import sqlite3
from pathlib import Path
from soar_engine import AuditStore, Event, SOAREngine, load_json

def make_engine(tmp_path):
    return SOAREngine(load_json(Path(__file__).parents[1] / "playbooks" / "default.json"), AuditStore(tmp_path / "audit.db"))

def test_matching_playbook_requires_approval(tmp_path):
    engine = make_engine(tmp_path)
    try:
        event = Event.from_mapping({"event_type":"malware_alert","severity":"critical","source":"edr","entity":"host-1"})
        executions = engine.process(event)
        assert len(executions) == 1
        assert executions[0]["status"] == "pending_approval"
        assert executions[0]["results"][0]["status"] == "pending"
    finally: engine.audit.close()

def test_approved_actions_are_simulated_and_audited(tmp_path):
    engine = make_engine(tmp_path)
    try:
        event = Event.from_mapping({"event_type":"authentication_alert","severity":"high","source":"idp","entity":"alice","fields":{"confidence":"high"}})
        executions = engine.process(event, {"account-compromise-containment"})
        assert executions[0]["status"] == "simulated"
        assert any(item["status"] == "simulated" for item in executions[0]["results"])
        assert sqlite3.connect(tmp_path / "audit.db").execute("select count(*) from executions").fetchone()[0] == 1
    finally: engine.audit.close()

def test_unknown_action_is_rejected(tmp_path):
    engine = SOAREngine([{"id":"bad","when":{"event_type":"test"},"requires_approval":False,"actions":[{"type":"shell"}]}], AuditStore(tmp_path / "audit.db"))
    try:
        result = engine.process(Event.from_mapping({"event_type":"test"}))[0]
        assert result["results"][0]["status"] == "rejected"
    finally: engine.audit.close()


def test_action_target_resolves_event_entity(tmp_path):
    engine = SOAREngine(
        [{
            "id": "target-resolution",
            "when": {"event_type": "test"},
            "requires_approval": False,
            "actions": [{"type": "isolate_host", "target": "event.entity"}],
        }],
        AuditStore(tmp_path / "audit.db"),
    )
    try:
        result = engine.process(Event.from_mapping({"event_type": "test", "entity": "host-42"}))[0]
        assert "target=host-42" in result["results"][0]["detail"]
    finally:
        engine.audit.close()
