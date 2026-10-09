#!/usr/bin/env python3
"""Safe-by-default SOAR playbook engine for authorized defensive workflows."""
from __future__ import annotations
import argparse, csv, hashlib, json, sqlite3, uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def as_bool(value: Any) -> bool:
    if isinstance(value, bool): return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}

@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    source: str
    entity: str
    fields: dict[str, Any]

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "Event":
        fields = dict(raw.get("fields") or {})
        for key, value in raw.items():
            if key not in {"event_id", "timestamp", "event_type", "severity", "source", "entity", "fields"}:
                fields.setdefault(key, value)
        return cls(
            str(raw.get("event_id") or uuid.uuid4()),
            str(raw.get("timestamp") or utc_now()),
            str(raw.get("event_type") or raw.get("type") or "unknown"),
            str(raw.get("severity") or "medium").lower(),
            str(raw.get("source") or "unknown"),
            str(raw.get("entity") or raw.get("user") or raw.get("src_ip") or "unknown"),
            fields,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"event_id": self.event_id, "timestamp": self.timestamp, "event_type": self.event_type,
                "severity": self.severity, "source": self.source, "entity": self.entity, "fields": self.fields}

@dataclass(frozen=True)
class ActionResult:
    action: str
    status: str
    detail: str
    def to_dict(self) -> dict[str, str]:
        return {"action": self.action, "status": self.status, "detail": self.detail}

class AuditStore:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(path)
        self.connection.execute("""CREATE TABLE IF NOT EXISTS executions (
            execution_id TEXT PRIMARY KEY, event_id TEXT NOT NULL, playbook_id TEXT NOT NULL,
            mode TEXT NOT NULL, status TEXT NOT NULL, approved INTEGER NOT NULL,
            created_at TEXT NOT NULL, event_json TEXT NOT NULL, results_json TEXT NOT NULL,
            evidence_hash TEXT NOT NULL)""")
        self.connection.commit()

    def record(self, execution: dict[str, Any]) -> None:
        self.connection.execute("INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
            execution["execution_id"], execution["event_id"], execution["playbook_id"],
            execution["mode"], execution["status"], int(execution["approved"]),
            execution["created_at"], json.dumps(execution["event"], sort_keys=True),
            json.dumps(execution["results"], sort_keys=True), execution["evidence_hash"]))
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

class SOAREngine:
    def __init__(self, playbooks: Iterable[dict[str, Any]], audit: AuditStore, mode: str = "dry-run"):
        self.playbooks, self.audit, self.mode = list(playbooks), audit, mode

    @staticmethod
    def _matches(condition: dict[str, Any], event: Event) -> bool:
        for key, expected in condition.items():
            if key == "fields":
                for field, expected_value in expected.items():
                    actual = event.fields.get(field)
                    if isinstance(expected_value, list) and actual not in expected_value: return False
                    if isinstance(expected_value, str) and expected_value.startswith("contains:") and expected_value[9:].lower() not in str(actual).lower(): return False
                    if not isinstance(expected_value, (list, str)) and actual != expected_value: return False
                    if isinstance(expected_value, str) and not expected_value.startswith("contains:") and actual != expected_value: return False
                continue
            actual = getattr(event, key, None)
            if isinstance(expected, list):
                if actual not in expected: return False
            elif actual != expected: return False
        return True

    def matching_playbooks(self, event: Event) -> list[dict[str, Any]]:
        return [p for p in self.playbooks if self._matches(p.get("when", {}), event)]

    def _execute_action(self, action: dict[str, Any], event: Event) -> ActionResult:
        name = str(action.get("type", "notify"))
        target = action.get("target", event.entity)
        if target == "event.entity":
            target = event.entity
        elif target == "event.source":
            target = event.source
        target = str(target)
        if name == "notify":
            return ActionResult(name, "simulated" if self.mode == "dry-run" else "queued", f"notification prepared for {target}")
        if name in {"isolate_host", "disable_account", "block_indicator", "collect_evidence"}:
            return ActionResult(name, "simulated" if self.mode == "dry-run" else "queued",
                                f"{'safe preview only' if self.mode == 'dry-run' else 'approval-controlled action queued'}; target={target}")
        return ActionResult(name, "rejected", "unknown action type; no external side effect allowed")

    def run(self, event: Event, playbook: dict[str, Any], approved: bool = False) -> dict[str, Any]:
        requires_approval = as_bool(playbook.get("requires_approval", True))
        execution_id = str(uuid.uuid4())
        if requires_approval and not approved:
            results = [ActionResult("approval_gate", "pending", "human approval is required before response actions")]
            status = "pending_approval"
        else:
            results = [self._execute_action(a, event) for a in playbook.get("actions", [])]
            if any(result.status == "rejected" for result in results):
                status = "rejected"
            else:
                status = "simulated" if self.mode == "dry-run" else "queued"
        result_dicts = [r.to_dict() for r in results]
        evidence = json.dumps({"event": event.to_dict(), "results": result_dicts}, sort_keys=True).encode()
        execution = {"execution_id": execution_id, "event_id": event.event_id,
            "playbook_id": str(playbook.get("id", "unknown")), "mode": self.mode, "status": status,
            "approved": approved, "created_at": utc_now(), "event": event.to_dict(),
            "results": result_dicts, "evidence_hash": hashlib.sha256(evidence).hexdigest()}
        self.audit.record(execution)
        return execution

    def process(self, event: Event, approved_ids: set[str] | None = None) -> list[dict[str, Any]]:
        approved_ids = approved_ids or set()
        return [self.run(event, p, p.get("id") in approved_ids) for p in self.matching_playbooks(event)]

def load_json(path: str | Path) -> Any:
    with open(path, encoding="utf-8") as handle: return json.load(handle)

def load_events(path: str | Path) -> list[Event]:
    source, events = Path(path), []
    if source.suffix.lower() == ".csv":
        with source.open(newline="", encoding="utf-8") as handle: return [Event.from_mapping(row) for row in csv.DictReader(handle)]
    with source.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip(): events.append(Event.from_mapping(json.loads(line)))
    return events

def main() -> int:
    parser = argparse.ArgumentParser(description="Safe-by-default SOAR playbook engine")
    parser.add_argument("--events", required=True); parser.add_argument("--playbooks", default="playbooks/default.json")
    parser.add_argument("--audit-db", default="soar_audit.db"); parser.add_argument("--mode", choices=("dry-run", "queue"), default="dry-run")
    parser.add_argument("--approve", action="append", default=[]); parser.add_argument("--output")
    args = parser.parse_args()
    audit = AuditStore(args.audit_db)
    try:
        engine = SOAREngine(load_json(args.playbooks), audit, args.mode)
        executions = []
        for event in load_events(args.events): executions.extend(engine.process(event, set(args.approve)))
        rendered = json.dumps({"mode": args.mode, "execution_count": len(executions), "executions": executions}, indent=2)
        if args.output: Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(rendered); return 0
    finally: audit.close()

if __name__ == "__main__": raise SystemExit(main())
