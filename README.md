# SOAR Playbook Engine for Auto-Response

A defensive, safe-by-default Security Orchestration, Automation, and Response (SOAR) engine for matching security events to approved playbooks, applying human approval gates, simulating response actions, and preserving an auditable evidence trail.

## Capabilities

- Normalize JSONL and CSV security events.
- Match events against data-driven JSON playbooks.
- Support authentication, malware, and IOC response workflows.
- Require human approval for containment actions.
- Run in \`dry-run\` mode by default.
- Queue approved intents without executing external commands.
- Reject unknown action types.
- Store execution history and evidence hashes in SQLite.
- Run tests through GitHub Actions CI.

## Quick start

\`\`\`bash
python -m venv .venv
# Windows
.venv\\\\Scripts\\\\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install -r requirements.txt
python soar_engine.py --events sample_events.jsonl --mode dry-run --audit-db soar_audit.db
\`\`\`

Approve a specific playbook for simulation:

\`\`\`bash
python soar_engine.py --events sample_events.jsonl --approve malware-host-triage --mode dry-run
\`\`\`

## Event format

JSONL events contain normalized fields plus an extensible \`fields\` object:

\`\`\`json
{"event_type":"malware_alert","severity":"critical","source":"edr","entity":"host-7","fields":{"confidence":"high"}}
\`\`\`

CSV files may use columns such as \`event_type\`, \`severity\`, \`source\`, \`entity\`, and \`confidence\`.

## Playbook format

Playbooks define a matching condition, approval policy, and allowlisted actions:

\`\`\`json
{"id":"example-notification","when":{"event_type":"ioc_match"},"requires_approval":false,"actions":[{"type":"notify","target":"soc-on-call"}]}
\`\`\`

Supported safe action intents are \`notify\`, \`collect_evidence\`, \`isolate_host\`, \`disable_account\`, and \`block_indicator\`. In this reference implementation, containment actions are simulated or queued only.

## Architecture

\`\`\`text
Event source -> Normalizer -> Playbook matcher -> Approval gate
                                      |
                         Dry-run / queue adapter
                                      |
                           SQLite audit evidence
\`\`\`

## Safety model

This repository intentionally does not execute arbitrary commands or directly change endpoints, identities, firewalls, or network controls. Production integrations should add narrowly scoped adapters with authentication, authorization, rate limits, rollback, secret management, and independent approval.

Use only with events and systems you are authorized to monitor and protect.

## Testing

\`\`\`bash
pytest -q
\`\`\`

## License

MIT. See [LICENSE](LICENSE).
