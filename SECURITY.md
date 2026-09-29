# Security Policy

This project is for authorized defensive automation only. It defaults to dry-run mode and does not execute arbitrary shell commands, send network traffic, disable accounts, isolate hosts, or block indicators directly.

Queue mode records approval-controlled actions as queued intents. Integrators must implement and review narrowly scoped adapters for their own environment.

Design safeguards include allowlisted playbooks, rejected unknown actions, default human approval, SQLite audit history, and evidence hashes. Never publish credentials, tokens, raw malware, or private infrastructure details in issues. Production adapters must enforce least privilege, authentication, authorization, rate limits, rollback, secret management, and independent approval.
