# Cloud Autopilot V2.4 — Security + FinOps + Safe Remediation

V2.4 builds on V2.3 and adds:

- Prowler integration inside the backend container
- Prowler security scan API
- security severity overview
- unified security findings
- AI-style finding explanation endpoint
- remediation preview
- approval workflow
- remediation job tracking
- safe-mode execution gate
- FinOps/security combined summary
- AWS discovery and Cost Explorer from V2.3

## Run

```bash
docker compose down --remove-orphans
docker compose build --no-cache
docker compose up
```

Open:

- http://localhost:3000
- http://localhost:8000/docs

## V2.4 workflow

```text
AWS
 │
 ├── Discovery
 │
 ├── Cost Explorer ──────> FinOps
 │
 └── Prowler ────────────> Security
                              │
                              ▼
                         AI Explanation
                              │
                              ▼
                       Remediation Preview
                              │
                              ▼
                       Approval Required
                              │
                              ▼
                         Safe Execution
```

## Prowler

Check:

```bash
curl http://localhost:8000/accounts/<ACCOUNT_ID>/prowler/status
```

Run:

```bash
curl -X POST http://localhost:8000/accounts/<ACCOUNT_ID>/prowler/scan
```

Prowler requires the assumed AWS role to have the read permissions required by the checks you enable.

## Remediation safety

V2.4 deliberately does NOT execute destructive AWS changes.

The workflow is:

1. preview
2. create approval request
3. approve
4. execution endpoint records the approved attempt
5. safe-mode blocks actual mutation

This prevents an accidental production delete/stop/release while the platform is still being developed.

For V2.5, a dedicated remediation worker can be added with narrowly scoped IAM permissions, resource locks, snapshots/backups, rollback checks and a complete audit trail.

## Important production work

V2.4 still uses in-memory state. Before production SaaS deployment, add PostgreSQL, Redis, authentication, tenant isolation, encrypted AWS role configuration, persistent audit logs, worker queues and per-action IAM policies.
