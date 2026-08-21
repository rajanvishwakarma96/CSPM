# Cloud Autopilot V2.1

Adds to V2:
- AWS Organizations account discovery
- AI-ready finding explanations without an LLM key
- FinOps savings recommendations
- remediation catalog
- audit endpoint
- multi-account foundation

Run:
```bash
cp .env.example .env
docker compose up --build
```

Dashboard: http://localhost:3000
API docs: http://localhost:8000/docs

For production, use a dedicated read-only discovery role and a separate narrowly scoped remediation role.
