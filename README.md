# Cloud Autopilot V2.5 — PostgreSQL + Redis + Celery

V2.5 adds persistent SaaS infrastructure to V2.4: PostgreSQL, SQLAlchemy, Redis, Celery worker, persistent accounts/resources/findings/costs/recommendations/remediation jobs/audit logs, while retaining AWS discovery, Cost Explorer, Prowler and safe approval workflows.

## Run
```bash
docker compose down --remove-orphans
docker compose build --no-cache
docker compose up
```
Open http://localhost:3000 and http://localhost:8000/docs.

## Architecture
```text
Next.js -> FastAPI -> PostgreSQL
                  -> Redis -> Celery Worker -> Prowler / AWS jobs
```

PostgreSQL persists in `postgres_data`. Set `POSTGRES_PASSWORD` in `.env` for anything beyond local development.

V2.5 remediation remains safe-mode: approved jobs are recorded, but destructive AWS mutations are not performed yet.
