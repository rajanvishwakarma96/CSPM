# AWS Cloud Autopilot MVP

Runnable starter for:
- AWS account connection using Role ARN + External ID
- EC2/S3/RDS/ECS/EBS discovery
- Deterministic security checks
- Basic cost/waste recommendations
- AI explanations
- Safe remediation planning (execution intentionally disabled)

## Run

```bash
cp .env.example .env
docker compose up --build
```

Open http://localhost:3000 and API docs at http://localhost:8000/docs.

DEMO_MODE=true is enabled by default so the app works without AWS credentials.
For real AWS discovery, set DEMO_MODE=false and provide a customer cross-account
IAM role ARN and External ID.

This is an MVP scaffold, not production-ready security software. Add tenant
isolation, encryption, audit controls, least-privilege review, approval workflows,
secret management and security testing before handling real customer accounts.
