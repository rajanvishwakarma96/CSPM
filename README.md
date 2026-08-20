# Cloud Autopilot V2

Real AWS discovery + Prowler integration + AWS Cost Explorer + guarded remediation.

Run:
```bash
cp .env.example .env
docker compose up --build
```

Open http://localhost:3000 and http://localhost:8000/docs.

DEMO mode is removed: this version expects a real cross-account IAM role.

Safety:
- Remediation is disabled by default.
- Set ENABLE_REMEDIATION=true only after reviewing the IAM policy.
- Every execution requires approved=true.
- Only S3_BLOCK_PUBLIC_ACCESS and EBS_DELETE_UNATTACHED are allow-listed.
- EBS deletion snapshots the volume first.
- This is an MVP; add authentication, tenant isolation, immutable audit,
  approval policies, rollback/verification and production security controls.
