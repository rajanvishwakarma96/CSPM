from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./autopilot.db")
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4.1-mini")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="AWS Cloud Autopilot MVP", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def now():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS aws_accounts (
            id TEXT PRIMARY KEY,
            account_name TEXT NOT NULL,
            account_id TEXT,
            role_arn TEXT,
            external_id TEXT,
            regions TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS resources (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            region TEXT,
            name TEXT,
            data TEXT NOT NULL,
            discovered_at TEXT NOT NULL
        )"""))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            resource_id TEXT,
            resource_type TEXT,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            status TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS recommendations (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            resource_id TEXT,
            estimated_monthly_saving REAL NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL
        )"""))


init_db()


class AccountIn(BaseModel):
    account_name: str
    account_id: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    regions: list[str] = ["ap-south-1"]


class AIRequest(BaseModel):
    question: str
    account_id: str


def demo_resources():
    return [
        {"resource_type": "EC2", "resource_id": "i-demo123", "region": "ap-south-1",
         "name": "payment-api", "data": {"instance_type": "m5.2xlarge", "cpu_avg_30d": 3.2}},
        {"resource_type": "S3", "resource_id": "prod-customer-data", "region": "global",
         "name": "prod-customer-data", "data": {"public_access": True}},
        {"resource_type": "RDS", "resource_id": "prod-postgres", "region": "ap-south-1",
         "name": "prod-postgres", "data": {"engine": "postgres", "cpu_avg_30d": 14.5, "publicly_accessible": False}},
        {"resource_type": "EBS", "resource_id": "vol-demo456", "region": "ap-south-1",
         "name": "unused-volume", "data": {"attached": False, "size_gb": 200}},
    ]


def assumed_session(account, region):
    if not account.get("role_arn"):
        return boto3.Session(region_name=region)
    sts = boto3.client("sts", region_name=region)
    kwargs = {
        "RoleArn": account["role_arn"],
        "RoleSessionName": "cloud-autopilot-discovery",
    }
    if account.get("external_id"):
        kwargs["ExternalId"] = account["external_id"]
    creds = sts.assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def discover_real(account):
    discovered = []
    for region in account["regions"]:
        session = assumed_session(account, region)
        ec2 = session.client("ec2", region_name=region)

        for reservation in ec2.describe_instances().get("Reservations", []):
            for instance in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                discovered.append({
                    "resource_type": "EC2",
                    "resource_id": instance["InstanceId"],
                    "region": region,
                    "name": tags.get("Name", instance["InstanceId"]),
                    "data": {
                        "instance_type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                    },
                })

        for volume in ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ).get("Volumes", []):
            discovered.append({
                "resource_type": "EBS",
                "resource_id": volume["VolumeId"],
                "region": region,
                "name": volume["VolumeId"],
                "data": {"attached": False, "size_gb": volume.get("Size")},
            })

        rds = session.client("rds", region_name=region)
        for db in rds.describe_db_instances().get("DBInstances", []):
            discovered.append({
                "resource_type": "RDS",
                "resource_id": db["DBInstanceIdentifier"],
                "region": region,
                "name": db["DBInstanceIdentifier"],
                "data": {
                    "engine": db.get("Engine"),
                    "instance_class": db.get("DBInstanceClass"),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                },
            })

        ecs = session.client("ecs", region_name=region)
        for cluster in ecs.list_clusters().get("clusterArns", []):
            discovered.append({
                "resource_type": "ECS_CLUSTER",
                "resource_id": cluster.split("/")[-1],
                "region": region,
                "name": cluster.split("/")[-1],
                "data": {},
            })

    session = assumed_session(account, account["regions"][0])
    s3 = session.client("s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        discovered.append({
            "resource_type": "S3",
            "resource_id": bucket["Name"],
            "region": "global",
            "name": bucket["Name"],
            "data": {},
        })
    return discovered


def save_resources(account_id, resources):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM resources WHERE account_id=:a"), {"a": account_id})
        for r in resources:
            conn.execute(text("""
                INSERT INTO resources
                VALUES (:id,:a,:t,:rid,:region,:name,:data,:dt)
            """), {
                "id": str(uuid.uuid4()), "a": account_id,
                "t": r["resource_type"], "rid": r["resource_id"],
                "region": r["region"], "name": r["name"],
                "data": json.dumps(r["data"]), "dt": now()
            })


def run_security_rules(account_id, resources):
    findings = []
    for r in resources:
        if r["resource_type"] == "S3" and r["data"].get("public_access") is True:
            findings.append({
                "severity": "HIGH",
                "title": "S3 bucket may be publicly accessible",
                "resource_id": r["resource_id"],
                "resource_type": "S3",
                "description": "Public access can expose objects to unauthorized users.",
                "recommendation": "Enable S3 Block Public Access after reviewing legitimate public-read requirements.",
                "source": "built-in-rule",
            })
        if r["resource_type"] == "RDS" and r["data"].get("publicly_accessible") is True:
            findings.append({
                "severity": "CRITICAL",
                "title": "RDS instance is publicly accessible",
                "resource_id": r["resource_id"],
                "resource_type": "RDS",
                "description": "A database exposed to the public network increases attack surface.",
                "recommendation": "Disable public accessibility and use private subnets/security groups.",
                "source": "built-in-rule",
            })

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM findings WHERE account_id=:a"), {"a": account_id})
        for f in findings:
            conn.execute(text("""
                INSERT INTO findings
                VALUES (:id,:a,:severity,:title,:rid,:rtype,:description,:recommendation,:status,:source,:dt)
            """), {
                "id": str(uuid.uuid4()), "a": account_id, **f,
                "status": "OPEN", "dt": now()
            })
    return findings


def run_cost_rules(account_id, resources):
    recs = []
    for r in resources:
        if r["resource_type"] == "EC2" and r["data"].get("cpu_avg_30d", 100) < 5:
            recs.append({
                "category": "rightsizing",
                "title": f"EC2 {r['resource_id']} appears oversized",
                "resource_id": r["resource_id"],
                "estimated_monthly_saving": 215.0,
                "reason": "30-day average CPU is below 5%; validate memory and workload patterns before resizing.",
            })
        if r["resource_type"] == "EBS" and not r["data"].get("attached", True):
            size = float(r["data"].get("size_gb", 0))
            recs.append({
                "category": "waste",
                "title": f"Unattached EBS volume {r['resource_id']}",
                "resource_id": r["resource_id"],
                "estimated_monthly_saving": round(size * 0.08, 2),
                "reason": "Volume is unattached and may no longer be required.",
            })

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM recommendations WHERE account_id=:a"), {"a": account_id})
        for r in recs:
            conn.execute(text("""
                INSERT INTO recommendations
                VALUES (:id,:a,:category,:title,:rid,:saving,:reason,:status)
            """), {
                "id": str(uuid.uuid4()), "a": account_id, **r, "status": "OPEN"
            })
    return recs


@app.get("/health")
def health():
    return {"status": "ok", "demo_mode": DEMO_MODE}


@app.post("/accounts")
def create_account(body: AccountIn):
    account_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO aws_accounts
            VALUES (:id,:name,:account_id,:role_arn,:external_id,:regions,:status,:dt)
        """), {
            "id": account_id,
            "name": body.account_name,
            "account_id": body.account_id,
            "role_arn": body.role_arn,
            "external_id": body.external_id,
            "regions": json.dumps(body.regions),
            "status": "CONNECTED",
            "dt": now(),
        })
    return {"id": account_id, "status": "CONNECTED"}


@app.get("/accounts")
def list_accounts():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT * FROM aws_accounts ORDER BY created_at DESC")).mappings().all()
    return [dict(r) for r in rows]


@app.post("/accounts/{account_id}/discover")
def discover(account_id: str):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT * FROM aws_accounts WHERE id=:id"), {"id": account_id}
        ).mappings().first()
    if not row:
        raise HTTPException(404, "Account not found")

    account = dict(row)
    account["regions"] = json.loads(account["regions"])

    try:
        resources = demo_resources() if DEMO_MODE else discover_real(account)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(400, f"AWS discovery failed: {exc}")

    save_resources(account_id, resources)
    findings = run_security_rules(account_id, resources)
    recs = run_cost_rules(account_id, resources)

    return {"resources": len(resources), "findings": len(findings), "recommendations": len(recs)}


@app.get("/accounts/{account_id}/resources")
def resources(account_id: str):
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT * FROM resources WHERE account_id=:a ORDER BY resource_type,name"),
            {"a": account_id},
        ).mappings().all()
    return [dict(r) for r in rows]


@app.get("/accounts/{account_id}/findings")
def findings(account_id: str):
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT * FROM findings WHERE account_id=:a ORDER BY severity,title"),
            {"a": account_id},
        ).mappings().all()
    return [dict(r) for r in rows]


@app.get("/accounts/{account_id}/recommendations")
def recommendations(account_id: str):
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT * FROM recommendations WHERE account_id=:a ORDER BY estimated_monthly_saving DESC"),
            {"a": account_id},
        ).mappings().all()
    return [dict(r) for r in rows]


@app.post("/ai/explain")
def ai_explain(body: AIRequest):
    with engine.begin() as conn:
        f = conn.execute(
            text("SELECT * FROM findings WHERE account_id=:a AND status='OPEN' LIMIT 20"),
            {"a": body.account_id},
        ).mappings().all()
        r = conn.execute(
            text("SELECT * FROM recommendations WHERE account_id=:a AND status='OPEN' LIMIT 20"),
            {"a": body.account_id},
        ).mappings().all()

    context = {
        "question": body.question,
        "security_findings": [dict(x) for x in f],
        "cost_recommendations": [dict(x) for x in r],
    }

    if not OPENAI_API_KEY:
        return {
            "mode": "local-fallback",
            "answer": (
                "AI key is not configured. The current analysis found "
                f"{len(f)} open security findings and {len(r)} cost recommendations. "
                "Review HIGH/CRITICAL findings first and validate cost recommendations "
                "against memory, traffic and business requirements."
            ),
        }

    import httpx
    payload = {
        "model": AI_MODEL,
        "input": [
            {
                "role": "system",
                "content": (
                    "You are a cautious AWS SRE assistant. Use only supplied context. "
                    "Never invent AWS state. Recommend reversible, least-privilege actions. "
                    "Never claim an action was executed."
                ),
            },
            {"role": "user", "content": json.dumps(context, default=str)},
        ],
    }
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = httpx.post(
        "https://api.openai.com/v1/responses",
        json=payload,
        headers=headers,
        timeout=60,
    )
    if resp.status_code >= 400:
        raise HTTPException(502, "AI provider request failed")
    data = resp.json()
    return {"mode": "llm", "answer": data.get("output_text", json.dumps(data))}


@app.post("/remediation/{finding_id}/plan")
def remediation_plan(finding_id: str):
    with engine.begin() as conn:
        f = conn.execute(
            text("SELECT * FROM findings WHERE id=:id"), {"id": finding_id}
        ).mappings().first()
    if not f:
        raise HTTPException(404, "Finding not found")

    action = "REVIEW_ONLY"
    if f["title"].startswith("S3"):
        action = "S3_BLOCK_PUBLIC_ACCESS"

    return {
        "finding_id": finding_id,
        "action": action,
        "approval_required": True,
        "execution_enabled": False,
        "message": "MVP safety mode: remediation is planned but not executed.",
    }
