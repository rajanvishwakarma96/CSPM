from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import boto3, datetime, uuid, subprocess, os, json, shutil

app=FastAPI(title="Cloud Autopilot",version="2.4.0")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:3000","http://127.0.0.1:3000","http://frontend:3000"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

ACCOUNTS={}
DATA={}
REMEDIATION_JOBS={}
APPROVALS={}

class Account(BaseModel):
    id: Optional[str]=None
    account_name:str
    account_id:str
    role_arn:str
    external_id:Optional[str]=None
    regions:list[str]=Field(default_factory=lambda:["us-east-1"])

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def ensure(aid):
    if aid not in ACCOUNTS: raise HTTPException(404,"AWS account not found")
    return ACCOUNTS[aid]
def data(aid):
    return DATA.setdefault(aid,{"resources":[],"findings":[],"costs":[],"cost_summary":{},"recommendations":[],"errors":{},"last_sync":None})

def session(a,region=None):
    region=region or a["regions"][0]
    sts=boto3.client("sts",region_name=region)
    p={"RoleArn":a["role_arn"],"RoleSessionName":"CloudAutopilotV23"}
    if a.get("external_id"): p["ExternalId"]=a["external_id"]
    c=sts.assume_role(**p)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"],aws_secret_access_key=c["SecretAccessKey"],aws_session_token=c["SessionToken"],region_name=region)

@app.get("/")
def root(): return {"service":"Cloud Autopilot","version":"2.4.0","status":"running","docs":"/docs"}
@app.get("/health")
def health(): return {"status":"ok","version":"2.3.0","timestamp":now()}
@app.get("/version")
def version():
    return {
        "version": "2.4.0",
        "features": [
            "AWS discovery",
            "Cost Explorer",
            "FinOps dashboard",
            "service cost breakdown",
            "daily cost trend",
            "savings recommendations",
            "Prowler security integration",
            "AI-style finding explanations",
            "approval-based remediation",
            "dry-run remediation preview",
            "AWS Organizations discovery",
            "audit-ready remediation jobs",
        ],
    }

@app.get("/accounts")
def accounts(): return list(ACCOUNTS.values())
@app.post("/accounts")
def create(a:Account):
    aid=a.id or str(uuid.uuid4()); x=a.model_dump(); x["id"]=aid; ACCOUNTS[aid]=x; data(aid); return x
@app.get("/accounts/{aid}")
def get_account(aid): return ensure(aid)
@app.delete("/accounts/{aid}")
def delete_account(aid):
    ensure(aid); del ACCOUNTS[aid]; DATA.pop(aid,None); return {"status":"deleted","account_id":aid}

@app.post("/accounts/{aid}/discover")
def discover(aid):
    a=ensure(aid); d=data(aid); out=[]; errors={}
    for region in a["regions"]:
        try: s=session(a,region)
        except Exception as e: errors[f"session:{region}"]=str(e); continue
        try:
            ec2=s.client("ec2")
            for rr in ec2.describe_instances().get("Reservations",[]):
                for i in rr.get("Instances",[]):
                    out.append({"resource_type":"EC2","resource_id":i["InstanceId"],"name":i["InstanceId"],"region":region,"data":{"state":i.get("State",{}).get("Name"),"instance_type":i.get("InstanceType")}})
            for v in ec2.describe_volumes().get("Volumes",[]):
                out.append({"resource_type":"EBS","resource_id":v["VolumeId"],"name":v["VolumeId"],"region":region,"data":{"size_gb":v.get("Size",0),"attached":bool(v.get("Attachments")),"state":v.get("State")}})
            for e in ec2.describe_addresses().get("Addresses",[]):
                if not e.get("InstanceId") and not e.get("NetworkInterfaceId"):
                    out.append({"resource_type":"ELASTIC_IP","resource_id":e.get("AllocationId") or e.get("PublicIp"),"name":e.get("PublicIp"),"region":region,"data":{}})
        except Exception as e: errors[f"ec2:{region}"]=str(e)
        try:
            for db in s.client("rds").describe_db_instances().get("DBInstances",[]):
                out.append({"resource_type":"RDS","resource_id":db["DBInstanceIdentifier"],"name":db["DBInstanceIdentifier"],"region":region,"data":{"status":db.get("DBInstanceStatus"),"engine":db.get("Engine")}})
        except Exception as e: errors[f"rds:{region}"]=str(e)
        try:
            lam=s.client("lambda")
            for page in lam.get_paginator("list_functions").paginate():
                for f in page.get("Functions",[]): out.append({"resource_type":"LAMBDA","resource_id":f["FunctionArn"],"name":f["FunctionName"],"region":region,"data":{"runtime":f.get("Runtime")}})
        except Exception as e: errors[f"lambda:{region}"]=str(e)
    try:
        for b in session(a,a["regions"][0]).client("s3").list_buckets().get("Buckets",[]):
            out.append({"resource_type":"S3","resource_id":b["Name"],"name":b["Name"],"region":"global","data":{}})
    except Exception as e: errors["s3"]=str(e)
    d["resources"]=out; d["errors"].update(errors); d["last_sync"]=now()
    return {"status":"OK","resource_count":len(out),"resources":out}

@app.get("/accounts/{aid}/resources")
def resources(aid): ensure(aid); return data(aid)["resources"]

def sync_ce(aid,days=30):
    a=ensure(aid); d=data(aid); end=datetime.date.today(); start=end-datetime.timedelta(days=days)
    try:
        ce=session(a,"us-east-1").client("ce",region_name="us-east-1")
        r=ce.get_cost_and_usage(TimePeriod={"Start":start.isoformat(),"End":end.isoformat()},Granularity="DAILY",Metrics=["UnblendedCost"],GroupBy=[{"Type":"DIMENSION","Key":"SERVICE"}])
        services={}; daily=[]
        for x in r.get("ResultsByTime",[]):
            total=0
            for g in x.get("Groups",[]):
                amount=float(g["Metrics"]["UnblendedCost"]["Amount"]); service=g["Keys"][0]
                services[service]=services.get(service,0)+amount; total+=amount
            daily.append({"date":x["TimePeriod"]["Start"],"amount":round(total,4)})
        rows=[{"service":k,"amount":round(v,2),"percentage":0} for k,v in services.items()]
        total=sum(x["amount"] for x in rows)
        for x in rows: x["percentage"]=round(x["amount"]/total*100,2) if total else 0
        rows.sort(key=lambda x:x["amount"],reverse=True); daily.sort(key=lambda x:x["date"])
        d["costs"]=rows; d["cost_summary"]={"period_start":start.isoformat(),"period_end":end.isoformat(),"total":round(total,2),"average_daily":round(total/max(days,1),2),"top_service":rows[0]["service"] if rows else None,"top_service_cost":rows[0]["amount"] if rows else 0,"daily":daily,"last_sync":now()}; d["errors"].pop("costs",None)
        return d["cost_summary"]
    except Exception as e:
        d["errors"]["costs"]=str(e); raise HTTPException(400,f"Cost Explorer failed: {e}")

@app.post("/accounts/{aid}/costs/sync")
def cost_sync(aid,days:int=30):
    if days not in (7,14,30,60,90): raise HTTPException(400,"days must be 7, 14, 30, 60 or 90")
    return sync_ce(aid,days)
@app.get("/accounts/{aid}/costs")
def costs(aid): ensure(aid); return data(aid)["costs"]
@app.get("/accounts/{aid}/finops")
def finops(aid):
    ensure(aid); d=data(aid); return {"summary":d["cost_summary"],"services":d["costs"],"recommendations":d["recommendations"],"errors":d["errors"]}

@app.post("/accounts/{aid}/recommendations/generate")
def recommendations(aid):
    ensure(aid); d=data(aid); out=[]
    for r in d["resources"]:
        x=r["data"]
        if r["resource_type"]=="EBS" and not x.get("attached"):
            savings=round(float(x.get("size_gb",0))*.08,2)
            if savings: out.append({"id":str(uuid.uuid4()),"category":"EBS","severity":"LOW","resource_type":"EBS","resource_id":r["resource_id"],"name":r["name"],"monthly_savings":savings,"title":"Delete unattached EBS volume","requires_approval":True})
        if r["resource_type"]=="EC2" and x.get("state")=="stopped":
            out.append({"id":str(uuid.uuid4()),"category":"EC2","severity":"MEDIUM","resource_type":"EC2","resource_id":r["resource_id"],"name":r["name"],"monthly_savings":5.0,"title":"Review stopped EC2 instance","requires_approval":True})
        if r["resource_type"]=="ELASTIC_IP":
            out.append({"id":str(uuid.uuid4()),"category":"NETWORK","severity":"MEDIUM","resource_type":"ELASTIC_IP","resource_id":r["resource_id"],"name":r["name"],"monthly_savings":3.65,"title":"Review unused Elastic IP","requires_approval":True})
    d["recommendations"]=out; return out
@app.get("/accounts/{aid}/recommendations")
def get_recs(aid): ensure(aid); return data(aid)["recommendations"]

@app.post("/accounts/{aid}/scan")
def scan(aid):
    ensure(aid); d=data(aid); out=[]
    for r in d["resources"]:
        if r["resource_type"]=="EBS" and not r["data"].get("attached"): out.append({"id":str(uuid.uuid4()),"severity":"LOW","title":"Unattached EBS volume","description":"The EBS volume is not attached to an EC2 instance.","resource_id":r["resource_id"],"recommendation":"Confirm unused, snapshot if needed, then delete."})
        if r["resource_type"]=="EC2" and r["data"].get("state")=="stopped": out.append({"id":str(uuid.uuid4()),"severity":"MEDIUM","title":"Stopped EC2 instance","description":"A stopped instance may still incur storage costs.","resource_id":r["resource_id"],"recommendation":"Confirm whether it is still required."})
    d["findings"]=out; return {"status":"OK","finding_count":len(out),"findings":out}
@app.get("/accounts/{aid}/findings")
def findings(aid): ensure(aid); return data(aid)["findings"]
@app.get("/accounts/{aid}/findings/{fid}/explain")
def explain(aid,fid):
    ensure(aid); f=next((x for x in data(aid)["findings"] if x["id"]==fid),None)
    if not f: raise HTTPException(404,"Finding not found")
    return {"summary":f["title"],"severity":f["severity"],"business_impact":"This configuration can increase security, operational or cloud-cost risk.","recommended_fix":f["recommendation"]}

@app.post("/accounts/{aid}/organization/discover")
def org(aid):
    a=ensure(aid)
    try:
        o=session(a,"us-east-1").client("organizations",region_name="us-east-1"); rows=[]
        for p in o.get_paginator("list_accounts").paginate(): rows.extend(p.get("Accounts",[]))
        return {"status":"OK","accounts_found":len(rows),"accounts":rows}
    except Exception as e: raise HTTPException(400,f"Organizations discovery failed: {e}")

@app.get("/remediation/catalog")
def catalog():
    return {"actions":[{"id":"S3_BLOCK_PUBLIC_ACCESS","risk":"LOW","requires_approval":True},{"id":"EBS_DELETE_UNATTACHED","risk":"HIGH","requires_approval":True,"creates_snapshot":True},{"id":"EC2_STOP_UNUSED","risk":"MEDIUM","requires_approval":True},{"id":"RELEASE_UNUSED_ELASTIC_IP","risk":"MEDIUM","requires_approval":True}]}


# ---------------- V2.4 Prowler + AI + Remediation ----------------

def prowler_available():
    return shutil.which("prowler") is not None


def run_prowler(account_id):
    account = ensure(account_id)
    d = data(account_id)

    if not prowler_available():
        return {
            "status": "not_installed",
            "message": "Prowler is not installed in the backend image.",
            "findings": [],
        }

    out_dir = "/tmp/prowler"
    os.makedirs(out_dir, exist_ok=True)
    cmd = [
        "prowler",
        "aws",
        "--output-directory", out_dir,
        "--output-formats", "json-ocsf",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
        )
        files = list(Path(out_dir).glob("*.json"))
        findings = []

        for f in files:
            try:
                payload = json.loads(f.read_text())
                rows = payload if isinstance(payload, list) else payload.get("findings", [])
                for row in rows:
                    findings.append({
                        "source": "prowler",
                        "title": row.get("finding_info", {}).get("title")
                                 or row.get("title")
                                 or row.get("message")
                                 or "Prowler finding",
                        "severity": str(
                            row.get("severity")
                            or row.get("finding_info", {}).get("severity")
                            or "UNKNOWN"
                        ).upper(),
                        "status": row.get("status_code")
                                 or row.get("status")
                                 or "UNKNOWN",
                        "resource_id": row.get("resource", {}).get("uid")
                                       or row.get("resource_uid")
                                       or row.get("resource_id"),
                        "raw": row,
                    })
            except Exception:
                continue

        d["prowler"] = {
            "status": "completed",
            "return_code": result.returncode,
            "findings_count": len(findings),
            "stderr": result.stderr[-3000:],
            "timestamp": now(),
        }
        d["prowler_findings"] = findings

        return {
            "status": "completed",
            "findings_count": len(findings),
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Prowler scan timed out")
    except Exception as exc:
        raise HTTPException(500, f"Prowler execution failed: {exc}")


@app.get("/accounts/{aid}/prowler/status")
def prowler_status(aid):
    ensure(aid)
    d = data(aid)
    return {
        "installed": prowler_available(),
        "last_run": d.get("prowler"),
        "findings_count": len(d.get("prowler_findings", [])),
    }


@app.post("/accounts/{aid}/prowler/scan")
def prowler_scan(aid):
    return run_prowler(aid)


@app.get("/accounts/{aid}/security/overview")
def security_overview(aid):
    ensure(aid)
    d = data(aid)
    findings = d.get("prowler_findings", []) + d.get("findings", [])

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1

    return {
        "total": len(findings),
        "severity": counts,
        "prowler": d.get("prowler", {}),
    }


@app.get("/accounts/{aid}/security/findings")
def security_findings(aid):
    ensure(aid)
    d = data(aid)
    return d.get("prowler_findings", []) + d.get("findings", [])


@app.post("/accounts/{aid}/security/explain/{finding_index}")
def ai_explain(aid, finding_index: int):
    ensure(aid)
    findings = data(aid).get("prowler_findings", []) + data(aid).get("findings", [])

    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(404, "Finding not found")

    f = findings[finding_index]
    severity = str(f.get("severity", "UNKNOWN")).upper()

    priority = {
        "CRITICAL": 100,
        "HIGH": 85,
        "MEDIUM": 60,
        "LOW": 30,
        "UNKNOWN": 10,
    }.get(severity, 10)

    title = f.get("title", "Cloud security finding")
    resource = f.get("resource_id")

    return {
        "finding": title,
        "resource_id": resource,
        "risk_score": priority,
        "executive_summary": (
            f"{title} should be reviewed because it may increase "
            "security, operational, compliance, or cloud-cost risk."
        ),
        "why_it_matters": (
            "Prioritize internet exposure, identity permissions, "
            "unencrypted data, logging gaps, and high-impact resources."
        ),
        "recommended_action": (
            "Validate the finding against the workload's business "
            "requirements before applying a change."
        ),
        "safe_next_step": (
            "Create an approval request and execute only after an "
            "authorized operator reviews the proposed action."
        ),
    }


class RemediationRequest(BaseModel):
    action: str
    resource_id: Optional[str] = None
    reason: Optional[str] = None
    dry_run: bool = True


def create_job(aid, request):
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "account_id": aid,
        "action": request.action,
        "resource_id": request.resource_id,
        "reason": request.reason,
        "dry_run": request.dry_run,
        "status": "PENDING_APPROVAL",
        "created_at": now(),
        "approved_at": None,
        "executed_at": None,
        "result": None,
    }
    REMEDIATION_JOBS[job_id] = job
    return job


@app.post("/accounts/{aid}/remediation/preview")
def remediation_preview(aid, request: RemediationRequest):
    ensure(aid)

    allowed = {
        "EBS_DELETE_UNATTACHED",
        "EC2_STOP_UNUSED",
        "RELEASE_UNUSED_ELASTIC_IP",
    }

    if request.action not in allowed:
        raise HTTPException(400, "Unsupported remediation action")

    return {
        "safe": True,
        "requires_approval": True,
        "action": request.action,
        "resource_id": request.resource_id,
        "dry_run": True,
        "impact": "A production resource may be changed or deleted.",
        "recommended": (
            "Take a snapshot/back-up where appropriate and verify "
            "the resource is not required before execution."
        ),
    }


@app.post("/accounts/{aid}/remediation/request")
def remediation_request(aid, request: RemediationRequest):
    ensure(aid)

    if not request.dry_run:
        raise HTTPException(
            400,
            "Direct execution is disabled. Create an approval request first.",
        )

    return create_job(aid, request)


@app.get("/remediation/jobs")
def remediation_jobs():
    return list(REMEDIATION_JOBS.values())


@app.get("/remediation/jobs/{job_id}")
def remediation_job(job_id):
    job = REMEDIATION_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Remediation job not found")
    return job


@app.post("/remediation/jobs/{job_id}/approve")
def approve_remediation(job_id):
    job = REMEDIATION_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Remediation job not found")

    if job["status"] != "PENDING_APPROVAL":
        raise HTTPException(400, "Job is not awaiting approval")

    job["status"] = "APPROVED"
    job["approved_at"] = now()
    return job


@app.post("/remediation/jobs/{job_id}/execute")
def execute_remediation(job_id):
    job = REMEDIATION_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Remediation job not found")

    if job["status"] != "APPROVED":
        raise HTTPException(
            400,
            "Remediation must be explicitly approved before execution.",
        )

    # V2.4 intentionally keeps real destructive execution disabled.
    # This endpoint records the execution attempt and requires a future
    # worker with explicit IAM permissions and resource-specific safeguards.
    job["status"] = "EXECUTION_BLOCKED_SAFE_MODE"
    job["executed_at"] = now()
    job["result"] = {
        "message": (
            "Safe mode: real AWS mutation is disabled in V2.4. "
            "The approved job was recorded but no AWS resource was changed."
        )
    }
    return job


@app.get("/accounts/{aid}/finops/security-summary")
def finops_security_summary(aid):
    ensure(aid)
    d = data(aid)
    recs = d.get("recommendations", [])
    findings = d.get("prowler_findings", []) + d.get("findings", [])
    savings = sum(float(x.get("monthly_savings", 0)) for x in recs)

    return {
        "monthly_savings_estimate": round(savings, 2),
        "security_findings": len(findings),
        "critical_high": sum(
            1 for x in findings
            if str(x.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ),
        "cost_summary": d.get("cost_summary", {}),
    }

@app.get("/accounts/{aid}/dashboard")
def dashboard(aid):
    ensure(aid); d=data(aid)
    return {"account_id":aid,"resources":d["resources"],"findings":d["findings"],"costs":d["costs"],"cost_summary":d["cost_summary"],"recommendations":d["recommendations"],"errors":d["errors"],"last_sync":d["last_sync"]}
