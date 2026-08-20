import json,os,uuid
from fastapi import HTTPException
from sqlalchemy import text
from app.db import engine,now
from app.aws import assume_role

ALLOWED={"S3_BLOCK_PUBLIC_ACCESS","EBS_DELETE_UNATTACHED"}

def plan(account_id,finding_id,action,resource_id):
    if action not in ALLOWED: raise HTTPException(400,"Action is not allow-listed")
    pid=str(uuid.uuid4())
    with engine.begin() as c:
        c.execute(text("""INSERT INTO remediation_plans
        VALUES (:id,:a,:f,:action,:rid,0,0,NULL,:dt,NULL)"""),{
        "id":pid,"a":account_id,"f":finding_id,"action":action,"rid":resource_id,"dt":now()})
    return pid

def execute(a,pid,approved):
    if not approved: raise HTTPException(400,"Explicit approval required")
    if os.getenv("ENABLE_REMEDIATION","false").lower()!="true":
        raise HTTPException(403,"Remediation is disabled")
    with engine.begin() as c:
        p=c.execute(text("SELECT * FROM remediation_plans WHERE id=:id"),{"id":pid}).mappings().first()
    if not p: raise HTTPException(404,"Plan not found")
    if p["executed"]: return json.loads(p["result"])
    s=assume_role(a["role_arn"],a.get("external_id"),a["regions"][0])
    if p["action"]=="S3_BLOCK_PUBLIC_ACCESS":
        s.client("s3").put_public_access_block(Bucket=p["resource_id"],
          PublicAccessBlockConfiguration={"BlockPublicAcls":True,"IgnorePublicAcls":True,
          "BlockPublicPolicy":True,"RestrictPublicBuckets":True})
        result={"action":p["action"],"bucket":p["resource_id"],"status":"applied"}
    elif p["action"]=="EBS_DELETE_UNATTACHED":
        ec2=s.client("ec2",region_name=a["regions"][0])
        v=ec2.describe_volumes(VolumeIds=[p["resource_id"]])["Volumes"][0]
        if v.get("Attachments"): raise HTTPException(409,"Volume is attached")
        snap=ec2.create_snapshot(VolumeId=p["resource_id"],
          Description="Cloud Autopilot pre-delete snapshot")
        ec2.delete_volume(VolumeId=p["resource_id"])
        result={"action":p["action"],"volume":p["resource_id"],
                "snapshot":snap["SnapshotId"],"status":"applied"}
    else: raise HTTPException(400,"Unsupported action")
    with engine.begin() as c:
        c.execute(text("""UPDATE remediation_plans
        SET approved=1,executed=1,result=:r,executed_at=:dt WHERE id=:id"""),
        {"id":pid,"r":json.dumps(result),"dt":now()})
    return result
