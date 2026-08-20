import json,os,uuid
from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text
from app.db import engine,init_db,now
from app.services.inventory import run as discover
from app.services.prowler import run as prowler
from app.services.cost import run as costs
from app.services.remediation import plan,execute

init_db()
app=FastAPI(title="Cloud Autopilot V2",version="2.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

class Account(BaseModel):
    account_name:str
    account_id:str|None=None
    role_arn:str
    external_id:str|None=None
    regions:list[str]=["ap-south-1"]

class Plan(BaseModel):
    action:str
    resource_id:str
    finding_id:str|None=None

class Approval(BaseModel):
    approved:bool

def account(aid):
    with engine.begin() as c:
        x=c.execute(text("SELECT * FROM aws_accounts WHERE id=:id"),{"id":aid}).mappings().first()
    if not x: raise HTTPException(404,"Account not found")
    x=dict(x);x["regions"]=json.loads(x["regions"]);return x

@app.get("/health")
def health(): return {"status":"ok","remediation_enabled":os.getenv("ENABLE_REMEDIATION","false").lower()=="true"}

@app.post("/accounts")
def add(x:Account):
    aid=str(uuid.uuid4())
    with engine.begin() as c:
        c.execute(text("INSERT INTO aws_accounts VALUES (:id,:name,:account_id,:role,:ext,:regions,:status,:dt)"),
          {"id":aid,"name":x.account_name,"account_id":x.account_id,"role":x.role_arn,
           "ext":x.external_id,"regions":json.dumps(x.regions),"status":"CONNECTED","dt":now()})
    return {"id":aid}

@app.get("/accounts")
def accounts():
    with engine.begin() as c:return [dict(x) for x in c.execute(text("SELECT * FROM aws_accounts")).mappings().all()]

@app.post("/accounts/{aid}/discover")
def do_discover(aid):
    try:
        real,rows=discover(account(aid));return {"aws_account_id":real,"resources":len(rows)}
    except Exception as e: raise HTTPException(400,f"Discovery failed: {e}")

@app.post("/accounts/{aid}/security/scan")
def do_scan(aid):
    try:return prowler(account(aid))
    except Exception as e: raise HTTPException(400,f"Prowler failed: {e}")

@app.post("/accounts/{aid}/costs/sync")
def do_cost(aid):
    try:return {"rows":len(costs(account(aid)))}
    except Exception as e: raise HTTPException(400,f"Cost Explorer failed: {e}")

@app.get("/accounts/{aid}/resources")
def resources(aid):
    account(aid)
    with engine.begin() as c:return [dict(x) for x in c.execute(text("SELECT * FROM resources WHERE account_id=:a"),{"a":aid}).mappings().all()]

@app.get("/accounts/{aid}/findings")
def findings(aid):
    account(aid)
    with engine.begin() as c:return [dict(x) for x in c.execute(text("SELECT * FROM findings WHERE account_id=:a ORDER BY severity"),{"a":aid}).mappings().all()]

@app.get("/accounts/{aid}/costs")
def cost_rows(aid):
    account(aid)
    with engine.begin() as c:return [dict(x) for x in c.execute(text("SELECT * FROM costs WHERE account_id=:a ORDER BY amount DESC"),{"a":aid}).mappings().all()]

@app.post("/accounts/{aid}/remediation/plans")
def create(aid,x:Plan):
    account(aid);pid=plan(aid,x.finding_id,x.action,x.resource_id)
    return {"plan_id":pid,"approval_required":True,"execution_enabled":os.getenv("ENABLE_REMEDIATION","false").lower()=="true"}

@app.post("/accounts/{aid}/remediation/{pid}/execute")
def run_fix(aid,pid,x:Approval): return execute(account(aid),pid,x.approved)
