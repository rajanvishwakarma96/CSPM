import os, uuid, datetime, json, subprocess, shutil
from pathlib import Path
from typing import Optional
import boto3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, DateTime, Float, Text, JSON, ForeignKey, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

VERSION='2.5.0'
DB=os.getenv('DATABASE_URL','postgresql+psycopg://cloud:cloud@postgres:5432/cloud_autopilot')
engine=create_engine(DB,pool_pre_ping=True)
Session=sessionmaker(bind=engine,autoflush=False,autocommit=False)
class Base(DeclarativeBase): pass
class CloudAccount(Base):
 __tablename__='cloud_accounts'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_name:Mapped[str]=mapped_column(String(200)); account_id:Mapped[str]=mapped_column(String(32),index=True); role_arn:Mapped[str]=mapped_column(String(500)); external_id:Mapped[Optional[str]]=mapped_column(String(300),nullable=True); regions:Mapped[list]=mapped_column(JSON,default=list); status:Mapped[str]=mapped_column(String(30),default='ACTIVE'); created_at:Mapped[datetime.datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.datetime.now(datetime.timezone.utc))
class Resource(Base):
 __tablename__='resources'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[str]=mapped_column(String(36),ForeignKey('cloud_accounts.id'),index=True); resource_type:Mapped[str]=mapped_column(String(80)); resource_id:Mapped[str]=mapped_column(String(500),index=True); name:Mapped[Optional[str]]=mapped_column(String(300),nullable=True); region:Mapped[str]=mapped_column(String(80)); metadata_json:Mapped[dict]=mapped_column('metadata',JSON,default=dict); last_seen_at:Mapped[datetime.datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.datetime.now(datetime.timezone.utc))
class SecurityFinding(Base):
 __tablename__='security_findings'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[str]=mapped_column(String(36),ForeignKey('cloud_accounts.id'),index=True); provider:Mapped[str]=mapped_column(String(50),default='prowler'); check_id:Mapped[Optional[str]]=mapped_column(String(300),nullable=True); severity:Mapped[str]=mapped_column(String(30)); title:Mapped[str]=mapped_column(String(500)); description:Mapped[Optional[str]]=mapped_column(Text,nullable=True); resource_id:Mapped[Optional[str]]=mapped_column(String(500),nullable=True); status:Mapped[str]=mapped_column(String(30),default='OPEN'); raw:Mapped[dict]=mapped_column(JSON,default=dict); created_at:Mapped[datetime.datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.datetime.now(datetime.timezone.utc))
class CostDaily(Base):
 __tablename__='cost_daily'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[str]=mapped_column(String(36),ForeignKey('cloud_accounts.id'),index=True); date:Mapped[str]=mapped_column(String(20),index=True); service:Mapped[str]=mapped_column(String(300)); amount:Mapped[float]=mapped_column(Float); currency:Mapped[str]=mapped_column(String(10),default='USD')
class Recommendation(Base):
 __tablename__='recommendations'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[str]=mapped_column(String(36),ForeignKey('cloud_accounts.id'),index=True); category:Mapped[str]=mapped_column(String(100)); title:Mapped[str]=mapped_column(String(500)); resource_id:Mapped[Optional[str]]=mapped_column(String(500),nullable=True); monthly_savings:Mapped[float]=mapped_column(Float,default=0); status:Mapped[str]=mapped_column(String(30),default='OPEN')
class RemediationJob(Base):
 __tablename__='remediation_jobs'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[str]=mapped_column(String(36),ForeignKey('cloud_accounts.id'),index=True); action:Mapped[str]=mapped_column(String(100)); resource_id:Mapped[Optional[str]]=mapped_column(String(500),nullable=True); reason:Mapped[Optional[str]]=mapped_column(Text,nullable=True); status:Mapped[str]=mapped_column(String(40),default='PENDING_APPROVAL'); requested_by:Mapped[str]=mapped_column(String(200),default='operator'); approved_by:Mapped[Optional[str]]=mapped_column(String(200),nullable=True); created_at:Mapped[datetime.datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.datetime.now(datetime.timezone.utc)); approved_at:Mapped[Optional[datetime.datetime]]=mapped_column(DateTime(timezone=True),nullable=True); executed_at:Mapped[Optional[datetime.datetime]]=mapped_column(DateTime(timezone=True),nullable=True); result:Mapped[dict]=mapped_column(JSON,default=dict)
class AuditLog(Base):
 __tablename__='audit_logs'; id:Mapped[str]=mapped_column(String(36),primary_key=True); account_id:Mapped[Optional[str]]=mapped_column(String(36),nullable=True,index=True); action:Mapped[str]=mapped_column(String(200)); actor:Mapped[str]=mapped_column(String(200),default='system'); details:Mapped[dict]=mapped_column(JSON,default=dict); created_at:Mapped[datetime.datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.datetime.now(datetime.timezone.utc))
Base.metadata.create_all(engine)
app=FastAPI(title='Cloud Autopilot',version=VERSION)
app.add_middleware(CORSMiddleware,allow_origins=['*'],allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
def now():return datetime.datetime.now(datetime.timezone.utc)
def sid():return str(uuid.uuid4())
def account(db,aid):
 a=db.get(CloudAccount,aid)
 if not a:raise HTTPException(404,'AWS account not found')
 return a
def aws(a,region=None):
 region=region or (a.regions or ['us-east-1'])[0]; sts=boto3.client('sts',region_name=region); p={'RoleArn':a.role_arn,'RoleSessionName':'CloudAutopilotV25'}
 if a.external_id:p['ExternalId']=a.external_id
 c=sts.assume_role(**p)['Credentials']; return boto3.Session(aws_access_key_id=c['AccessKeyId'],aws_secret_access_key=c['SecretAccessKey'],aws_session_token=c['SessionToken'],region_name=region)
def audit(db,aid,action,details={},actor='system'):db.add(AuditLog(id=sid(),account_id=aid,action=action,actor=actor,details=details));db.commit()
class AccountIn(BaseModel): account_name:str; account_id:str; role_arn:str; external_id:Optional[str]=None; regions:list[str]=Field(default_factory=lambda:['us-east-1'])
class RemediationIn(BaseModel): action:str; resource_id:Optional[str]=None; reason:Optional[str]=None; dry_run:bool=True
@app.get('/')
def root():return {'service':'Cloud Autopilot','version':VERSION,'status':'running','database':'postgresql','queue':'redis/celery'}
@app.get('/health')
def health():
 db=Session();
 try:db.execute(text('SELECT 1'));return {'status':'ok','version':VERSION,'postgres':'ok','timestamp':now().isoformat()}
 finally:db.close()
@app.get('/version')
def version():return {'version':VERSION,'features':['PostgreSQL persistence','Redis/Celery foundation','AWS discovery','Cost Explorer','FinOps','Prowler','AI explanations','approval remediation','audit logs','multi-account foundation']}
@app.get('/accounts')
def accounts():
 db=Session();
 try:return [{'id':a.id,'account_name':a.account_name,'account_id':a.account_id,'role_arn':a.role_arn,'regions':a.regions,'status':a.status} for a in db.query(CloudAccount).all()]
 finally:db.close()
@app.post('/accounts')
def create(x:AccountIn):
 db=Session();a=CloudAccount(id=sid(),**x.model_dump());db.add(a);db.commit();db.refresh(a);audit(db,a.id,'ACCOUNT_CREATED',{'aws_account_id':a.account_id});return {'id':a.id,'account_name':a.account_name,'account_id':a.account_id,'role_arn':a.role_arn,'regions':a.regions}
@app.delete('/accounts/{aid}')
def delete(aid):
 db=Session();account(db,aid);db.query(Resource).filter_by(account_id=aid).delete();db.query(SecurityFinding).filter_by(account_id=aid).delete();db.query(CostDaily).filter_by(account_id=aid).delete();db.query(Recommendation).filter_by(account_id=aid).delete();db.query(RemediationJob).filter_by(account_id=aid).delete();db.query(AuditLog).filter_by(account_id=aid).delete();db.query(CloudAccount).filter_by(id=aid).delete();db.commit();return {'status':'deleted','account_id':aid}
@app.post('/accounts/{aid}/discover')
def discover(aid):
 db=Session();a=account(db,aid);rows=[];errors={}
 for region in a.regions:
  try:s=aws(a,region)
  except Exception as e:errors[f'session:{region}']=str(e);continue
  try:
   ec2=s.client('ec2')
   for rr in ec2.describe_instances().get('Reservations',[]):
    for i in rr.get('Instances',[]):rows.append(('EC2',i['InstanceId'],i['InstanceId'],region,{'state':i.get('State',{}).get('Name'),'instance_type':i.get('InstanceType')}))
   for v in ec2.describe_volumes().get('Volumes',[]):rows.append(('EBS',v['VolumeId'],v['VolumeId'],region,{'size_gb':v.get('Size',0),'attached':bool(v.get('Attachments'))}))
  except Exception as e:errors[f'ec2:{region}']=str(e)
  try:
   for r in s.client('rds').describe_db_instances().get('DBInstances',[]):rows.append(('RDS',r['DBInstanceIdentifier'],r['DBInstanceIdentifier'],region,{'status':r.get('DBInstanceStatus'),'engine':r.get('Engine')}))
  except Exception as e:errors[f'rds:{region}']=str(e)
 try:
  for b in aws(a).client('s3').list_buckets().get('Buckets',[]):rows.append(('S3',b['Name'],b['Name'],'global',{}))
 except Exception as e:errors['s3']=str(e)
 db.query(Resource).filter_by(account_id=aid).delete()
 for typ,rid,name,region,meta in rows:db.add(Resource(id=sid(),account_id=aid,resource_type=typ,resource_id=rid,name=name,region=region,metadata_json=meta,last_seen_at=now()))
 db.commit();audit(db,aid,'DISCOVERY_COMPLETED',{'resource_count':len(rows),'errors':errors});return {'status':'OK','resource_count':len(rows),'errors':errors}
@app.get('/accounts/{aid}/resources')
def resources(aid):
 db=Session();account(db,aid);return [{'resource_type':r.resource_type,'resource_id':r.resource_id,'name':r.name,'region':r.region,'data':r.metadata_json} for r in db.query(Resource).filter_by(account_id=aid).all()]
@app.post('/accounts/{aid}/costs/sync')
def cost_sync(aid,days:int=30):
 if days not in (7,14,30,60,90):raise HTTPException(400,'days must be 7, 14, 30, 60 or 90')
 db=Session();a=account(db,aid);end=datetime.date.today();start=end-datetime.timedelta(days=days)
 try:r=aws(a,'us-east-1').client('ce',region_name='us-east-1').get_cost_and_usage(TimePeriod={'Start':start.isoformat(),'End':end.isoformat()},Granularity='DAILY',Metrics=['UnblendedCost'],GroupBy=[{'Type':'DIMENSION','Key':'SERVICE'}])
 except Exception as e:raise HTTPException(400,f'Cost Explorer failed: {e}')
 db.query(CostDaily).filter_by(account_id=aid).delete()
 for day in r.get('ResultsByTime',[]):
  for g in day.get('Groups',[]):db.add(CostDaily(id=sid(),account_id=aid,date=day['TimePeriod']['Start'],service=g['Keys'][0],amount=float(g['Metrics']['UnblendedCost']['Amount'])))
 db.commit();audit(db,aid,'COST_SYNC_COMPLETED',{'days':days});return {'status':'OK','days':days}
@app.get('/accounts/{aid}/costs')
def costs(aid):
 db=Session();account(db,aid);d={}
 for r in db.query(CostDaily).filter_by(account_id=aid).all():d[r.service]=d.get(r.service,0)+r.amount
 return [{'service':k,'amount':round(v,2)} for k,v in sorted(d.items(),key=lambda x:x[1],reverse=True)]
def prowler_ok():return shutil.which('prowler') is not None
@app.post('/accounts/{aid}/prowler/scan')
def prowler(aid):
 db=Session();account(db,aid)
 if not prowler_ok():raise HTTPException(503,'Prowler is not installed')
 out=f'/tmp/prowler-{aid}-{sid()}';os.makedirs(out,exist_ok=True)
 try:p=subprocess.run(['prowler','aws','--output-directory',out,'--output-formats','json-ocsf'],capture_output=True,text=True,timeout=900)
 except subprocess.TimeoutExpired:raise HTTPException(504,'Prowler scan timed out')
 findings=[]
 for f in Path(out).glob('*.json'):
  try:
   x=json.loads(f.read_text());findings.extend(x if isinstance(x,list) else x.get('findings',[]))
  except Exception:pass
 db.query(SecurityFinding).filter_by(account_id=aid).delete()
 for x in findings:
  info=x.get('finding_info',{}) or {};db.add(SecurityFinding(id=sid(),account_id=aid,provider='prowler',check_id=info.get('uid') or x.get('check_id'),severity=str(x.get('severity') or info.get('severity') or 'UNKNOWN').upper(),title=info.get('title') or x.get('title') or 'Prowler finding',description=x.get('message'),resource_id=(x.get('resource') or {}).get('uid') or x.get('resource_uid') or x.get('resource_id'),raw=x))
 db.commit();audit(db,aid,'PROWLER_SCAN_COMPLETED',{'findings':len(findings),'return_code':p.returncode});return {'status':'completed','findings_count':len(findings)}
@app.get('/accounts/{aid}/prowler/status')
def prowler_status(aid):
 db=Session();account(db,aid);n=db.query(SecurityFinding).filter_by(account_id=aid).count();return {'installed':prowler_ok(),'findings_count':n}
@app.get('/accounts/{aid}/security/findings')
def findings(aid):
 db=Session();account(db,aid);return [{'id':f.id,'severity':f.severity,'title':f.title,'description':f.description,'resource_id':f.resource_id,'status':f.status,'check_id':f.check_id} for f in db.query(SecurityFinding).filter_by(account_id=aid).all()]
@app.post('/accounts/{aid}/security/explain/{fid}')
def explain(aid,fid):
 db=Session();account(db,aid);f=db.get(SecurityFinding,fid)
 if not f or f.account_id!=aid:raise HTTPException(404,'Finding not found')
 return {'finding':f.title,'severity':f.severity,'risk_score':{'CRITICAL':100,'HIGH':85,'MEDIUM':60,'LOW':30}.get(f.severity,10),'executive_summary':f'{f.title} may increase security or compliance risk.','recommended_action':'Validate the finding, then use approval-based remediation.','ai_provider':'rule-based-v2.5','resource_id':f.resource_id}
@app.post('/accounts/{aid}/recommendations/generate')
def genrec(aid):
 db=Session();account(db,aid);db.query(Recommendation).filter_by(account_id=aid).delete()
 for r in db.query(Resource).filter_by(account_id=aid).all():
  m=r.metadata_json or {}
  if r.resource_type=='EBS' and not m.get('attached'):db.add(Recommendation(id=sid(),account_id=aid,category='EBS',title='Delete unattached EBS volume',resource_id=r.resource_id,monthly_savings=round(float(m.get('size_gb',0))*.08,2)))
  elif r.resource_type=='EC2' and m.get('state')=='stopped':db.add(Recommendation(id=sid(),account_id=aid,category='EC2',title='Review stopped EC2 instance',resource_id=r.resource_id,monthly_savings=5))
 db.commit();return [{'id':r.id,'title':r.title,'resource_id':r.resource_id,'monthly_savings':r.monthly_savings} for r in db.query(Recommendation).filter_by(account_id=aid).all()]
@app.get('/accounts/{aid}/recommendations')
def recs(aid):
 db=Session();account(db,aid);return [{'id':r.id,'title':r.title,'resource_id':r.resource_id,'monthly_savings':r.monthly_savings,'status':r.status} for r in db.query(Recommendation).filter_by(account_id=aid).all()]
@app.post('/accounts/{aid}/remediation/preview')
def preview(aid,x:RemediationIn):
 db=Session();account(db,aid);allowed={'EBS_DELETE_UNATTACHED','EC2_STOP_UNUSED','RELEASE_UNUSED_ELASTIC_IP','S3_BLOCK_PUBLIC_ACCESS'}
 if x.action not in allowed:raise HTTPException(400,'Unsupported remediation action')
 return {'safe':True,'requires_approval':True,'action':x.action,'resource_id':x.resource_id,'dry_run':True}
@app.post('/accounts/{aid}/remediation/request')
def request(aid,x:RemediationIn):
 db=Session();account(db,aid);j=RemediationJob(id=sid(),account_id=aid,action=x.action,resource_id=x.resource_id,reason=x.reason);db.add(j);db.commit();db.refresh(j);audit(db,aid,'REMEDIATION_REQUESTED',{'job_id':j.id,'action':j.action});return {'id':j.id,'status':j.status}
@app.get('/remediation/jobs')
def jobs():
 db=Session();return [{'id':j.id,'account_id':j.account_id,'action':j.action,'resource_id':j.resource_id,'status':j.status,'created_at':j.created_at.isoformat()} for j in db.query(RemediationJob).order_by(RemediationJob.created_at.desc()).all()]
@app.post('/remediation/jobs/{jid}/approve')
def approve(jid,actor='operator'):
 db=Session();j=db.get(RemediationJob,jid)
 if not j:raise HTTPException(404,'Remediation job not found')
 if j.status!='PENDING_APPROVAL':raise HTTPException(400,'Job is not awaiting approval')
 j.status='APPROVED';j.approved_by=actor;j.approved_at=now();db.commit();audit(db,j.account_id,'REMEDIATION_APPROVED',{'job_id':jid},actor);return {'id':jid,'status':j.status}
@app.post('/remediation/jobs/{jid}/execute')
def execute(jid):
 db=Session();j=db.get(RemediationJob,jid)
 if not j:raise HTTPException(404,'Remediation job not found')
 if j.status!='APPROVED':raise HTTPException(400,'Job must be approved first')
 j.status='EXECUTION_BLOCKED_SAFE_MODE';j.executed_at=now();j.result={'message':'V2.5 safe mode: no destructive AWS mutation performed.'};db.commit();audit(db,j.account_id,'REMEDIATION_EXECUTION_BLOCKED',{'job_id':jid});return {'id':jid,'status':j.status,'result':j.result}
@app.get('/accounts/{aid}/audit')
def audit_logs(aid):
 db=Session();account(db,aid);return [{'id':x.id,'action':x.action,'actor':x.actor,'details':x.details,'created_at':x.created_at.isoformat()} for x in db.query(AuditLog).filter_by(account_id=aid).order_by(AuditLog.created_at.desc()).limit(200).all()]
@app.get('/accounts/{aid}/dashboard')
def dashboard(aid):
 db=Session();account(db,aid);rs=[{'resource_type':r.resource_type,'resource_id':r.resource_id,'name':r.name,'region':r.region,'data':r.metadata_json} for r in db.query(Resource).filter_by(account_id=aid).all()];fs=[{'id':f.id,'severity':f.severity,'title':f.title,'resource_id':f.resource_id,'status':f.status} for f in db.query(SecurityFinding).filter_by(account_id=aid).all()];rc=[{'id':r.id,'title':r.title,'resource_id':r.resource_id,'monthly_savings':r.monthly_savings} for r in db.query(Recommendation).filter_by(account_id=aid).all()];d={}
 for c in db.query(CostDaily).filter_by(account_id=aid).all():d[c.service]=d.get(c.service,0)+c.amount
 return {'account_id':aid,'resources':rs,'findings':fs,'recommendations':rc,'costs':[{'service':k,'amount':round(v,2)} for k,v in sorted(d.items(),key=lambda x:x[1],reverse=True)],'cost_summary':{'total':round(sum(d.values()),2)}}
