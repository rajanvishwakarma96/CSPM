import json,uuid
from sqlalchemy import text
from app.db import engine,now
from app.services.ai import savings

def generate(account_id):
    with engine.begin() as c:
        c.execute(text('''CREATE TABLE IF NOT EXISTS recommendations(
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL, name TEXT, monthly_savings REAL NOT NULL,
        basis TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)'''))
        rows=c.execute(text('SELECT * FROM resources WHERE account_id=:a'),{'a':account_id}).mappings().all()
        c.execute(text('DELETE FROM recommendations WHERE account_id=:a'),{'a':account_id})
        out=[]
        for r in rows:
            item=dict(r); item['data']=json.loads(r['data'])
            x=savings(item)
            if x['monthly_savings']>0:
                rid=str(uuid.uuid4())
                out.append({'id':rid,'resource_type':r['resource_type'],'resource_id':r['resource_id'],'name':r['name'],**x})
                c.execute(text('''INSERT INTO recommendations VALUES
                (:id,:a,:type,:rid,:name,:amount,:basis,'OPEN',:dt)'''),
                {'id':rid,'a':account_id,'type':r['resource_type'],'rid':r['resource_id'],
                 'name':r['name'],'amount':x['monthly_savings'],'basis':x['basis'],'dt':now()})
    return out
