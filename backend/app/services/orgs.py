import json
from sqlalchemy import text
from app.db import engine,now
from app.aws import assume_role

def discover_org(a):
    s=assume_role(a['role_arn'],a.get('external_id'),a['regions'][0])
    client=s.client('organizations',region_name='us-east-1')
    rows=[]
    for page in client.get_paginator('list_accounts').paginate():
        rows.extend(page['Accounts'])
    return rows

def save_members(parent,members):
    ids=[]
    with engine.begin() as c:
        for m in members:
            aid='org-'+m['Id']; ids.append(aid)
            c.execute(text('''INSERT INTO aws_accounts
            (id,account_name,account_id,role_arn,external_id,regions,status,created_at)
            VALUES (:id,:name,:account_id,:role,:ext,:regions,:status,:dt)
            ON CONFLICT(id) DO UPDATE SET account_name=:name,status=:status'''),
            {'id':aid,'name':m['Name'],'account_id':m['Id'],
             'role':parent['role_arn'],'ext':parent.get('external_id'),
             'regions':json.dumps(parent['regions']),'status':m['Status'],'dt':now()})
    return ids
