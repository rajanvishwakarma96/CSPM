import json,uuid
from sqlalchemy import text
from app.db import engine,now
from app.aws import assume_role,caller_account,discover

def run(a):
    session=assume_role(a["role_arn"],a.get("external_id"),a["regions"][0])
    aid=caller_account(session)
    rows=discover(a)
    with engine.begin() as c:
        c.execute(text("DELETE FROM resources WHERE account_id=:a"),{"a":a["id"]})
        for r in rows:
            c.execute(text("""INSERT INTO resources VALUES
            (:id,:a,:t,:rid,:region,:name,:data,:dt)"""),{
            "id":str(uuid.uuid4()),"a":a["id"],"t":r["resource_type"],
            "rid":r["resource_id"],"region":r["region"],"name":r["name"],
            "data":json.dumps(r["data"],default=str),"dt":now()})
    return aid,rows
