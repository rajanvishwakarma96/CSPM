import json,uuid
from datetime import date
from sqlalchemy import text
from app.db import engine,now
from app.aws import assume_role

def run(a):
    today=date.today(); start=today.replace(day=1)
    end=date(today.year+1,1,1) if today.month==12 else date(today.year,today.month+1,1)
    s=assume_role(a["role_arn"],a.get("external_id"),a["regions"][0])
    ce=s.client("ce",region_name="us-east-1")
    r=ce.get_cost_and_usage(TimePeriod={"Start":start.isoformat(),"End":end.isoformat()},
      Granularity="MONTHLY",Metrics=["UnblendedCost"],
      GroupBy=[{"Type":"DIMENSION","Key":"SERVICE"}])
    rows=[]
    for period in r.get("ResultsByTime",[]):
        for g in period.get("Groups",[]):
            m=g["Metrics"]["UnblendedCost"]
            rows.append({"service":g["Keys"][0],"amount":float(m["Amount"]),
              "currency":m.get("Unit","USD"),"start":period["TimePeriod"]["Start"],
              "end":period["TimePeriod"]["End"],"raw":json.dumps(g)})
    with engine.begin() as c:
        c.execute(text("DELETE FROM costs WHERE account_id=:a"),{"a":a["id"]})
        for x in rows:
            c.execute(text("INSERT INTO costs VALUES (:id,:a,:s,:amount,:cur,:start,:end,:raw,:dt)"),
              {"id":str(uuid.uuid4()),"a":a["id"],"s":x["service"],"amount":x["amount"],
               "cur":x["currency"],"start":x["start"],"end":x["end"],"raw":x["raw"],"dt":now()})
    return rows
