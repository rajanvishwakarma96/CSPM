import json,os,subprocess,uuid
from pathlib import Path
from sqlalchemy import text
from app.db import engine,now

def norm(x):
    fi=x.get("finding_info",{}) or {}
    resources=x.get("resources") or []
    rid=x.get("resource_uid") or (resources[0].get("uid","") if resources else "")
    return {
      "severity":str(x.get("severity") or fi.get("severity") or "UNKNOWN").upper(),
      "title":str(fi.get("title") or x.get("title") or x.get("check_id") or "Prowler finding"),
      "check_id":str(x.get("check_id") or fi.get("uid") or ""),
      "resource_id":str(rid),"resource_type":str(x.get("resource_type") or ""),
      "region":str(x.get("region") or ""),
      "description":str(fi.get("desc") or x.get("description") or x.get("message") or ""),
      "recommendation":str(fi.get("remediation",{}).get("desc") or x.get("remediation") or "Review Prowler remediation guidance."),
      "raw":json.dumps(x,default=str)}

def run(a):
    root=Path(os.getenv("PROWLER_OUTPUT_DIR","/tmp/prowler")); root.mkdir(parents=True,exist_ok=True)
    d=root/str(uuid.uuid4()); d.mkdir()
    cmd=["prowler","aws","--role",a["role_arn"],"--output-formats","json-ocsf","--output-directory",str(d)]
    if a.get("external_id"): cmd += ["--external-id",a["external_id"]]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=1800)
    findings=[]
    for f in d.rglob("*.json"):
        try: obj=json.loads(f.read_text())
        except Exception: continue
        for x in (obj if isinstance(obj,list) else [obj]): findings.append(norm(x))
    with engine.begin() as c:
        c.execute(text("DELETE FROM findings WHERE account_id=:a"),{"a":a["id"]})
        for x in findings:
            c.execute(text("""INSERT INTO findings VALUES
            (:id,:a,:severity,:title,:check_id,:rid,:rtype,:region,:status,
             :description,:recommendation,:raw,:dt)"""),{
             "id":str(uuid.uuid4()),"a":a["id"],"status":"OPEN","dt":now(),
             "rid":x["resource_id"],"rtype":x["resource_type"],**{k:x[k] for k in
             ["severity","title","check_id","region","description","recommendation","raw"]}})
    return {"returncode":p.returncode,"files":len(list(d.rglob("*.json"))),
            "findings":len(findings),"stderr":p.stderr[-3000:]}
