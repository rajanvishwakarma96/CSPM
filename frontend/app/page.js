"use client";
import {useEffect,useState} from "react";
const API=process.env.NEXT_PUBLIC_API_URL||"http://localhost:8000";
export default function Page(){
 const [acs,setAcs]=useState([]),[aid,setAid]=useState(""),[res,setRes]=useState([]),[find,setFind]=useState([]),[cost,setCost]=useState([]);
 const [f,setF]=useState({account_name:"Production",account_id:"",role_arn:"",external_id:"",regions:["ap-south-1"]});
 async function loadA(){let x=await fetch(API+"/accounts").then(r=>r.json());setAcs(x);if(!aid&&x[0])setAid(x[0].id)}
 async function load(){if(!aid)return;let [a,b,c]=await Promise.all(["resources","findings","costs"].map(k=>fetch(`${API}/accounts/${aid}/${k}`).then(r=>r.json())));setRes(a);setFind(b);setCost(c)}
 useEffect(()=>{loadA()},[]);useEffect(()=>{load()},[aid]);
 async function add(){let x=await fetch(API+"/accounts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(f)}).then(r=>r.json());await loadA();setAid(x.id)}
 async function run(path){let x=await fetch(API+path,{method:"POST"}).then(r=>r.json());alert(JSON.stringify(x,null,2));load()}
 async function fix(x){let action=x.title.toLowerCase().includes("s3")?"S3_BLOCK_PUBLIC_ACCESS":null;if(!action)return alert("No allow-listed fix for this finding yet.");let p=await fetch(`${API}/accounts/${aid}/remediation/plans`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action,resource_id:x.resource_id,finding_id:x.id})}).then(r=>r.json());alert(JSON.stringify(p,null,2))}
 return <main><header><div><small>CLOUD AUTOPILOT V2</small><h1>AWS Security + FinOps</h1><p>Real discovery · Prowler · Cost Explorer · guarded remediation</p></div><select value={aid} onChange={e=>setAid(e.target.value)}><option value="">Account</option>{acs.map(a=><option key={a.id} value={a.id}>{a.account_name}</option>)}</select></header>
 <section className="cards"><Card t="Resources" v={res.length}/><Card t="Findings" v={find.length}/><Card t="High/Critical" v={find.filter(x=>["HIGH","CRITICAL"].includes(x.severity)).length}/><Card t="Cost" v={"$"+cost.reduce((a,x)=>a+Number(x.amount),0).toFixed(2)}/></section>
 <section className="panel"><h2>Connect AWS</h2><div className="form">{["account_name","account_id","role_arn","external_id"].map(k=><input key={k} placeholder={k} value={f[k]} onChange={e=>setF({...f,[k]:e.target.value})}/>)}<button onClick={add}>Connect</button></div></section>
 <section className="panel"><h2>Run</h2><div className="form"><button disabled={!aid} onClick={()=>run(`/accounts/${aid}/discover`)}>Discover</button><button disabled={!aid} onClick={()=>run(`/accounts/${aid}/security/scan`)}>Prowler scan</button><button disabled={!aid} onClick={()=>run(`/accounts/${aid}/costs/sync`)}>Cost Explorer</button></div></section>
 <div className="two"><section className="panel"><h2>Security findings</h2>{find.slice(0,40).map(x=><div className="item" key={x.id}><b className={"pill "+x.severity.toLowerCase()}>{x.severity}</b><div><strong>{x.title}</strong><div className="muted">{x.check_id} · {x.resource_id}</div><p>{x.description}</p><button className="secondary" onClick={()=>fix(x)}>Create remediation plan</button></div></div>)}</section>
 <section className="panel"><h2>Cost by service</h2>{cost.map(x=><div className="cost" key={x.id}><span>{x.service}</span><strong>${Number(x.amount).toFixed(2)}</strong></div>)}</section></div>
 <section className="panel"><h2>Inventory</h2><div className="table">{res.map(x=><div className="row" key={x.id}><span>{x.resource_type}</span><strong>{x.name}</strong><span>{x.region}</span><span>{x.resource_id}</span></div>)}</div></section>
 </main>}
function Card({t,v}){return <div className="card"><span>{t}</span><strong>{v}</strong></div>}