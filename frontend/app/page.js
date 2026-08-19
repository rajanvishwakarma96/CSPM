"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [accounts, setAccounts] = useState([]);
  const [selected, setSelected] = useState(null);
  const [resources, setResources] = useState([]);
  const [findings, setFindings] = useState([]);
  const [recs, setRecs] = useState([]);
  const [question, setQuestion] = useState("What should I fix first?");
  const [answer, setAnswer] = useState("");
  const [form, setForm] = useState({
    account_name: "Demo Production",
    account_id: "123456789012",
    role_arn: "",
    external_id: "",
    regions: ["ap-south-1"]
  });

  async function loadAccounts() {
    const r = await fetch(`${API}/accounts`);
    const data = await r.json();
    setAccounts(data);
    if (!selected && data[0]) setSelected(data[0].id);
  }

  async function loadData(id) {
    const [a, b, c] = await Promise.all([
      fetch(`${API}/accounts/${id}/resources`).then(x => x.json()),
      fetch(`${API}/accounts/${id}/findings`).then(x => x.json()),
      fetch(`${API}/accounts/${id}/recommendations`).then(x => x.json())
    ]);
    setResources(a);
    setFindings(b);
    setRecs(c);
  }

  useEffect(() => { loadAccounts(); }, []);
  useEffect(() => { if (selected) loadData(selected); }, [selected]);

  async function connect() {
    const r = await fetch(`${API}/accounts`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(form)
    });
    const data = await r.json();
    await loadAccounts();
    setSelected(data.id);
  }

  async function discover() {
    await fetch(`${API}/accounts/${selected}/discover`, {method:"POST"});
    await loadData(selected);
  }

  async function askAI() {
    setAnswer("Thinking...");
    const r = await fetch(`${API}/ai/explain`, {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({account_id:selected, question})
    });
    const data = await r.json();
    setAnswer(data.answer || "No answer");
  }

  return (
    <main>
      <header>
        <div>
          <div className="eyebrow">AWS CLOUD AUTOPILOT</div>
          <h1>Cloud Health Console</h1>
          <p>Discover → secure → optimize → explain → safely remediate.</p>
        </div>
        <button onClick={discover} disabled={!selected}>Discover AWS</button>
      </header>

      <section className="grid cards">
        <Card title="Resources" value={resources.length} />
        <Card title="Open findings" value={findings.length} />
        <Card title="Potential savings" value={`$${recs.reduce((a,x)=>a+Number(x.estimated_monthly_saving||0),0).toFixed(0)}/mo`} />
        <Card title="Critical/High" value={findings.filter(x=>["CRITICAL","HIGH"].includes(x.severity)).length} />
      </section>

      <section className="panel">
        <h2>Connect AWS</h2>
        <p className="muted">Demo mode is enabled by default. Set DEMO_MODE=false and provide a cross-account role ARN for real AWS discovery.</p>
        <div className="form">
          <input placeholder="Account name" value={form.account_name} onChange={e=>setForm({...form,account_name:e.target.value})}/>
          <input placeholder="AWS Account ID" value={form.account_id} onChange={e=>setForm({...form,account_id:e.target.value})}/>
          <input placeholder="Role ARN (real mode)" value={form.role_arn} onChange={e=>setForm({...form,role_arn:e.target.value})}/>
          <input placeholder="External ID (real mode)" value={form.external_id} onChange={e=>setForm({...form,external_id:e.target.value})}/>
          <button onClick={connect}>Add account</button>
        </div>
      </section>

      <div className="two">
        <section className="panel">
          <h2>Security findings</h2>
          {findings.length === 0 ? <p className="muted">Run discovery.</p> : findings.map(f=>(
            <div className="item" key={f.id}>
              <span className={`pill ${f.severity.toLowerCase()}`}>{f.severity}</span>
              <div>
                <strong>{f.title}</strong>
                <div className="muted">{f.resource_id}</div>
                <p>{f.description}</p>
                <button className="secondary" onClick={async()=>{
                  const r=await fetch(`${API}/remediation/${f.id}/plan`,{method:"POST"});
                  const d=await r.json();
                  alert(`${d.action}: approval=${d.approval_required}, execution=${d.execution_enabled}`);
                }}>Create safe fix plan</button>
              </div>
            </div>
          ))}
        </section>

        <section className="panel">
          <h2>Cost opportunities</h2>
          {recs.length === 0 ? <p className="muted">Run discovery.</p> : recs.map(r=>(
            <div className="item" key={r.id}>
              <span className="pill saving">SAVE</span>
              <div>
                <strong>{r.title}</strong>
                <div className="savingText">${Number(r.estimated_monthly_saving).toFixed(0)}/month estimated</div>
                <p>{r.reason}</p>
              </div>
            </div>
          ))}
        </section>
      </div>

      <section className="panel">
        <h2>AI SRE</h2>
        <div className="ai">
          <input value={question} onChange={e=>setQuestion(e.target.value)} />
          <button onClick={askAI} disabled={!selected}>Ask AI</button>
        </div>
        {answer && <pre className="answer">{answer}</pre>}
      </section>

      <section className="panel">
        <h2>Discovered resources</h2>
        <div className="table">
          {resources.map(r=><div className="row" key={r.id}>
            <span>{r.resource_type}</span><strong>{r.name}</strong><span>{r.region}</span><span>{r.resource_id}</span>
          </div>)}
        </div>
      </section>
    </main>
  );
}

function Card({title,value}) {
  return <div className="card"><div className="muted">{title}</div><div className="big">{value}</div></div>
}
