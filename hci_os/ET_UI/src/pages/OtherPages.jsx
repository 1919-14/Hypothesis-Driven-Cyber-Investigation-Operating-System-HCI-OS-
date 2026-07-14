import React from "react";
import { AUDIT_LOG } from "@/mock/data";
import { Lock, ShieldCheck, LineChart, TrendingUp, TrendingDown, Cpu, Server, Database, Activity, Waves, Loader } from "lucide-react";
import AttackGraph from "@/components/topology/AttackGraph";
import HumanGatePanel from "@/components/gate/HumanGatePanel";
import { useHealth } from "@/api/useHealth";

export const TopologyPage = () => (
  <div className="space-y-4">
    <div className="panel px-5 py-4">
      <div className="font-head font-bold text-[15px]">Attack Topology · Full View</div>
      <div className="text-[12.5px] text-[var(--hci-text-2)] mt-0.5">
        Live GNN visualization with GAT attention weights and blocked lateral paths.
      </div>
    </div>
    <AttackGraph />
  </div>
);

export const GatePage = () => (
  <div className="space-y-4">
    <div className="panel px-5 py-4">
      <div className="font-head font-bold text-[15px]">Human Gate · Pending Decisions</div>
      <div className="text-[12.5px] text-[var(--hci-text-2)] mt-0.5">
        Every autonomous action awaits a human before execution. SLA 15 minutes per gate.
      </div>
    </div>
    <HumanGatePanel />
  </div>
);

export const AuditPage = () => (
  <div className="space-y-4">
    <div className="panel px-5 py-4 flex items-center gap-3">
      <Lock size={18} className="text-[var(--hci-brand)]" />
      <div>
        <div className="font-head font-bold text-[15px]">Audit Chain · A12</div>
        <div className="text-[12.5px] text-[var(--hci-text-2)]">Immutable, hash-linked log of every agent and human action.</div>
      </div>
      <span className="ml-auto chip chip-clean"><ShieldCheck size={12}/> chain verified</span>
    </div>
    <div className="panel overflow-hidden">
      <table className="w-full text-[12.5px]">
        <thead className="bg-[#fbfcfd] border-b border-[var(--hci-border)]">
          <tr className="text-left label-caps">
            <th className="px-5 py-2.5">Timestamp</th>
            <th className="px-5 py-2.5">Actor</th>
            <th className="px-5 py-2.5">Event</th>
            <th className="px-5 py-2.5">Target</th>
            <th className="px-5 py-2.5">Hash</th>
          </tr>
        </thead>
        <tbody>
          {AUDIT_LOG.map((a, i) => (
            <tr key={i} className="border-b border-[var(--hci-border)] hover:bg-[#fbfcfd]">
              <td className="px-5 py-2.5 font-mono text-[var(--hci-brand)] font-semibold">{a.ts}</td>
              <td className="px-5 py-2.5 font-mono">{a.actor}</td>
              <td className="px-5 py-2.5"><span className="chip chip-info">{a.event}</span></td>
              <td className="px-5 py-2.5 font-mono">{a.target}</td>
              <td className="px-5 py-2.5 font-mono text-[var(--hci-text-3)]">{a.hash}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

const KpiCard = ({ icon: Icon, label, value, delta, tone }) => (
  <div className="panel px-5 py-4">
    <div className="flex items-center gap-2 label-caps">
      <Icon size={12} /> {label}
    </div>
    <div className="font-head font-bold text-[26px] mt-1.5 leading-tight">{value}</div>
    {delta && (
      <div className={`text-[12px] mt-1 font-mono flex items-center gap-1 ${tone === "up" ? "text-emerald-600" : "text-red-600"}`}>
        {tone === "up" ? <TrendingUp size={12} /> : <TrendingDown size={12} />} {delta}
      </div>
    )}
  </div>
);

export const ExecPage = () => (
  <div className="space-y-4">
    <div className="panel px-5 py-4">
      <div className="font-head font-bold text-[15px]">Executive View · CISO</div>
      <div className="text-[12.5px] text-[var(--hci-text-2)]">Mission impact, ROI, and federation status. Read-only.</div>
    </div>
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-3"><KpiCard icon={Activity} label="MTTD" value="4.2s" delta="-62% vs Q3" tone="up" /></div>
      <div className="col-span-3"><KpiCard icon={Activity} label="MTTR" value="43s" delta="-71% vs Q3" tone="up" /></div>
      <div className="col-span-3"><KpiCard icon={LineChart} label="Automation Ratio" value="86%" delta="+14 pts" tone="up" /></div>
      <div className="col-span-3"><KpiCard icon={Waves} label="False Positive Rate" value="0.4%" delta="-1.8 pts" tone="up" /></div>
    </div>
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-7 panel px-5 py-4">
        <div className="label-caps mb-3">Federation · Peer SOCs</div>
        {[
          { peer: "AIIMS Delhi", state: "SYNCED", latency: "31 ms" },
          { peer: "PowerGrid North", state: "SYNCED", latency: "47 ms" },
          { peer: "CBSE South Zone", state: "DEGRADED", latency: "412 ms" },
          { peer: "NPCI", state: "SYNCED", latency: "22 ms" },
        ].map((p) => (
          <div key={p.peer} className="flex items-center py-2 border-b border-[var(--hci-border)] last:border-0 text-[13px]">
            <span className="w-2 h-2 rounded-full mr-3" style={{ background: p.state === "SYNCED" ? "#059669" : "#ea580c" }} />
            <span className="font-semibold">{p.peer}</span>
            <span className="ml-auto font-mono text-[var(--hci-text-3)]">{p.latency}</span>
            <span className={`ml-3 chip ${p.state === "SYNCED" ? "chip-clean" : "chip-suspicious"}`}>{p.state}</span>
          </div>
        ))}
      </div>
      <div className="col-span-5 panel px-5 py-4">
        <div className="label-caps mb-3">Business Impact · This Quarter</div>
        <table className="w-full text-[13px]">
          <tbody>
            <tr className="border-b border-[var(--hci-border)]"><td className="py-2 text-[var(--hci-text-3)]">Incidents contained autonomously</td><td className="py-2 text-right font-mono font-semibold">248</td></tr>
            <tr className="border-b border-[var(--hci-border)]"><td className="py-2 text-[var(--hci-text-3)]">Crown-jewel breaches prevented</td><td className="py-2 text-right font-mono font-semibold">7</td></tr>
            <tr className="border-b border-[var(--hci-border)]"><td className="py-2 text-[var(--hci-text-3)]">Analyst hours saved</td><td className="py-2 text-right font-mono font-semibold">3 412 h</td></tr>
            <tr><td className="py-2 text-[var(--hci-text-3)]">Est. ₹ risk avoided</td><td className="py-2 text-right font-mono font-semibold text-emerald-600">₹ 41.2 Cr</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
);

export const HealthPage = () => {
  const { data, isLoading } = useHealth();

  const staticAgents = [
    { id: "A1",  name: "Sensor Bus",    status: "ok",   cpu: 12, mem: 22, kind: Waves },
    { id: "A2",  name: "HumanGate",     status: "ok",   cpu: 4,  mem: 8,  kind: Cpu },
    { id: "A3",  name: "Reasoner",      status: "ok",   cpu: 68, mem: 41, kind: Cpu },
    { id: "A4",  name: "Critic",        status: "warn", cpu: 84, mem: 63, kind: Cpu },
    { id: "A5",  name: "GNN",           status: "ok",   cpu: 52, mem: 71, kind: Server },
    { id: "A6",  name: "Reasoner-LLM",  status: "ok",   cpu: 41, mem: 44, kind: Cpu },
    { id: "A7",  name: "SOAR",          status: "ok",   cpu: 18, mem: 26, kind: Server },
    { id: "A8",  name: "Hash-Chain",    status: "ok",   cpu: 6,  mem: 12, kind: Database },
    { id: "A12", name: "Audit",         status: "ok",   cpu: 7,  mem: 15, kind: Database },
    { id: "A13", name: "Federation",    status: "warn", cpu: 22, mem: 33, kind: Server },
  ];

  // Merge live watchdog data over the static defaults
  const liveAgents = data?.watchdog?.agents ?? {};
  const agents = staticAgents.map((a) => {
    const live = liveAgents[a.id] ?? liveAgents[a.name] ?? {};
    return {
      ...a,
      status: live.healthy === false ? "warn" : live.healthy === true ? "ok" : a.status,
    };
  });

  const frozenBanner = data?.autonomy_frozen;

  return (
    <div className="space-y-4">
      <div className="panel px-4 py-3 flex items-center gap-3 flex-wrap">
        <div>
          <div className="font-head font-bold text-[15px]">Agent Health · SysAdmin</div>
          <div className="text-[12.5px] text-[var(--hci-text-2)]">Live status of all HCI-OS microservice agents.</div>
        </div>
        {isLoading && <Loader size={14} className="animate-spin text-[var(--hci-text-3)] ml-auto" />}
        {frozenBanner && <span className="ml-auto chip chip-critical">KILL SWITCH ACTIVE — agents frozen</span>}
        {!frozenBanner && !isLoading && <span className="ml-auto chip chip-clean"><ShieldCheck size={12}/> autonomy nominal</span>}
      </div>
      <div className="grid grid-cols-4 gap-3">
        {agents.map((a) => {
          const Icon = a.kind;
          return (
            <div key={a.id} className="panel card-hover px-4 py-3">
              <div className="flex items-center gap-2">
                <Icon size={14} className="text-[var(--hci-brand)] shrink-0" />
                <div className="font-mono text-[10.5px] text-[var(--hci-text-3)]">{a.id}</div>
                <span className={`ml-auto chip ${a.status === "ok" ? "chip-clean" : "chip-warning"}`}>{a.status.toUpperCase()}</span>
              </div>
              <div className="font-head font-bold text-[14px] mt-1.5 truncate">{a.name}</div>
              <div className="mt-2 space-y-1.5">
                <Bar label="CPU" value={a.cpu} />
                <Bar label="MEM" value={a.mem} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const Bar = ({ label, value }) => (
  <div>
    <div className="flex justify-between text-[10.5px] font-mono text-[var(--hci-text-3)] mb-0.5">
      <span>{label}</span><span>{value}%</span>
    </div>
    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
      <div className="h-full rounded-full" style={{
        width: `${value}%`,
        background: value > 80 ? "#dc2626" : value > 60 ? "#ea580c" : "#0a58ca"
      }} />
    </div>
  </div>
);
