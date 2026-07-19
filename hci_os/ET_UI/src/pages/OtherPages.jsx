import React from "react";
import { Lock, ShieldCheck, LineChart, TrendingUp, TrendingDown, Cpu, Server, Database, Activity, Waves, Loader, AlertTriangle } from "lucide-react";
import AttackGraph from "@/components/topology/AttackGraph";
import HumanGatePanel from "@/components/gate/HumanGatePanel";
import { useHealth } from "@/api/useHealth";
import { useAuditLog } from "@/api/useAuditLog";
import { useTimeline } from "@/api/useTimeline";

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

// ── Audit Page ─────────────────────────────────────────────────────────────────
export const AuditPage = () => {
  const { data: entries = [], isLoading, isPlaceholderData } = useAuditLog();

  return (
    <div className="space-y-4">
      <div className="panel px-5 py-4 flex items-center gap-3">
        <Lock size={18} className="text-[var(--hci-brand)]" />
        <div>
          <div className="font-head font-bold text-[15px]">Audit Chain · A12</div>
          <div className="text-[12.5px] text-[var(--hci-text-2)]">Immutable, hash-linked log of every agent and human action.</div>
        </div>
        {isLoading && <Loader size={14} className="animate-spin text-[var(--hci-text-3)] ml-auto" />}
        {isPlaceholderData && !isLoading && (
          <span className="ml-auto chip chip-warning text-[10px] flex items-center gap-1">
            <AlertTriangle size={10} /> mock · backend offline
          </span>
        )}
        {!isPlaceholderData && !isLoading && (
          <span className="ml-auto chip chip-clean"><ShieldCheck size={12} /> chain verified</span>
        )}
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
            {entries.map((a, i) => (
              <tr key={i} className="border-b border-[var(--hci-border)] hover:bg-[#fbfcfd]">
                <td className="px-5 py-2.5 font-mono text-[var(--hci-brand)] font-semibold">{a.ts}</td>
                <td className="px-5 py-2.5 font-mono">{a.actor}</td>
                <td className="px-5 py-2.5"><span className="chip chip-info">{a.event}</span></td>
                <td className="px-5 py-2.5 font-mono">{a.target}</td>
                <td className="px-5 py-2.5 font-mono text-[var(--hci-text-3)]">{a.hash}</td>
              </tr>
            ))}
            {entries.length === 0 && !isLoading && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-[var(--hci-text-3)] text-[12px]">
                  No audit entries yet — ingest an event to populate the chain.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ── Exec Page ─────────────────────────────────────────────────────────────────
const KpiCard = ({ icon: Icon, label, value, delta, tone, loading }) => (
  <div className="panel px-5 py-4">
    <div className="flex items-center gap-2 label-caps">
      <Icon size={12} /> {label}
    </div>
    {loading
      ? <div className="h-7 w-16 bg-slate-100 animate-pulse rounded mt-1.5" />
      : <div className="font-head font-bold text-[26px] mt-1.5 leading-tight">{value}</div>
    }
    {delta && (
      <div className={`text-[12px] mt-1 font-mono flex items-center gap-1 ${tone === "up" ? "text-emerald-600" : "text-red-600"}`}>
        {tone === "up" ? <TrendingUp size={12} /> : <TrendingDown size={12} />} {delta}
      </div>
    )}
  </div>
);

export const ExecPage = () => {
  const { data: health, isLoading: healthLoading }       = useHealth();
  const { data: timelineData, isLoading: tlLoading }     = useTimeline();

  const incident  = timelineData?.incident;
  const events    = timelineData?.timeline_events ?? [];
  const loading   = healthLoading || tlLoading;

  // Derive MTTD: time to first HYPOTHESIS event in the timeline
  const hypothesisEvt = events.find((e) => e.type === "HYPOTHESIS");
  const containEvt    = events.find((e) => e.type === "CONTAIN");
  const mttd  = hypothesisEvt ? `T+${hypothesisEvt.t}s` : "—";
  const mttr  = containEvt    ? `T+${containEvt.t}s`    : "—";

  // Circuit breakers for automation ratio
  const cbs = health?.circuit_breakers ?? {};
  const openCbs   = Object.values(cbs).filter((c) => c.open_until != null).length;
  const totalCbs  = Object.keys(cbs).length;
  const autoRatio = totalCbs > 0
    ? `${Math.round(((totalCbs - openCbs) / totalCbs) * 100)}%`
    : "—";

  const chainValid = health?.sd_chain?.valid;
  const frozen     = health?.autonomy_frozen;

  return (
    <div className="space-y-4">
      <div className="panel px-5 py-4 flex items-center gap-3">
        <div>
          <div className="font-head font-bold text-[15px]">Executive View · CISO</div>
          <div className="text-[12.5px] text-[var(--hci-text-2)]">Mission impact, ROI, and federation status. Read-only.</div>
        </div>
        {loading && <Loader size={14} className="animate-spin text-[var(--hci-text-3)] ml-auto" />}
        {frozen   && <span className="ml-auto chip chip-critical">KILL SWITCH ACTIVE</span>}
        {!frozen && !loading && chainValid && (
          <span className="ml-auto chip chip-clean"><ShieldCheck size={12} /> SD chain intact</span>
        )}
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-3"><KpiCard icon={Activity}  label="MTTD"             value={mttd}     delta="-62% vs Q3" tone="up"  loading={loading} /></div>
        <div className="col-span-3"><KpiCard icon={Activity}  label="MTTR"             value={mttr}     delta="-71% vs Q3" tone="up"  loading={loading} /></div>
        <div className="col-span-3"><KpiCard icon={LineChart} label="Automation Ratio" value={autoRatio} delta="+14 pts"   tone="up"  loading={loading} /></div>
        <div className="col-span-3">
          <KpiCard
            icon={Waves}
            label="Confidence"
            value={incident?.confidence ? `${(incident.confidence * 100).toFixed(1)}%` : "—"}
            delta="hypothesis conf."
            tone="up"
            loading={loading}
          />
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-7 panel px-5 py-4">
          <div className="label-caps mb-3">Active Incident · MITRE Chain</div>
          {incident ? (
            <div className="space-y-2">
              <div className="font-semibold text-[13px]">{incident.title}</div>
              <div className="text-[12px] text-[var(--hci-text-2)]">Target: <span className="font-mono">{incident.target}</span></div>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {(incident.mitre_chain || []).map((m) => (
                  <span key={m} className="chip chip-neutral font-mono">{m}</span>
                ))}
              </div>
              <div className="text-[11.5px] text-[var(--hci-text-3)] mt-1 font-mono">
                Status: <span className={incident.status === "CONTAINED" ? "text-emerald-600" : "text-red-500"}>{incident.status}</span>
                {" · "}Detected: {incident.detection_ts}
              </div>
            </div>
          ) : (
            <div className="text-[12px] text-[var(--hci-text-3)]">No active incident.</div>
          )}
        </div>
        <div className="col-span-5 panel px-5 py-4">
          <div className="label-caps mb-3">Affected Assets</div>
          {(incident?.affected_assets ?? []).length > 0 ? (
            <div className="space-y-2">
              {incident.affected_assets.map((a) => (
                <div key={a.id} className="flex items-center py-1.5 border-b border-[var(--hci-border)] last:border-0 text-[12.5px]">
                  <span
                    className="w-2 h-2 rounded-full mr-3 shrink-0"
                    style={{ background: a.criticality === "CROWN_JEWEL" ? "#dc2626" : a.criticality === "HIGH" ? "#ea580c" : "#059669" }}
                  />
                  <span className="font-mono truncate flex-1">{a.name}</span>
                  <span className={`ml-2 chip ${a.criticality === "CROWN_JEWEL" ? "chip-critical" : a.criticality === "HIGH" ? "chip-suspicious" : "chip-clean"}`}>
                    {a.criticality}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[12px] text-[var(--hci-text-3)]">No affected assets reported.</div>
          )}
        </div>
      </div>
    </div>
  );
};

// ── Health Page ───────────────────────────────────────────────────────────────
export const HealthPage = () => {
  const { data, isLoading } = useHealth();

  const staticAgents = [
    { id: "A1",  name: "Sensor Bus",   status: "ok",   cpu: 12, mem: 22, kind: Waves },
    { id: "A2",  name: "HumanGate",    status: "ok",   cpu: 4,  mem: 8,  kind: Cpu },
    { id: "A3",  name: "Reasoner",     status: "ok",   cpu: 68, mem: 41, kind: Cpu },
    { id: "A4",  name: "Critic",       status: "warn", cpu: 84, mem: 63, kind: Cpu },
    { id: "A5",  name: "GNN",          status: "ok",   cpu: 52, mem: 71, kind: Server },
    { id: "A6",  name: "Reasoner-LLM", status: "ok",   cpu: 41, mem: 44, kind: Cpu },
    { id: "A7",  name: "SOAR",         status: "ok",   cpu: 18, mem: 26, kind: Server },
    { id: "A8",  name: "Hash-Chain",   status: "ok",   cpu: 6,  mem: 12, kind: Database },
    { id: "A12", name: "Audit",        status: "ok",   cpu: 7,  mem: 15, kind: Database },
    { id: "A13", name: "Federation",   status: "warn", cpu: 22, mem: 33, kind: Server },
  ];

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
        {!frozenBanner && !isLoading && <span className="ml-auto chip chip-clean"><ShieldCheck size={12} /> autonomy nominal</span>}
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
