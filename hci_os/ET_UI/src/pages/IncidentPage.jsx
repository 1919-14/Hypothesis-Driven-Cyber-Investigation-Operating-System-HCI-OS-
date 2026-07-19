import React from "react";
import { useApp } from "@/context/AppContext";
import Timeline from "@/components/timeline/Timeline";
import AttackGraph from "@/components/topology/AttackGraph";
import HumanGatePanel from "@/components/gate/HumanGatePanel";
import { useTimeline } from "@/api/useTimeline";
import { INCIDENT } from "@/mock/data";
import { ShieldAlert, Activity, Target, GitBranch, Clock } from "lucide-react";

/**
 * Stat card — used in the 4-up metrics row.
 * Labels are kept SHORT (≤ 3 words, no whitespace-nowrap) so they wrap
 * gracefully at any column width instead of overflowing.
 */
const Stat = ({ icon: Icon, label, value, sub, tone = "info" }) => (
  <div className="panel card-hover px-3 py-3 flex items-center gap-2.5 min-w-0">
    <div className={`w-9 h-9 rounded-md flex items-center justify-center shrink-0 ${
      tone === "critical" ? "bg-red-50 text-red-600" :
      tone === "warn"     ? "bg-amber-50 text-amber-600" :
      tone === "clean"    ? "bg-emerald-50 text-emerald-600" :
      "bg-blue-50 text-[var(--hci-brand)]"
    }`}>
      <Icon size={16} />
    </div>
    <div className="min-w-0 flex-1">
      {/* label-caps WITHOUT whitespace-nowrap — let it wrap */}
      <div className="label-caps leading-tight">{label}</div>
      <div className="font-head font-bold text-[17px] leading-snug mt-0.5 truncate">{value}</div>
      {sub && <div className="text-[10.5px] text-[var(--hci-text-3)] mt-0.5 font-mono truncate">{sub}</div>}
    </div>
  </div>
);

const IncidentBanner = ({ incident }) => {
  const data = incident || INCIDENT;
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-stretch">
        <div className="w-1.5 shrink-0 bg-[var(--hci-critical)]" />
        <div className="flex-1 min-w-0 px-4 py-3.5 flex flex-col gap-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="chip chip-critical shrink-0">
              <span className="live-dot" style={{ width: 6, height: 6 }} />
              ACTIVE
            </span>
            <ShieldAlert size={16} className="text-[var(--hci-critical)] shrink-0" />
            <span className="font-head font-bold text-[14.5px] leading-snug">{data.title}</span>
            <span className="chip chip-neutral font-mono shrink-0">{data.hypothesis_id}</span>
          </div>
          <div className="text-[12px] text-[var(--hci-text-2)]">
            Target: <span className="font-mono text-[var(--hci-text)]">{data.target}</span>
            {" · "}Detected {data.detection_ts}
            {" · "}confidence <span className="font-mono">{((data.confidence || 0.94) * 100).toFixed(1)}%</span>
          </div>
        </div>
        {/* MITRE chain — wraps on small screens */}
        <div className="hidden lg:flex items-center gap-1.5 flex-wrap px-4 py-3.5 shrink-0 max-w-[260px]">
          {(data.mitre_chain || []).map((m) => (
            <span key={m} className="chip chip-neutral font-mono">{m}</span>
          ))}
        </div>
      </div>
    </div>
  );
};

const IncidentPage = () => {
  const { selectedEventIdx, setSelectedEventIdx } = useApp();
  const { data } = useTimeline();
  const incident = data?.incident || INCIDENT;
  const events   = data?.timeline_events ?? [];

  // Derive stats from live timeline events
  const containEvt   = events.find((e) => e.type === "CONTAIN");
  const containTime  = containEvt ? `T+${containEvt.t}s` : "—";

  const assetsHit    = (incident?.affected_assets ?? []).length || 3;
  const crownJewels  = (incident?.affected_assets ?? []).filter((a) => a.criticality === "CROWN_JEWEL").length;
  const assetSub     = crownJewels > 0 ? `${crownJewels} crown jewel` : `${assetsHit} total`;

  const predictEdges = events.filter((e) => e.type === "HYPOTHESIS").length;
  const deadlineHrs  = incident?.cert_in_deadline_hours ?? 6;
  const certWindow   = `${String(deadlineHrs - 1).padStart(2,"0")}:59:17`;

  return (
    <div className="space-y-4">
      <IncidentBanner incident={incident} />

      {/* 4-column stats — computed from live data */}
      <div className="grid grid-cols-4 gap-3">
        <Stat icon={Activity}  label="Contain Time"   value={containTime}                   sub="from T-0"                    tone="clean"    />
        <Stat icon={Target}    label="Assets Hit"     value={String(assetsHit)}             sub={assetSub}                    tone="critical" />
        <Stat icon={GitBranch} label="Hypotheses"     value={String(predictEdges || 1)}     sub="reasoning chains"            tone="warn"     />
        <Stat icon={Clock}     label="CERT-In Window" value={certWindow}                    sub={`${deadlineHrs}h deadline`}  tone="warn"     />
      </div>

      <Timeline selectedIdx={selectedEventIdx} onSelect={setSelectedEventIdx} />

      {/* Bottom row — graph takes 2/3, gate takes 1/3 */}
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2"><AttackGraph /></div>
        <div className="col-span-1"><HumanGatePanel compact /></div>
      </div>
    </div>
  );
};

export default IncidentPage;
