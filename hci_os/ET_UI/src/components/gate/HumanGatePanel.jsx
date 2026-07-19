import React, { useState, useEffect } from "react";
import { TID } from "@/constants/testIds";
import { useApp } from "@/context/AppContext";
import { useDecisions } from "@/api/useDecisions";
import { CheckCircle2, XCircle, Edit3, ArrowUpRight, Users, Clock, Loader } from "lucide-react";

const fmt = (s) => {
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return `${m}m ${sec}s`;
};

const HumanGatePanel = ({ compact = false }) => {
  const { role } = useApp();
  const readOnly = role.id === "ciso";
  const { data: apiDecisions, isLoading, act: mutate, isMutating } = useDecisions(role);

  // Local UI state: map each decision_id → "pending" | "confirmed" | "revoked" | ...
  const [localStatus, setLocalStatus] = useState({});
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const iv = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(iv);
  }, []);

  const rows = (apiDecisions ?? []).map((r) => ({
    ...r,
    status: localStatus[r.decision_id] ?? "pending",
  }));

  const timeLeft = (r) => Math.max(0, (r.sla_seconds_left ?? 900) - tick);

  const act = (id, status, action) => {
    setLocalStatus((s) => ({ ...s, [id]: status }));
    mutate({ decisionId: id, action, analystId: role.email });
  };

  return (
    <div className="panel h-full flex flex-col">
      <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2 flex-wrap">
        <Users size={15} className="text-[var(--hci-brand)] shrink-0" />
        <div className="font-head font-bold text-[13.5px]">Human Gate</div>
        <span className="chip chip-warning">{rows.filter(r => r.status === "pending").length} pending</span>
        {isLoading && <Loader size={12} className="animate-spin text-[var(--hci-text-3)]" />}
        <span className="ml-auto label-caps whitespace-nowrap">SLA · 15 min</span>
      </div>
      <div className="flex-1 overflow-auto">
        {rows.length === 0 && !isLoading && (
          <div className="p-8 text-center text-[var(--hci-text-3)] flex flex-col items-center justify-center h-full">
            <CheckCircle2 size={32} className="mb-2 text-emerald-500 opacity-60" />
            <div className="font-semibold text-[12.5px]">All Gates Cleared</div>
            <div className="text-[11.5px] mt-0.5 max-w-[200px] mx-auto">
              No decisions pending human authorization at this time.
            </div>
          </div>
        )}
        {rows.map((r) => {
          const left = timeLeft(r);
          const slaCritical = left < 300;
          const acted = r.status !== "pending";
          return (
            <div
              key={r.decision_id}
              data-testid={TID.gateRow(r.decision_id)}
              className="px-5 py-4 border-b border-[var(--hci-border)] card-hover"
            >
              <div className="flex items-start gap-3">
                <div className={`w-1 rounded-full self-stretch ${acted ? "bg-emerald-500" : slaCritical ? "bg-red-500" : "bg-amber-500"}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-[11.5px] text-[var(--hci-text-3)]">{r.decision_id}</span>
                    <span className="chip chip-neutral font-mono">{r.hypothesis_id}</span>
                    <span className={`chip ${r.blast_radius_label === "LOW" ? "chip-clean" : "chip-warning"}`}>blast {r.blast_radius_label}</span>
                    <span className="chip chip-info">by {r.proposed_by}</span>
                    <span className="ml-auto flex items-center gap-1.5 font-mono text-[11.5px]">
                      <Clock size={11} className={slaCritical ? "text-red-500" : "text-slate-500"} />
                      <span className={slaCritical ? "text-red-600 font-semibold" : "text-[var(--hci-text-3)]"}>{fmt(left)} left</span>
                    </span>
                  </div>
                  <div className="mt-1.5 font-semibold text-[13.5px] text-[var(--hci-text)]">
                    {r.action_taken}
                  </div>
                  <div className="mt-1 flex items-center gap-4 text-[11.5px] text-[var(--hci-text-3)] font-mono">
                    <span>risk <span className="text-[var(--hci-text)] font-semibold">{r.risk_score.toFixed(2)}</span></span>
                    <span>blast_radius <span className="text-[var(--hci-text)] font-semibold">{r.blast_radius_score.toFixed(2)}</span></span>
                    <span>ts {new Date(r.ts_iso).toLocaleTimeString()}</span>
                  </div>

                  {acted ? (
                    <div className="mt-2 chip chip-clean">
                      <CheckCircle2 size={12} /> {r.status.toUpperCase()}
                    </div>
                  ) : (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      <button
                        data-testid={TID.gateConfirm(r.decision_id)}
                        disabled={readOnly || isMutating}
                        onClick={() => act(r.decision_id, "confirmed", "confirm")}
                        className="btn btn-success-outline btn-sm"
                      >
                        <CheckCircle2 size={12} /> CONFIRM
                      </button>
                      <button
                        data-testid={TID.gateRevoke(r.decision_id)}
                        disabled={readOnly || isMutating}
                        onClick={() => act(r.decision_id, "revoked", "revoke")}
                        className="btn btn-danger btn-sm"
                      >
                        <XCircle size={12} /> REVOKE
                      </button>
                      <button
                        data-testid={TID.gateModify(r.decision_id)}
                        disabled={readOnly || isMutating}
                        onClick={() => act(r.decision_id, "modified", "modify")}
                        className="btn btn-amber-outline btn-sm"
                      >
                        <Edit3 size={12} /> MODIFY
                      </button>
                      <button
                        data-testid={TID.gateEscalate(r.decision_id)}
                        disabled={readOnly || isMutating}
                        onClick={() => act(r.decision_id, "escalated", "escalate")}
                        className="btn btn-primary btn-sm"
                      >
                        <ArrowUpRight size={12} /> ESCALATE
                      </button>
                      {readOnly && (
                        <span className="text-[10.5px] text-[var(--hci-text-3)] self-center">
                          {role.label}: read-only
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
        {compact && <div className="p-4 text-center text-[12px] text-[var(--hci-text-3)]">Open Human Gate tab for full view →</div>}
      </div>
    </div>
  );
};

export default HumanGatePanel;
