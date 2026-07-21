import React, { useState } from "react";
import { usePipelineHistory } from "@/api/usePipelineHistory";
import { useDecisions } from "@/api/useDecisions";
import { useApp } from "@/context/AppContext";
import {
  X, Activity, CheckCircle2, XCircle, AlertTriangle, SkipForward,
  Zap, ShieldAlert, Brain, ChevronDown, ChevronUp, Clock, Edit3,
  Database, Hash, Cpu, Search, Loader, RefreshCw, ArrowRight,
  Terminal, Info, Lock, User,
} from "lucide-react";

import { ProductionCodeView } from "../gate/HumanGatePanel";

// ── Timezone utility for IST (Asia/Kolkata) ───────────────────────────────────
const formatTimeIST = (isoString) => {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    }) + " IST";
  } catch (e) {
    return isoString;
  }
};

const formatDateTimeIST = (isoString) => {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    }) + " IST";
  } catch (e) {
    return isoString;
  }
};

// ── Agent Logic & Operational Rules View (Explainability) ─────────────────────
const AGENT_RULES = {
  A1:  "Validates ingress log formats, filters out corrupted packets, and computes the source integrity trust score.",
  A2:  "Normalizes incoming raw payloads into structured standardized Evidence schemas.",
  A3:  "Routes fingerprinted matches based on cached patterns to optimize analysis pathing.",
  A4:  "Executes unsupervised machine learning ensembles (One-Class SVM, VAE, Z-score) to detect anomalous telemetry.",
  A5:  "Analyzes Graph Neural Networks (GNN) to discover lateral movement and topological correlations.",
  A6:  "Retrieves threat-intelligence details via RAG and maps anomalies to active MITRE ATT&CK techniques.",
  A7:  "Formulates optimal automated playbooks and mitigation strategies under defined safety thresholds.",
  A8:  "Runs a consensus checking critic to cross-validate hypothesis confidence and prevent false-positives.",
  A10: "Dispatches proactive hunting queries across distributed endpoints to fetch supplementary evidence.",
  A12: "Audits each decision on a block-chained hash trail, assuring transparency and immutable telemetry.",
  A13: "Federates incident hashes and threat intelligence across external collaborative organizational nodes."
};

const AgentLogicView = ({ agentId, detail }) => {
  const [open, setOpen] = useState(false);
  const rule = AGENT_RULES[agentId] || "Executes autonomous operations on behalf of the HCI-OS core controller.";

  return (
    <div className="mt-2 border-t border-[var(--hci-border)]/40 pt-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-[10px] text-emerald-400 hover:text-emerald-300 transition-colors"
      >
        <Terminal size={11} />
        {open ? "Hide Agent Parameters & Rules" : "View Agent Parameters & Rules"}
      </button>
      {open && (
        <div className="mt-2 rounded bg-[#0d1117] p-2.5 border border-[var(--hci-border)]/60 select-text text-[11px] leading-relaxed">
          <div className="text-slate-400 font-semibold mb-1">Operational Policy / Purpose:</div>
          <div className="text-slate-300 mb-2 font-sans">{rule}</div>
          
          {detail && Object.keys(detail).length > 0 && (
            <>
              <div className="text-slate-400 font-semibold mb-1">Execution Parameters:</div>
              <pre className="font-mono text-[10px] text-emerald-300 whitespace-pre leading-relaxed select-text overflow-x-auto max-h-40">
                {JSON.stringify(detail, null, 2)}
              </pre>
            </>
          )}
        </div>
      )}
    </div>
  );
};


// ── Agent display config ──────────────────────────────────────────────────────
const AGENT_META = {
  A1:  { label: "A1 · Ingest & Trust",        color: "text-blue-400",    bg: "bg-blue-500/10" },
  A2:  { label: "A2 · Normalize",             color: "text-cyan-400",    bg: "bg-cyan-500/10" },
  A3:  { label: "A3 · Fingerprint Router",    color: "text-teal-400",    bg: "bg-teal-500/10" },
  A4:  { label: "A4 · Anomaly Detection",     color: "text-amber-400",   bg: "bg-amber-500/10" },
  A5:  { label: "A5 · GNN Correlator",        color: "text-violet-400",  bg: "bg-violet-500/10" },
  A6:  { label: "A6 · Attribution & RAG",     color: "text-pink-400",    bg: "bg-pink-500/10" },
  A7:  { label: "A7 · SOAR Planner",          color: "text-orange-400",  bg: "bg-orange-500/10" },
  A8:  { label: "A8 · Critic (Skeptic)",      color: "text-rose-400",    bg: "bg-rose-500/10" },
  A10: { label: "A10 · Active Hunt",          color: "text-indigo-400",  bg: "bg-indigo-500/10" },
  A12: { label: "A12 · Audit & Memory",       color: "text-emerald-400", bg: "bg-emerald-500/10" },
  A13: { label: "A13 · Federation",           color: "text-sky-400",     bg: "bg-sky-500/10" },
};

const STATUS_ICON = {
  pass:  <CheckCircle2 size={13} className="text-emerald-500 shrink-0" />,
  flag:  <AlertTriangle size={13} className="text-amber-500 shrink-0" />,
  block: <ShieldAlert size={13} className="text-red-500 shrink-0" />,
  skip:  <SkipForward size={13} className="text-slate-500 shrink-0" />,
  error: <XCircle size={13} className="text-red-600 shrink-0" />,
};

const STATUS_COLOR = {
  pass:  "text-emerald-400",
  flag:  "text-amber-400",
  block: "text-red-500",
  skip:  "text-slate-500",
  error: "text-red-600",
};

// ── Override modal ────────────────────────────────────────────────────────────
const OverrideModal = ({ run, onClose, onSubmit }) => {
  const [newAction, setNewAction] = useState(
    run.decision?.action_taken || "MONITOR"
  );
  const [reason, setReason] = useState("");
  const reasonRequired = reason.trim().length < 10;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-[var(--hci-surface)] border border-[var(--hci-border)] rounded-2xl shadow-2xl w-full max-w-lg mx-4 p-6">
        <div className="flex items-center gap-2 mb-5">
          <Edit3 size={16} className="text-amber-400" />
          <h2 className="font-bold text-[14px]">Override Pipeline Decision</h2>
          <span className="ml-auto font-mono text-[11px] text-[var(--hci-text-3)]">{run.run_id}</span>
        </div>

        {/* Current decision */}
        <div className="mb-3">
          <div className="label-caps mb-1">AI-Proposed Action</div>
          <div className="px-3 py-2 rounded-lg bg-[var(--hci-surface-2)] font-mono text-[12px] text-[var(--hci-text-3)]">
            {run.decision?.action_taken || "No decision issued (human gate pending)"}
          </div>
        </div>

        {/* New action */}
        <div className="mb-3">
          <div className="label-caps mb-1">Your Override Action *</div>
          <input
            value={newAction}
            onChange={(e) => setNewAction(e.target.value)}
            placeholder="e.g. MONITOR, BLOCK_IP, ESCALATE_TO_SOC"
            className="w-full px-3 py-2 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] text-[12.5px] text-[var(--hci-text)] outline-none focus:border-[var(--hci-brand)] transition-colors font-mono"
          />
        </div>

        {/* Mandatory reason */}
        <div className="mb-5">
          <div className="label-caps mb-1 flex items-center gap-1">
            <Lock size={10} className="text-amber-400" />
            Reason for Override * <span className="text-[var(--hci-text-3)] font-normal">(required · min 10 chars)</span>
          </div>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Explain why you are overriding the AI decision — this will be stored immutably in the audit chain…"
            rows={3}
            className={`w-full px-3 py-2 rounded-lg border ${reasonRequired && reason.length > 0 ? "border-red-500/60" : "border-[var(--hci-border)]"} bg-[var(--hci-surface-2)] text-[12px] text-[var(--hci-text)] outline-none focus:border-[var(--hci-brand)] transition-colors resize-none`}
          />
          {reasonRequired && reason.length > 0 && (
            <div className="text-[10.5px] text-red-400 mt-1">Reason must be at least 10 characters.</div>
          )}
        </div>

        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="btn btn-ghost btn-sm">Cancel</button>
          <button
            disabled={!newAction.trim() || reasonRequired}
            onClick={() => onSubmit(newAction.trim(), reason)}
            className="btn btn-amber-outline btn-sm disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Edit3 size={12} /> Apply Override
          </button>
        </div>
      </div>
    </div>
  );
};

// ── Single run row (expandable) ───────────────────────────────────────────────
const RunRow = ({ run, onOverride }) => {
  const [open, setOpen] = useState(false);
  const hasDecision = !!run.decision_id;

  const isPendingGate = !!run.decision && run.decision.action_taken?.toUpperCase().includes("PENDING");

  const isQuarantined = (run.quarantined || (run.decision && (
    run.decision.action_taken?.toUpperCase().includes("ISOLATE") ||
    run.decision.action_taken?.toUpperCase().includes("QUARANTINE")
  ))) && !isPendingGate;

  const isFlagged = run.flagged || !!run.decision_id || (run.decision && (
    run.decision.action_taken?.toUpperCase() !== "MONITOR" &&
    run.decision.action_taken?.toUpperCase() !== "NONE"
  ));

  const passed = !isQuarantined && !isFlagged && !isPendingGate;
  const agentCount = run.pipeline_trace?.length || 0;

  const statusLabel = isQuarantined
    ? "QUARANTINED"
    : isPendingGate
    ? "PENDING GATE"
    : isFlagged
    ? "FLAGGED"
    : "CLEAN";

  const statusClass = isQuarantined
    ? "chip chip-danger"
    : isPendingGate
    ? "chip chip-warning"
    : isFlagged
    ? "chip chip-warning"
    : "chip chip-clean";

  return (
    <div className={`border-b border-[var(--hci-border)] transition-colors ${open ? "bg-[var(--hci-surface-2)]" : "hover:bg-[var(--hci-surface-hover)]"}`}>
      {/* Header row */}
      <button
        className="w-full text-left px-5 py-3 flex items-center gap-3"
        onClick={() => setOpen(!open)}
      >
        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${isQuarantined ? "bg-red-500" : isFlagged ? "bg-amber-500" : "bg-emerald-500"}`} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[11px] text-[var(--hci-text-3)]">{run.run_id?.slice(0, 20) || "—"}</span>
            <span className={statusClass}>{statusLabel}</span>
            {run.mitre_tags?.slice(0, 2).map((t) => (
              <span key={t} className="chip chip-neutral font-mono text-[10px]">{t}</span>
            ))}
            {run.mitre_tags?.length > 2 && (
              <span className="chip chip-neutral text-[10px]">+{run.mitre_tags.length - 2}</span>
            )}
          </div>
          <div className="mt-0.5 flex items-center gap-3 text-[11px] text-[var(--hci-text-3)]">
            <span>trust <b className="text-[var(--hci-text)]">{run.trust_score?.toFixed(2) ?? "—"}</b></span>
            <span>anomaly <b className="text-[var(--hci-text)]">{run.anomaly_score?.toFixed(3) ?? "—"}</b></span>
            <span>agents <b className="text-[var(--hci-text)]">{agentCount}</b></span>
            {run.source && <span>src <b className="text-[var(--hci-text)]">{run.source}</b></span>}
            <span className="ml-auto flex items-center gap-1">
              <Clock size={10} />
              {formatTimeIST(run.created_at)}
            </span>
          </div>
        </div>

        {open ? <ChevronUp size={14} className="text-[var(--hci-text-3)] shrink-0" /> : <ChevronDown size={14} className="text-[var(--hci-text-3)] shrink-0" />}
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="px-5 pb-4 space-y-4">
          {/* Agent-by-agent trace */}
          {run.pipeline_trace?.length > 0 && (
            <div>
              <div className="label-caps mb-2 flex items-center gap-1.5">
                <Activity size={11} className="text-[var(--hci-brand)]" />
                Agent-by-Agent Pipeline Trace
              </div>
              <div className="relative pl-6 space-y-4">
                {/* Timeline line */}
                <div className="absolute left-[11px] top-2 bottom-2 w-px bg-[var(--hci-border)]" />

                {run.pipeline_trace.map((step, idx) => {
                  const meta = AGENT_META[step.agent] || {
                    label: step.agent, color: "text-slate-400", bg: "bg-slate-500/10"
                  };
                  return (
                    <div key={idx} className="flex items-start gap-4 relative">
                      {/* dot */}
                      <div className={`absolute left-[-19px] top-1.5 w-4 h-4 rounded-full border border-[var(--hci-border)] flex items-center justify-center ${meta.bg}`}>
                        <div className={`w-2 h-2 rounded-full ${step.status === "pass" ? "bg-emerald-400" : step.status === "block" ? "bg-red-500" : step.status === "flag" ? "bg-amber-400" : "bg-slate-500"}`} />
                      </div>

                      <div className={`ml-2 rounded-xl border border-[var(--hci-border)] p-3.5 flex-1 ${meta.bg} shadow-sm`}>
                        <div className="flex items-center gap-2 mb-1">
                          {STATUS_ICON[step.status] || STATUS_ICON.skip}
                          <span className={`font-bold text-[12.5px] ${meta.color}`}>{meta.label}</span>
                          <span className={`text-[10.5px] font-bold ml-auto ${STATUS_COLOR[step.status]} chip ${step.status === "pass" ? "chip-clean" : step.status === "block" ? "chip-critical" : "chip-warning"}`}>
                            {step.status.toUpperCase()}
                          </span>
                        </div>
                        <div className="text-[12px] text-[var(--hci-text-2)] leading-relaxed mt-1">
                          {step.summary}
                        </div>
                        {/* Detail fields */}
                        {step.detail && Object.keys(step.detail).length > 0 && (
                          <div className="mt-2.5 flex flex-wrap gap-2 border-t border-[var(--hci-border)]/50 pt-2">
                            {Object.entries(step.detail)
                              .filter(([, v]) => v !== null && v !== undefined)
                              .map(([k, v]) => (
                                <span key={k} className="font-mono text-[11px] text-[var(--hci-text-3)] bg-[var(--hci-surface-2)] px-2 py-0.5 rounded border border-[var(--hci-border)]">
                                  {k}=<span className="text-[var(--hci-text)] font-semibold">
                                    {typeof v === "number" ? v.toFixed(3) : String(v)}
                                  </span>
                                </span>
                              ))}
                          </div>
                        )}
                        {/* Agent operational rules & parameters visualization */}
                        <AgentLogicView agentId={step.agent} detail={step.detail} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* SD Events */}
          {run.sd_events?.length > 0 && (
            <div>
              <div className="label-caps mb-2 flex items-center gap-1.5">
                <ShieldAlert size={11} className="text-red-400" />
                Self-Defense Events ({run.sd_events.length})
              </div>
              <div className="space-y-1">
                {run.sd_events.map((ev, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px]">
                    <span className="font-mono text-red-400 shrink-0">{ev.layer}</span>
                    <span className="text-[var(--hci-text-3)]">{ev.description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Explainability metrics */}
          <div>
            <div className="label-caps mb-2 flex items-center gap-1.5">
              <Brain size={11} className="text-violet-400" />
              Explainability Metrics
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11.5px]">
              {[
                ["Trust Score",   run.trust_score?.toFixed(3) ?? "—",    "text-blue-400"],
                ["Anomaly Score", run.anomaly_score?.toFixed(4) ?? "—",  "text-amber-400"],
                ["Evidence ID",  run.evidence_id?.slice(0,16) + "…" ?? "—", "text-[var(--hci-text)]"],
                ["Hypothesis",   run.hypothesis_id?.slice(0,12) + "…" ?? "—", "text-[var(--hci-text)]"],
                ["Decision ID",  run.decision_id?.slice(0,12) + "…" ?? "none", run.decision_id ? "text-emerald-400" : "text-slate-500"],
                ["Audit Hash",   run.audit_hash ? "0x" + run.audit_hash.slice(0,10) + "…" : "—", "text-[var(--hci-text-3)] font-mono text-[10px]"],
              ].map(([label, val, cls]) => (
                <div key={label} className="flex items-center justify-between px-2 py-1 rounded bg-[var(--hci-surface-2)]">
                  <span className="text-[var(--hci-text-3)]">{label}</span>
                  <span className={cls}>{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE chain */}
          {run.mitre_tags?.length > 0 && (
            <div>
              <div className="label-caps mb-2">MITRE ATT&CK Chain</div>
              <div className="flex flex-wrap gap-1.5">
                {run.mitre_tags.map((t, i) => (
                  <React.Fragment key={t}>
                    <span className="chip chip-info font-mono text-[10.5px]">{t}</span>
                    {i < run.mitre_tags.length - 1 && (
                      <ArrowRight size={10} className="text-[var(--hci-text-3)] self-center" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Action Execution Code */}
          {run.decision && (
            <div>
              <div className="label-caps mb-1 flex items-center gap-1.5 text-emerald-400">
                <Terminal size={11} />
                Action Execution Code
              </div>
              <ProductionCodeView decision={run.decision} />
            </div>
          )}

          {/* HITL Override */}
          <div className="pt-1 flex items-center gap-2">
            <button
              onClick={() => onOverride(run)}
              className="btn btn-amber-outline btn-sm"
            >
              <Edit3 size={12} /> Override Decision
            </button>
            <span className="text-[10.5px] text-[var(--hci-text-3)]">
              Override will be logged with your mandatory reason to the immutable audit chain.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Main Modal ────────────────────────────────────────────────────────────────
const PipelineTraceModal = ({ onClose }) => {
  const { role } = useApp();
  const { data: runs = [], isLoading, refetch, isFetching } = usePipelineHistory(50);
  const { act: mutate } = useDecisions(role);

  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [overrideTarget, setOverrideTarget] = useState(null);

  const filtered = runs.filter((r) => {
    const _isQ = r.quarantined;
    const _isF = r.flagged || !!r.decision_id;
    if (filterStatus === "quarantined" && !_isQ) return false;
    if (filterStatus === "flagged" && (!_isF || _isQ)) return false;
    if (filterStatus === "clean" && (_isQ || _isF)) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        r.run_id?.toLowerCase().includes(q) ||
        r.source?.toLowerCase().includes(q) ||
        r.asset_id?.toLowerCase().includes(q) ||
        r.evidence_id?.toLowerCase().includes(q) ||
        r.mitre_tags?.some((t) => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleOverrideSubmit = (run, newAction, reason) => {
    setOverrideTarget(null);
    if (run.decision_id) {
      mutate({
        decisionId: run.decision_id,
        action: "modify",
        analystId: role?.email || "analyst",
        newAction,
        notes: reason,
      });
    }
  };

  return (
    <>
      {overrideTarget && (
        <OverrideModal
          run={overrideTarget}
          onClose={() => setOverrideTarget(null)}
          onSubmit={(a, r) => handleOverrideSubmit(overrideTarget, a, r)}
        />
      )}

      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
        <div className="bg-[var(--hci-surface)] border border-[var(--hci-border)] rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col">
          {/* Header */}
          <div className="px-6 py-4 border-b border-[var(--hci-border)] flex items-center gap-3 flex-wrap">
            <Activity size={18} className="text-[var(--hci-brand)] shrink-0" />
            <div>
              <div className="font-head font-bold text-[15px]">Pipeline Explainability Trace</div>
              <div className="text-[11.5px] text-[var(--hci-text-3)]">
                {runs.length} runs · every agent decision, MITRE tag, and SD event recorded
              </div>
            </div>

            {/* Stats pills */}
            <div className="flex items-center gap-2 ml-2">
              <span className="chip chip-danger">{runs.filter(r => r.quarantined).length} quarantined</span>
              <span className="chip chip-warning">{runs.filter(r => r.flagged && !r.quarantined).length} flagged</span>
              <span className="chip chip-clean">{runs.filter(r => !r.quarantined && !r.flagged).length} clean</span>
            </div>

            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => refetch()}
                className="btn btn-ghost btn-sm"
                disabled={isFetching}
              >
                <RefreshCw size={12} className={isFetching ? "animate-spin" : ""} />
              </button>
              <button onClick={onClose} className="btn btn-ghost btn-sm">
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Controls */}
          <div className="px-6 py-3 border-b border-[var(--hci-border)] flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[180px]">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--hci-text-3)]" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search run id, source, MITRE tag…"
                className="w-full pl-7 pr-3 py-1.5 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] text-[12px] text-[var(--hci-text)] outline-none focus:border-[var(--hci-brand)] transition-colors"
              />
            </div>
            {["all", "clean", "flagged", "quarantined"].map((f) => (
              <button
                key={f}
                onClick={() => setFilterStatus(f)}
                className={`btn btn-sm ${filterStatus === f ? "btn-primary" : "btn-ghost"}`}
              >
                {f}
              </button>
            ))}
          </div>

          {/* Run list */}
          <div className="flex-1 overflow-auto">
            {isLoading && (
              <div className="flex items-center justify-center py-20 gap-3 text-[var(--hci-text-3)]">
                <Loader size={18} className="animate-spin" />
                Loading pipeline history…
              </div>
            )}

            {!isLoading && filtered.length === 0 && (
              <div className="flex flex-col items-center justify-center py-20 gap-2 text-[var(--hci-text-3)]">
                <Database size={32} className="opacity-40" />
                <div className="text-[13px] font-semibold">No runs found</div>
                <div className="text-[11.5px]">
                  {runs.length === 0
                    ? "Ingest a telemetry event from the dashboard to see it appear here."
                    : "Try adjusting the search or filter."}
                </div>
              </div>
            )}

            {filtered.map((run) => (
              <RunRow
                key={run.run_id}
                run={run}
                onOverride={(r) => setOverrideTarget(r)}
              />
            ))}
          </div>

          {/* Footer */}
          <div className="px-6 py-3 border-t border-[var(--hci-border)] flex items-center gap-2 text-[11px] text-[var(--hci-text-3)]">
            <Hash size={11} />
            All runs cryptographically hashed and stored in MySQL.
            <span className="ml-2 flex items-center gap-1">
              <User size={10} />
              Role: <b className="text-[var(--hci-text)]">{role?.label}</b>
            </span>
            <span className="ml-auto">Auto-refreshes every 10s</span>
          </div>
        </div>
      </div>
    </>
  );
};

export default PipelineTraceModal;
