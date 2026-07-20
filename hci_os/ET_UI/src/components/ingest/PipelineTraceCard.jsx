import React, { useState } from "react";
import {
  CheckCircle2, XCircle, AlertTriangle, MinusCircle, ChevronDown,
  ChevronRight, Shield, Zap, Brain, Eye, GitBranch, Lock, Radio,
  Network, Search, Cpu, SkipForward,
} from "lucide-react";

const AGENT_META = {
  A1:  { label: "Ingest · Trust Score",     icon: Shield,    color: "#0a58ca" },
  A2:  { label: "Normalize → Evidence",     icon: GitBranch, color: "#0891b2" },
  A3:  { label: "Fingerprint Router",       icon: Search,    color: "#7c3aed" },
  A4:  { label: "Anomaly Detection",        icon: Zap,       color: "#ea580c" },
  A5:  { label: "GNN Correlator",           icon: Network,   color: "#059669" },
  A6:  { label: "Attribution · RAG",        icon: Brain,     color: "#d97706" },
  A10: { label: "Active Hunt",              icon: Eye,       color: "#dc2626" },
  A8:  { label: "Critic · FP Challenge",   icon: Cpu,       color: "#7c3aed" },
  A7:  { label: "SOAR Planner",            icon: Radio,     color: "#0a58ca" },
  A13: { label: "Federation · SD-5",       icon: Network,   color: "#64748b" },
  A12: { label: "Audit Chain · A12",       icon: Lock,      color: "#059669" },
};

const STATUS_CFG = {
  pass:  { icon: CheckCircle2, cls: "text-emerald-500", bg: "bg-emerald-50  border-emerald-200", label: "PASS"  },
  flag:  { icon: AlertTriangle,cls: "text-amber-500",   bg: "bg-amber-50   border-amber-200",   label: "FLAG"  },
  block: { icon: XCircle,      cls: "text-red-500",     bg: "bg-red-50     border-red-200",     label: "BLOCK" },
  error: { icon: XCircle,      cls: "text-red-600",     bg: "bg-red-50     border-red-200",     label: "ERROR" },
  skip:  { icon: SkipForward,  cls: "text-slate-400",   bg: "bg-slate-50   border-slate-200",   label: "SKIP"  },
};

const TraceStep = ({ step, isLast }) => {
  const [open, setOpen] = useState(false);
  const meta   = AGENT_META[step.agent] || { label: step.agent, icon: Cpu, color: "#64748b" };
  const scfg   = STATUS_CFG[step.status] || STATUS_CFG.skip;
  const Icon   = meta.icon;
  const SIcon  = scfg.icon;
  const hasDetail = step.detail && Object.keys(step.detail).length > 0;

  return (
    <div className="flex gap-3">
      {/* Timeline spine */}
      <div className="flex flex-col items-center shrink-0" style={{ width: 28 }}>
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center border-2 shrink-0"
          style={{ borderColor: meta.color, background: meta.color + "18" }}
        >
          <Icon size={13} style={{ color: meta.color }} />
        </div>
        {!isLast && <div className="w-px flex-1 bg-slate-200 mt-1" style={{ minHeight: 18 }} />}
      </div>

      {/* Content */}
      <div className={`flex-1 mb-2 rounded-lg border text-[12px] overflow-hidden ${scfg.bg}`}>
        <div
          className="px-3 py-2 flex items-center gap-2 cursor-pointer select-none"
          onClick={() => hasDetail && setOpen(o => !o)}
        >
          <SIcon size={13} className={scfg.cls} />
          <span className="font-mono font-bold text-[10.5px] text-slate-500 shrink-0 w-7">{step.agent}</span>
          <span className="font-semibold text-slate-700 shrink-0">{meta.label}</span>
          <span className={`ml-1 chip text-[9.5px] font-mono !py-0 !px-1.5 ${
            step.status === "pass"  ? "chip-clean"    :
            step.status === "flag"  ? "chip-warning"  :
            step.status === "block" || step.status === "error" ? "chip-critical" :
            "chip-neutral"
          }`}>{scfg.label}</span>
          <span className="flex-1 text-slate-600 ml-1 truncate text-[11px]">{step.summary}</span>
          {hasDetail && (open ? <ChevronDown size={11} /> : <ChevronRight size={11} />)}
        </div>
        {open && hasDetail && (
          <div className="border-t border-slate-200 px-3 py-2 bg-white/70">
            <pre className="text-[10.5px] font-mono text-slate-700 whitespace-pre-wrap">
              {JSON.stringify(step.detail, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

const PipelineTraceCard = ({ item, onExpand, expanded }) => {
  const r = item.result || {};
  const trace = r.pipeline_trace || [];
  const isQuarantined = r.quarantined;
  const hasDecision   = !!r.decision;
  const anomaly       = r.anomaly_score;
  const trust         = r.trust_score;

  return (
    <div className={`rounded-xl border overflow-hidden shadow-sm transition-all ${
      isQuarantined      ? "border-red-300 bg-red-50/40"   :
      item.status === "error" ? "border-red-200 bg-red-50" :
      r.flagged          ? "border-amber-300 bg-amber-50/30" :
      "border-slate-200 bg-white"
    }`}>
      {/* Header row */}
      <div
        className="px-4 py-3 flex items-center gap-2.5 cursor-pointer hover:bg-slate-50/60 transition-colors"
        onClick={onExpand}
      >
        {item.status === "pending" ? (
          <div className="w-3.5 h-3.5 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
        ) : isQuarantined ? (
          <XCircle size={14} className="text-red-500 shrink-0" />
        ) : r.flagged ? (
          <AlertTriangle size={14} className="text-amber-500 shrink-0" />
        ) : item.status === "success" ? (
          <CheckCircle2 size={14} className="text-emerald-500 shrink-0" />
        ) : (
          <XCircle size={14} className="text-red-500 shrink-0" />
        )}

        <span className="font-mono font-semibold text-[12px] flex-1 truncate">{item.label}</span>
        <span className="text-[10.5px] text-slate-400 shrink-0">{item.source}</span>

        {trust != null && (
          <span className="chip chip-neutral text-[10px] font-mono shrink-0">
            trust {trust.toFixed(2)}
          </span>
        )}
        {anomaly != null && (
          <span className={`chip text-[10px] font-mono shrink-0 ${anomaly > 0.6 ? "chip-warning" : "chip-clean"}`}>
            anomaly {anomaly.toFixed(2)}
          </span>
        )}
        {isQuarantined && <span className="chip chip-critical text-[10px] shrink-0">QUARANTINED</span>}
        {hasDecision   && <span className="chip chip-info text-[10px] shrink-0">DECISION QUEUED</span>}
        {r.audit_hash  && <span className="chip chip-clean text-[10px] shrink-0">AUDITED</span>}

        {trace.length > 0 && (
          <span className="text-[10px] text-slate-400 shrink-0">
            {trace.length} steps {expanded ? "▲" : "▼"}
          </span>
        )}
      </div>

      {/* MITRE tags */}
      {(r.mitre_tags || []).length > 0 && (
        <div className="px-4 pb-2 flex flex-wrap gap-1">
          {r.mitre_tags.map(t => (
            <span key={t} className="chip chip-neutral font-mono text-[9.5px]">{t}</span>
          ))}
        </div>
      )}

      {/* Pipeline Trace */}
      {expanded && (
        <div className="border-t border-slate-200 px-4 pt-3 pb-2 bg-slate-50/40">
          {trace.length === 0 ? (
            <div className="text-[12px] text-slate-500 py-2">
              {item.status === "error"
                ? <span className="text-red-600 font-mono">{item.error}</span>
                : "No trace available."}
            </div>
          ) : (
            <>
              <div className="label-caps mb-3 text-slate-500">
                Pipeline Explainability Trace · A1 → A12
              </div>
              <div>
                {trace.map((step, i) => (
                  <TraceStep key={i} step={step} isLast={i === trace.length - 1} />
                ))}
              </div>
              {/* SD Events */}
              {(r.sd_events || []).length > 0 && (
                <div className="mt-3 p-3 rounded-lg bg-red-50 border border-red-200">
                  <div className="label-caps text-red-600 mb-2">Self-Defense Events Fired</div>
                  {r.sd_events.map((e, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11.5px] font-mono text-red-700 py-0.5">
                      <Shield size={10} />
                      <span className="font-bold">{e.layer}</span>
                      <span className="text-red-500">·</span>
                      <span>{e.description}</span>
                    </div>
                  ))}
                </div>
              )}
              {/* Decision summary */}
              {r.decision && (
                <div className="mt-3 p-3 rounded-lg bg-blue-50 border border-blue-200">
                  <div className="label-caps text-blue-600 mb-1.5">SOAR Decision · Awaiting Human Gate</div>
                  <div className="font-mono text-[11.5px] text-blue-800 space-y-0.5">
                    <div><span className="text-blue-500">id:</span> {r.decision.decision_id}</div>
                    <div><span className="text-blue-500">action:</span> {r.decision.action_taken}</div>
                    <div><span className="text-blue-500">risk:</span> {r.decision.risk_score?.toFixed(2)}</div>
                    {r.audit_hash && (
                      <div><span className="text-blue-500">hash:</span> {String(r.audit_hash).slice(0, 20)}…</div>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default PipelineTraceCard;
