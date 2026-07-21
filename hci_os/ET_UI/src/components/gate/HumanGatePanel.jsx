import React, { useState, useEffect, useRef } from "react";
import { TID } from "@/constants/testIds";
import { useApp } from "@/context/AppContext";
import { useDecisions } from "@/api/useDecisions";
import {
  CheckCircle2, XCircle, Edit3, ArrowUpRight, Users, Clock,
  Loader, ChevronDown, ChevronUp, Code2, Brain, ShieldCheck,
  Terminal, AlertTriangle, Info, Trash2, Sparkles,
} from "lucide-react";

const fmt = (s) => {
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return `${m}m ${sec}s`;
};

const formatTimeIST = (isoString) => {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    return d.toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true,
    }) + " IST";
  } catch (e) { return isoString; }
};

// ── Production code viewer (uses AI-generated snippet) ───────────────────────

export const ProductionCodeView = ({ decision, aiData }) => {
  const isRevoked   = (decision.status === "revoked")   || (decision.action_taken || "").toLowerCase().startsWith("revoked:");
  const isModified  = (decision.status === "modified")  || (decision.action_taken || "").toLowerCase().startsWith("modified:");
  const isEscalated = (decision.status === "escalated") || (decision.action_taken || "").toLowerCase().startsWith("escalated:");

  const label = aiData?.production_code_label || "Execution Code";
  const lang  = aiData?.production_code_lang  || "bash";
  const code  = aiData?.production_code       || "# No code available — generate AI analysis first.";

  return (
    <div className="mt-2 rounded-lg border border-[var(--hci-border)] bg-[#0d1117] overflow-hidden text-[11px]">
      {isRevoked   && <div className="bg-red-950/80 border-b border-red-500/30 px-3 py-1.5 text-red-400 font-semibold flex items-center gap-1.5"><XCircle size={12} /> ACTION REVOKED BY HUMAN OVERRIDE</div>}
      {isModified  && <div className="bg-amber-950/80 border-b border-amber-500/30 px-3 py-1.5 text-amber-400 font-semibold flex items-center gap-1.5"><Edit3 size={12} /> ACTION MODIFIED BY HUMAN OVERRIDE</div>}
      {isEscalated && <div className="bg-blue-950/80 border-b border-blue-500/30 px-3 py-1.5 text-blue-400 font-semibold flex items-center gap-1.5"><ArrowUpRight size={12} /> ACTION ESCALATED BY HUMAN OVERRIDE</div>}
      <div className="flex items-center gap-2 px-3 py-2 bg-[var(--hci-surface-2)] border-b border-[var(--hci-border)]">
        <Terminal size={12} className="text-emerald-400" />
        <span className="font-semibold text-emerald-400">{label}</span>
        <span className="ml-auto font-mono text-[var(--hci-text-3)]">{lang}</span>
      </div>
      <pre className="p-3 overflow-x-auto text-[10.5px] leading-relaxed text-slate-300 whitespace-pre select-all">{code}</pre>
    </div>
  );
};

// ── AI Debate box ─────────────────────────────────────────────────────────────

const AIDebateBox = ({ decision, aiData }) => (
  <div className="mt-3 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] p-3 text-[11.5px]">
    <div className="flex items-center gap-2 mb-2">
      <Brain size={13} className="text-violet-400 shrink-0" />
      <span className="font-bold text-[var(--hci-text)]">AI Reasoning Debate</span>
    </div>
    <div className="space-y-2">
      <div className="flex gap-2">
        <div className="mt-0.5 shrink-0 w-4 h-4 rounded-full bg-emerald-500/20 flex items-center justify-center">
          <CheckCircle2 size={9} className="text-emerald-500" />
        </div>
        <div>
          <div className="text-emerald-400 font-semibold">A6-Attribution (Proposer)</div>
          <div className="text-[var(--hci-text-3)] leading-relaxed">
            Matched known APT threat profile via RAG + MITRE ATT&CK. Confidence boosted by&nbsp;
            <span className="font-mono text-[var(--hci-text)]">{(decision.risk_score * 100).toFixed(0)}%</span>&nbsp;
            supporting evidence density. Bayesian posterior:&nbsp;
            <span className="font-mono text-amber-400">P(H|E) = {decision.risk_score.toFixed(3)}</span>
          </div>
        </div>
      </div>
      <div className="flex gap-2">
        <div className="mt-0.5 shrink-0 w-4 h-4 rounded-full bg-amber-500/20 flex items-center justify-center">
          <AlertTriangle size={9} className="text-amber-500" />
        </div>
        <div>
          <div className="text-amber-400 font-semibold">A8-Critic (Skeptic)</div>
          <div className="text-[var(--hci-text-3)] leading-relaxed">
            Checked 5 counter-evidence signals: whitelist, known-scanner IPs, TLS validity,
            red-team windows, maintenance windows. False-positive likelihood:&nbsp;
            <span className="font-mono text-orange-400">{((1 - decision.risk_score) * 30).toFixed(0)}%</span>.
            Blast radius&nbsp;
            <span className="font-mono text-[var(--hci-text)]">{decision.blast_radius_score?.toFixed(2) ?? "—"}</span>&nbsp;
            forced <strong>HUMAN_GATE</strong> (threshold 0.60).
          </div>
        </div>
      </div>
      <div className="flex gap-2">
        <div className="mt-0.5 shrink-0 w-4 h-4 rounded-full bg-blue-500/20 flex items-center justify-center">
          <Info size={9} className="text-blue-400" />
        </div>
        <div>
          <div className="text-blue-400 font-semibold">Decision Formula</div>
          <code className="text-[10.5px] text-[var(--hci-text-3)] font-mono">
            Risk = Likelihood × Impact × Exposure × Confidence&nbsp;=&nbsp;{decision.risk_score.toFixed(4)}
          </code>
        </div>
      </div>
    </div>
  </div>
);

// ── Modify modal ──────────────────────────────────────────────────────────────

const ModifyModal = ({ decision, onClose, onSubmit }) => {
  const [customAction, setCustomAction] = useState(decision.action_taken || "");
  const [notes, setNotes]               = useState("");
  const ref = useRef(null);
  useEffect(() => { ref.current?.focus(); }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[var(--hci-surface)] border border-[var(--hci-border)] rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
        <div className="flex items-center gap-2 mb-4">
          <Edit3 size={16} className="text-amber-400" />
          <h2 className="font-bold text-[14px]">Modify Action</h2>
          <span className="ml-auto font-mono text-[11px] text-[var(--hci-text-3)]">{decision.decision_id}</span>
        </div>
        <div className="mb-3">
          <label className="label-caps block mb-1">Current AI-Proposed Action</label>
          <div className="px-3 py-2 rounded-lg bg-[var(--hci-surface-2)] font-mono text-[12px] text-[var(--hci-text-3)]">
            {decision.action_taken}
          </div>
        </div>
        <div className="mb-3">
          <label className="label-caps block mb-1">Your Modified Action *</label>
          <input
            ref={ref}
            value={customAction}
            onChange={(e) => setCustomAction(e.target.value)}
            placeholder="e.g. MONITOR instead of ISOLATE_HOST"
            className="w-full px-3 py-2 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] text-[12.5px] text-[var(--hci-text)] outline-none focus:border-[var(--hci-brand)] transition-colors font-mono"
          />
        </div>
        <div className="mb-5">
          <label className="label-caps block mb-1">Analyst Notes (optional)</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Reason for modification…"
            rows={2}
            className="w-full px-3 py-2 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] text-[12px] text-[var(--hci-text)] outline-none focus:border-[var(--hci-brand)] transition-colors resize-none"
          />
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="btn btn-ghost btn-sm">Cancel</button>
          <button
            disabled={!customAction.trim()}
            onClick={() => onSubmit(customAction.trim(), notes)}
            className="btn btn-amber-outline btn-sm"
          >
            <Edit3 size={12} /> Apply Modification
          </button>
        </div>
      </div>
    </div>
  );
};

// ── Main Panel ────────────────────────────────────────────────────────────────

const HumanGatePanel = ({ compact = false }) => {
  const { role } = useApp();
  const readOnly = role.id === "ciso";
  const { data: apiDecisions, isLoading, act: mutate, isMutating } = useDecisions(role);

  const [localStatus, setLocalStatus]       = useState({});
  const [expandedCode, setExpandedCode]     = useState({});
  const [expandedDebate, setExpandedDebate] = useState({});
  const [expandedExplain, setExpandedExplain] = useState({});
  const [aiData, setAiData]                 = useState({});  // keyed by decision_id
  const [aiLoading, setAiLoading]           = useState({});
  const [modifyTarget, setModifyTarget]     = useState(null);
  const [tick, setTick]                     = useState(0);
  const [rows, setRows]                     = useState([]);
  const [deletedIds, setDeletedIds]         = useState(new Set());
  const [priorityFilter, setPriorityFilter] = useState("all");

  useEffect(() => {
    const iv = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    if (!apiDecisions) return;
    setRows(prev => {
      const existingMap = new Map(prev.map(item => [item.decision_id, item]));
      const updated = [];
      for (const item of prev) {
        if (item.status !== "pending" && !deletedIds.has(item.decision_id)) updated.push(item);
      }
      for (const apiItem of apiDecisions) {
        if (deletedIds.has(apiItem.decision_id)) continue;
        const existing = existingMap.get(apiItem.decision_id);
        if (existing) {
          if (existing.status === "pending") {
            updated.push({ ...apiItem, status: localStatus[apiItem.decision_id] ?? "pending" });
          }
        } else {
          updated.push({ ...apiItem, status: localStatus[apiItem.decision_id] ?? "pending" });
        }
      }
      return updated.sort((a, b) => new Date(b.ts_iso || 0) - new Date(a.ts_iso || 0));
    });
  }, [apiDecisions, deletedIds, localStatus]);

  const filteredRows = rows.filter((r) => {
    if (priorityFilter === "high") {
      return (r.blast_radius_score ?? r.blast_radius ?? 0) >= 0.3;
    }
    return true;
  });

  const timeLeft   = (r) => Math.max(0, (r.sla_seconds_left ?? 900) - tick);
  const toggleCode    = (id) => setExpandedCode((s)    => ({ ...s, [id]: !s[id] }));
  const toggleDebate  = (id) => setExpandedDebate((s)  => ({ ...s, [id]: !s[id] }));
  const toggleExplain = (id) => setExpandedExplain((s) => ({ ...s, [id]: !s[id] }));

  const generateAI = async (decisionId) => {
    setAiLoading(l => ({ ...l, [decisionId]: true }));
    try {
      const res = await fetch(`/api/decisions/explain/${decisionId}`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setAiData(d => ({ ...d, [decisionId]: data }));
        // Auto-open both panels
        setExpandedExplain(s => ({ ...s, [decisionId]: true }));
        setExpandedCode(s    => ({ ...s, [decisionId]: true }));
      }
    } catch (err) {
      console.error("AI explain failed:", err);
    } finally {
      setAiLoading(l => ({ ...l, [decisionId]: false }));
    }
  };

  const act = (id, status, action, newAction = undefined, notes = undefined) => {
    setLocalStatus((s) => ({ ...s, [id]: status }));
    setRows((prev) => prev.map((r) => r.decision_id === id
      ? { ...r, status, action_taken: newAction !== undefined ? newAction : r.action_taken }
      : r
    ));
    mutate({ decisionId: id, action, analystId: role.email, newAction, notes });
  };

  const handleModifySubmit = (decision, customAction, notes) => {
    setModifyTarget(null);
    act(decision.decision_id, "modified", "modify", customAction, notes);
  };

  return (
    <>
      {modifyTarget && (
        <ModifyModal
          decision={modifyTarget}
          onClose={() => setModifyTarget(null)}
          onSubmit={(a, n) => handleModifySubmit(modifyTarget, a, n)}
        />
      )}

      <div className="panel h-full flex flex-col">
        <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2 flex-wrap">
          <Users size={15} className="text-[var(--hci-brand)] shrink-0" />
          <div className="font-head font-bold text-[13.5px]">Human Gate</div>
          <span className="chip chip-warning">{filteredRows.filter(r => r.status === "pending").length} pending</span>
          {isLoading && <Loader size={12} className="animate-spin text-[var(--hci-text-3)]" />}
          
          <div className="ml-auto flex items-center gap-3">
            <select
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.target.value)}
              className="text-[11.5px] bg-[var(--hci-surface-2)] border border-[var(--hci-border)] rounded-lg px-2.5 py-1 outline-none text-[var(--hci-text)] font-semibold hover:border-slate-400 transition-colors"
            >
              <option value="all">All Priorities</option>
              <option value="high">⚠️ High Priority (Blast Radius &ge; 0.30)</option>
            </select>
            <span className="label-caps whitespace-nowrap text-[var(--hci-text-3)]">SLA · 15 min</span>
          </div>
        </div>

        <div className="flex-1 overflow-auto">
          {filteredRows.length === 0 && !isLoading && (
            <div className="p-8 text-center text-[var(--hci-text-3)] flex flex-col items-center justify-center h-full">
              <CheckCircle2 size={32} className="mb-2 text-emerald-500 opacity-60" />
              <div className="font-semibold text-[12.5px]">All Gates Cleared</div>
              <div className="text-[11.5px] mt-0.5 max-w-[200px] mx-auto">
                No decisions matching the active filter pending human authorization.
              </div>
            </div>
          )}

          {filteredRows.map((r) => {
            const left        = timeLeft(r);
            const slaCritical = left < 300;
            const acted       = r.status !== "pending";
            const codeOpen    = !!expandedCode[r.decision_id];
            const debateOpen  = !!expandedDebate[r.decision_id];
            const explainOpen = !!expandedExplain[r.decision_id];
            const ai          = aiData[r.decision_id];
            const aiIsLoading = !!aiLoading[r.decision_id];
            const isAuto      = !r.action_taken?.includes("(PENDING)") && r.action_taken?.toLowerCase() !== "monitor";

            return (
              <div
                key={r.decision_id}
                data-testid={TID.gateRow(r.decision_id)}
                className="px-5 py-4 border-b border-[var(--hci-border)] card-hover"
              >
                <div className="flex items-start gap-3">
                  <div className={`w-1 rounded-full self-stretch ${acted ? "bg-emerald-500" : slaCritical ? "bg-red-500" : "bg-amber-500"}`} />
                  <div className="flex-1 min-w-0">
                    {/* Header */}
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
 
                    {/* Action */}
                    <div className="mt-1.5 flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-[13.5px] text-[var(--hci-text)]">{r.action_taken}</span>
                      {isAuto ? (
                        <span className="chip chip-clean bg-emerald-500/10 text-emerald-400 border-emerald-500/20 font-bold text-[10.5px] flex items-center gap-1">
                          <Sparkles size={11} className="text-emerald-400 animate-pulse" /> Autonomous AI Execution (Overrideable)
                        </span>
                      ) : (
                        <span className="chip chip-warning bg-amber-500/10 text-amber-400 border-amber-500/20 font-bold text-[10.5px] flex items-center gap-1">
                          <Clock size={11} className="text-amber-400" /> Pending Human Gate Approval
                        </span>
                      )}
                    </div>

                    {/* Metrics */}
                    <div className="mt-1 flex items-center gap-4 text-[11.5px] text-[var(--hci-text-3)] font-mono">
                      <span>risk <span className="text-[var(--hci-text)] font-semibold">{(r.risk_score||0).toFixed(2)}</span></span>
                      <span>blast_radius <span className="text-[var(--hci-text)] font-semibold">{(r.blast_radius_score||0).toFixed(2)}</span></span>
                      <span>ts {formatTimeIST(r.ts_iso)}</span>
                    </div>
 
                    {/* AI Generate button + expandable explain */}
                    <div className="mt-2 space-y-1">
                      {!ai && (
                        <button
                          onClick={() => generateAI(r.decision_id)}
                          disabled={aiIsLoading}
                          className="flex items-center gap-1.5 text-[10.5px] text-violet-400 hover:text-violet-300 transition-colors font-semibold disabled:opacity-50"
                        >
                          {aiIsLoading
                            ? <Loader size={11} className="animate-spin" />
                            : <Sparkles size={11} />}
                          {aiIsLoading ? "Generating AI Analysis…" : "✦ Generate AI Analysis & Code"}
                        </button>
                      )}
                      {ai && (
                        <button
                          onClick={() => toggleExplain(r.decision_id)}
                          className="flex items-center gap-1.5 text-[10.5px] text-[var(--hci-brand)] hover:text-blue-400 transition-colors font-semibold"
                        >
                          <Info size={12} /> {explainOpen ? "▲ Hide" : "▼ Show"} AI Explanation
                        </button>
                      )}
                    </div>
 
                    {/* AI Explanation Drawer */}
                    {ai && explainOpen && (
                      <div className="mt-2 rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] p-3 space-y-3 text-[11.5px]">
                        <div>
                          <div className="text-[var(--hci-brand)] font-bold mb-1">🔍 What Happened</div>
                          <div className="text-[var(--hci-text-2)] leading-relaxed">{ai.what_happened}</div>
                        </div>
                        <div>
                          <div className="text-amber-400 font-bold mb-1">📡 Request & Source</div>
                          <div className="text-[var(--hci-text-2)] leading-relaxed">
                            Decision <span className="font-mono text-[var(--hci-text)]">{r.decision_id}</span> was raised by{" "}
                            <span className="font-mono text-[var(--hci-text)]">{r.proposed_by || "A7-SOAR"}</span> at{" "}
                            {formatTimeIST(r.ts_iso)} targeting hypothesis{" "}
                            <span className="font-mono text-[var(--hci-text)]">{r.hypothesis_id}</span>.
                          </div>
                        </div>
                        <div>
                          <div className="text-red-400 font-bold mb-1">⚠️ Potential Impact if Ignored</div>
                          <div className="text-[var(--hci-text-2)] leading-relaxed">{ai.potential_impact}</div>
                        </div>
                        <div>
                          <div className="text-violet-400 font-bold mb-1">🛑 Why Human Gate Was Raised</div>
                          <div className="text-[var(--hci-text-2)] leading-relaxed">{ai.why_stopped}</div>
                        </div>
                        <div>
                          <div className="text-emerald-400 font-bold mb-1">✅ Agent Decision Validation</div>
                          <div className="space-y-1">
                            {(ai.agent_decisions || []).map((a) => (
                              <div key={a.agent} className="flex items-center gap-2 font-mono">
                                <span className={`w-28 shrink-0 ${a.color || "text-slate-400"}`}>{a.agent}</span>
                                <span className="text-[var(--hci-text-3)]">{a.result}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div className="text-cyan-400 font-bold mb-1">💻 What the Execution Code Will Do</div>
                          <div className="text-[var(--hci-text-2)] leading-relaxed">
                            If <strong>CONFIRMED</strong>, the production code below will automatically {ai.code_action}. This action is{" "}
                            <span className="text-emerald-400 font-semibold">reversible</span> and logged to the immutable A12 audit chain.
                          </div>
                        </div>
                      </div>
                    )}
 
                    {/* Controls row */}
                    <div className="mt-2 flex gap-2 flex-wrap">
                      {!acted && (
                        <button
                          onClick={() => toggleDebate(r.decision_id)}
                          className="flex items-center gap-1 text-[10.5px] text-violet-400 hover:text-violet-300 transition-colors"
                        >
                          <Brain size={11} />
                          AI Debate {debateOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                        </button>
                      )}
                      {ai && (
                        <button
                          onClick={() => toggleCode(r.decision_id)}
                          className="flex items-center gap-1 text-[10.5px] text-emerald-400 hover:text-emerald-300 transition-colors"
                        >
                          <Code2 size={11} />
                          Production Code {(codeOpen || acted) ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                        </button>
                      )}
                    </div>
 
                    {debateOpen && !acted && <AIDebateBox decision={r} aiData={ai} />}
                    {ai && (codeOpen || acted) && <ProductionCodeView decision={r} aiData={ai} />}
 
                    {/* Action buttons */}
                    {acted ? (
                      <div className="mt-2 flex items-center gap-2">
                        <span className="chip chip-clean">
                          <CheckCircle2 size={12} /> {r.status.toUpperCase()}
                        </span>
                        <button
                          onClick={() => setDeletedIds(prev => { const next = new Set(prev); next.add(r.decision_id); return next; })}
                          className="text-red-400 hover:text-red-300 p-1 rounded hover:bg-red-500/10 transition-colors flex items-center justify-center"
                          title="Delete from view"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    ) : (
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        <button
                          data-testid={TID.gateConfirm(r.decision_id)}
                          disabled={readOnly || isMutating}
                          onClick={() => act(r.decision_id, "confirmed", "confirm")}
                          className={`${isAuto ? "btn-outline" : "btn-success-outline"} btn btn-sm`}
                        >
                          <CheckCircle2 size={12} /> {isAuto ? "ACKNOWLEDGE & DISMISS" : "CONFIRM"}
                        </button>
                        <button data-testid={TID.gateRevoke(r.decision_id)} disabled={readOnly || isMutating} onClick={() => act(r.decision_id, "revoked", "revoke")} className="btn btn-danger btn-sm">
                          <XCircle size={12} /> REVOKE
                        </button>
                        <button data-testid={TID.gateModify(r.decision_id)} disabled={readOnly || isMutating} onClick={() => setModifyTarget(r)} className="btn btn-amber-outline btn-sm">
                          <Edit3 size={12} /> MODIFY
                        </button>
                        <button data-testid={TID.gateEscalate(r.decision_id)} disabled={readOnly || isMutating} onClick={() => act(r.decision_id, "escalated", "escalate")} className="btn btn-primary btn-sm">
                          <ArrowUpRight size={12} /> ESCALATE
                        </button>
                        {readOnly && <span className="text-[10.5px] text-[var(--hci-text-3)] self-center">{role.label}: read-only</span>}
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
    </>
  );
};

export default HumanGatePanel;
