import React, { useState, useEffect } from "react";
import { TID } from "@/constants/testIds";
import {
  FileText, Download, RefreshCw, ShieldAlert, CheckCircle2,
  Loader, Printer, Sparkles, ChevronDown, ChevronUp, Clock,
} from "lucide-react";
import { useCertIn } from "@/api/useCertIn";
import { usePipelineHistory } from "@/api/usePipelineHistory";
import { useCountdown } from "@/hooks/useCountdown";

const Row = ({ label, value, mono = false }) => (
  <tr className="border-b border-[var(--hci-border)] last:border-0">
    <td className="py-2 pr-4 label-caps whitespace-nowrap align-top">{label}</td>
    <td className={`py-2 text-[13px] ${mono ? "font-mono" : ""}`}>{value}</td>
  </tr>
);

// ── AI-generated compliance narrative section ─────────────────────────────────
const NarrativeSection = ({ title, content, color = "text-[var(--hci-brand)]" }) => (
  <div className="mb-4">
    <div className={`font-bold text-[12.5px] ${color} mb-1`}>{title}</div>
    <div className="text-[12.5px] text-[var(--hci-text-2)] leading-relaxed whitespace-pre-wrap">{content}</div>
  </div>
);

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

const CertInReport = () => {
  const [selectedId, setSelectedId] = useState("latest");
  const { data, refetch, isLoading } = useCertIn(selectedId);
  const { data: historyData, isLoading: historyLoading } = usePipelineHistory(50);
  const incident       = data?.incident;
  const timelineEvents = data?.timeline_events ?? [];
  const auditExcerpt   = data?.audit_excerpt   ?? [];
  const countdown      = useCountdown(incident?.detection_ts);

  // AI narrative state
  const [aiReport, setAiReport]       = useState(null);
  const [aiLoading, setAiLoading]     = useState(false);
  const [showNarrative, setShowNarrative] = useState(true);

  // Reset AI report when switching incidents
  useEffect(() => {
    setAiReport(null);
  }, [selectedId]);

  const generateAIReport = async () => {
    if (!incident) return;
    setAiLoading(true);
    try {
      const targetId = selectedId === "latest" ? (incident.hypothesis_id ?? "latest") : selectedId;
      const res = await fetch(`/api/cert-in/generate/${targetId}`, {
        method: "POST",
      });
      if (res.ok) {
        const json = await res.json();
        setAiReport(json);
        setShowNarrative(true);
      }
    } catch (err) {
      console.error("AI report generation failed:", err);
    } finally {
      setAiLoading(false);
    }
  };

  const downloadMarkdown = async () => {
    if (!incident) return;
    try {
      const targetId = selectedId === "latest" ? (incident.hypothesis_id ?? "latest") : selectedId;
      const res = await fetch(`/api/cert-in/report/${targetId}?format=md`);
      const text = await res.text();
      const blob = new Blob([text], { type: "text/markdown" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = `CERT-IN_${targetId}.md`;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a); URL.revokeObjectURL(url);
    } catch { /* silent */ }
  };

  const exportPDF = async () => {
    if (!incident) return;
    try {
      const targetId = selectedId === "latest" ? (incident.hypothesis_id ?? "latest") : selectedId;
      const res = await fetch(`/api/cert-in/report/${targetId}?format=pdf`);
      if (!res.ok) throw new Error("PDF download failed");
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url;
      a.download = `CERT-IN_${targetId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Export PDF failed:", err);
      alert("Failed to export PDF. Please check backend connection.");
    }
  };

  // Professional period report generation states
  const [reportType, setReportType] = useState("monthly");
  const [startDate, setStartDate]   = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 30);
    return d.toISOString().split("T")[0];
  });
  const [endDate, setEndDate]       = useState(() => new Date().toISOString().split("T")[0]);
  const [sectorFilter, setSectorFilter] = useState("");
  const [exportFormat, setExportFormat] = useState("pdf");
  const [generatingPeriod, setGeneratingPeriod] = useState(false);

  const handleGeneratePeriodReport = async () => {
    setGeneratingPeriod(true);
    try {
      const params = new URLSearchParams({
        start_date: startDate,
        end_date: endDate,
        report_type: reportType,
        format: exportFormat,
      });
      if (sectorFilter) {
        params.append("sector", sectorFilter);
      }
      
      const downloadUrl = `/api/cert-in/export?${params.toString()}`;
      const res = await fetch(downloadUrl);
      if (!res.ok) throw new Error("Export failed");
      
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url;
      a.download = `CERT-IN_${reportType.toUpperCase()}_REPORT_${startDate}_to_${endDate}.${exportFormat === "markdown" ? "md" : exportFormat}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Cumulative report generation failed:", err);
      alert("Failed to generate report. Please verify date range and inputs.");
    } finally {
      setGeneratingPeriod(false);
    }
  };

  if (isLoading) {
    return (
      <div className="panel p-6 text-center text-slate-500">
        <Loader className="animate-spin inline-block mr-2" size={16} /> Loading compliance report...
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="panel p-8 text-center text-[var(--hci-text-3)] flex flex-col items-center justify-center">
        <FileText size={40} className="mb-3 opacity-20 text-[var(--hci-brand)]" />
        <div className="font-semibold text-[14px]">No Compliance Report Available</div>
        <div className="text-[12.5px] mt-1 max-w-sm">
          No incident data has been recorded yet. Please ingest a security event through the console.
        </div>
      </div>
    );
  }

  return (
    <div className="panel printable-area" data-testid={TID.reportContainer}>
      {/* Header — hidden during print */}
      <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3 no-print">
        <FileText size={16} className="text-[var(--hci-brand)]" />
        <div className="font-head font-bold text-[14.5px]">CERT-In Compliance Report · Draft</div>
        <span className="chip chip-info">Auto-generated</span>
        <div className="ml-auto flex items-center gap-2">
          <div className="text-[11.5px] font-mono text-[var(--hci-text-3)]">6h deadline</div>
          <span className="chip chip-critical font-mono">{countdown}</span>
          <button onClick={() => refetch()} className="btn btn-ghost btn-sm">
            <RefreshCw size={13} /> Refresh
          </button>
          <button
            onClick={generateAIReport}
            disabled={aiLoading}
            className="btn btn-outline btn-sm"
            data-testid={TID.reportGenerate}
          >
            {aiLoading ? <Loader size={13} className="animate-spin" /> : <Sparkles size={13} />}
            {aiLoading ? "Generating…" : "Generate AI Report"}
          </button>
          <button onClick={downloadMarkdown} className="btn btn-outline btn-sm" data-testid={TID.reportDownload}>
            <Download size={13} /> Download .md
          </button>
          <button onClick={exportPDF} className="btn btn-primary btn-sm">
            <FileText size={13} /> Export PDF
          </button>
        </div>
      </div>

      <div className="p-6 grid grid-cols-12 gap-6">
        {/* Left Sidebar: Incident History */}
        <div className="col-span-3 border-r border-[var(--hci-border)] pr-4 space-y-3 no-print">
          <div className="label-caps mb-1 flex items-center gap-1.5 text-[var(--hci-brand)]">
            <Clock size={12} />
            Incident History
          </div>
          <div className="space-y-2 max-h-[calc(100vh-220px)] overflow-y-auto pr-1">
            {historyLoading ? (
              <div className="text-[12px] text-[var(--hci-text-3)] p-4 text-center">
                <Loader size={12} className="animate-spin inline mr-1" /> Loading history…
              </div>
            ) : !historyData || historyData.length === 0 ? (
              <div className="text-[12px] text-[var(--hci-text-3)] p-4 text-center">
                No history recorded
              </div>
            ) : (
              historyData.map((run) => {
                const isSelected = selectedId === run.hypothesis_id || (selectedId === "latest" && run.hypothesis_id === incident?.hypothesis_id);
                return (
                  <button
                    key={run.run_id || run.hypothesis_id}
                    onClick={() => setSelectedId(run.hypothesis_id)}
                    className={`w-full text-left p-2.5 rounded-xl border transition-all flex flex-col gap-1.5 ${
                      isSelected
                        ? "bg-blue-500/10 border-[var(--hci-brand)] text-[var(--hci-text)]"
                        : "bg-[var(--hci-surface)] border-[var(--hci-border)] hover:border-slate-400 text-[var(--hci-text-2)]"
                    }`}
                  >
                    <div className="flex items-center gap-2 w-full justify-between">
                      <span className="font-mono text-[11px] font-bold">{run.hypothesis_id}</span>
                      <span className={`chip !py-0 !text-[9px] ${run.flagged ? "chip-warning" : "chip-clean"}`}>
                        {run.flagged ? "FLAGGED" : "CLEAN"}
                      </span>
                    </div>
                    <div className="text-[12px] font-semibold truncate w-full">{run.asset_id || "Unknown Asset"}</div>
                    <div className="text-[10px] text-[var(--hci-text-3)] font-mono flex justify-between w-full">
                      <span>risk {run.anomaly_score?.toFixed(2) ?? "0.00"}</span>
                      <span>{formatTimeIST(run.created_at)}</span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Middle: Main report */}
        <div className="col-span-6 print:col-span-12">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert size={18} className="text-[var(--hci-critical)]" />
            <div className="font-head font-bold text-[18px]">
              Section 70B · Cyber Incident Report — {incident.hypothesis_id}
            </div>
          </div>
          <div className="text-[12.5px] text-[var(--hci-text-2)] mb-4 leading-relaxed">
            Prepared under CERT-In Directions dated 28 April 2022 for reporting cyber incidents
            involving critical information infrastructure. This document is machine-generated
            from HCI-OS audit chain at {new Date().toISOString()}.
          </div>

          <table className="w-full text-[13px]">
            <tbody>
              <Row label="Incident ID"          value={incident.hypothesis_id} mono />
              <Row label="Title"                value={incident.title} />
              <Row label="Target Asset"         value={incident.target} />
              <Row label="Detection Timestamp"  value={incident.detection_ts} mono />
              <Row label="Confidence"           value={`${((incident.confidence ?? 0.94) * 100).toFixed(1)} %`} mono />
              <Row label="Status"               value={<span className="chip chip-clean"><CheckCircle2 size={11}/> {incident.status ?? "CONTAINED"}</span>} />
              <Row label="MITRE ATT&CK"         value={(incident.mitre_chain ?? []).map((m) => <span key={m} className="chip chip-neutral font-mono mr-1">{m}</span>)} />
              <Row
                label="Affected Assets"
                value={
                  <ul className="space-y-0.5">
                    {(incident.affected_assets ?? []).map((a) => (
                      <li key={a.id} className="font-mono">{a.name} <span className="chip chip-warning !py-0 !text-[10px]">{a.criticality}</span></li>
                    ))}
                  </ul>
                }
              />
              <Row
                label="IOCs"
                value={
                  <ul className="space-y-0.5">
                    {(incident.iocs ?? []).map((i, k) => (
                      <li key={k} className="font-mono text-[12px]">
                        <span className="chip chip-neutral !py-0 !text-[10px] mr-1">{i.type}</span>
                        {i.value} <span className="text-[var(--hci-text-3)]">— {i.note}</span>
                      </li>
                    ))}
                  </ul>
                }
              />
              <Row label="Timeline"         value={`${timelineEvents.length} events · T-0 to T+43s`} />
              <Row label="Actions Taken"    value={<span className="font-mono text-[12px]">{incident.actions_taken ?? "See audit chain below"}</span>} />
              <Row label="Actions Reversed" value={<span className="chip chip-clean">{incident.actions_reversed ?? "none"}</span>} />
              <Row label="DPDP Notification" value={<span className="text-[var(--hci-text-2)]">Not required · no personal data exfiltrated. Placeholder for compliance workflow.</span>} />
            </tbody>
          </table>

          {/* AI-generated narrative */}
          {!aiReport && (
            <div className="mt-6 rounded-lg border border-dashed border-[var(--hci-border)] p-4 text-center text-[12.5px] text-[var(--hci-text-3)]">
              <Sparkles size={18} className="mx-auto mb-2 text-violet-400 opacity-60" />
              <div className="font-semibold">AI-Generated Compliance Narrative</div>
              <div className="mt-1">Click <strong>Generate AI Report</strong> to produce a deep causal analysis, root-cause summary, and legal assessment via Groq LLM.</div>
            </div>
          )}

          {aiReport && (
            <div className="mt-6 space-y-2">
              <div className="flex items-center gap-2 mb-3 no-print">
                <Sparkles size={14} className="text-violet-400" />
                <span className="font-bold text-[13px] text-violet-400">AI-Generated Compliance Narrative</span>
                <button onClick={() => setShowNarrative(v => !v)} className="ml-auto text-[10.5px] text-[var(--hci-text-3)] flex items-center gap-1">
                  {showNarrative ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  {showNarrative ? "Collapse" : "Expand"}
                </button>
              </div>
              {showNarrative && (
                <div className="rounded-lg border border-[var(--hci-border)] bg-[var(--hci-surface-2)] p-4 space-y-3">
                  {aiReport.abstract       && <NarrativeSection title="📋 Incident Abstract"        content={aiReport.abstract}          color="text-[var(--hci-brand)]" />}
                  {aiReport.root_cause     && <NarrativeSection title="🔎 Root Cause Analysis"      content={aiReport.root_cause}        color="text-amber-600" />}
                  {aiReport.attack_chain   && <NarrativeSection title="⛓️ Attack Chain Narrative"   content={aiReport.attack_chain}      color="text-red-600" />}
                  {aiReport.remediation    && <NarrativeSection title="🛡️ Remediation & Recovery"   content={aiReport.remediation}       color="text-emerald-600" />}
                  {aiReport.legal_analysis && <NarrativeSection title="⚖️ Legal & Compliance Notes" content={aiReport.legal_analysis}    color="text-violet-600" />}
                  {aiReport.recommendations && <NarrativeSection title="📌 Long-term Recommendations" content={aiReport.recommendations} color="text-sky-600" />}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: Sidebar */}
        <div className="col-span-3 print:col-span-12 space-y-4">
          <div className="panel-raised p-4">
            <div className="label-caps mb-2">6-Hour SLA Countdown</div>
            <div className="font-mono text-[24px] font-bold text-[var(--hci-critical)]">{countdown}</div>
            <div className="text-[11.5px] text-[var(--hci-text-3)] mt-1">since detection @ {incident.detection_ts}</div>
          </div>
          <div className="panel-raised p-4">
            <div className="label-caps mb-2">Audit Chain Excerpt</div>
            <div className="space-y-1.5 font-mono text-[11px]">
              {(auditExcerpt ?? []).slice(0, 5).map((a, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="text-[var(--hci-brand)] w-16 shrink-0">{a.ts}</span>
                  <span className="flex-1 truncate">{a.actor}::{a.event}</span>
                  <span className="text-[var(--hci-text-3)]">{String(a.hash || "").slice(0, 8)}</span>
                </div>
              ))}
            </div>
            <div className="text-[10.5px] text-[var(--hci-text-3)] mt-2">Signed with A12-hash-chain (SHA-256).</div>
          </div>
          <div className="panel-raised p-4 text-[12px] leading-relaxed">
            <div className="font-semibold mb-1">Filed by</div>
            <div>Sriram Iyer, CISO</div>
            <div className="font-mono text-[11px] text-[var(--hci-text-3)]">s.iyer@cbse.gov.in</div>
            <div className="mt-2 text-[11.5px] text-[var(--hci-text-3)]">
              Downloaded copies are watermarked with the audit chain root hash.
            </div>
          </div>

          {/* Professional Compliance Report Generator */}
          <div className="panel-raised p-4 space-y-3 no-print">
            <div className="label-caps mb-1 flex items-center gap-1.5 text-[var(--hci-brand)]">
              <FileText size={12} />
              Professional Period Report
            </div>
            <p className="text-[11px] text-[var(--hci-text-3)] leading-relaxed">
              Compile and download a sector-filtered regulatory report across all agents.
            </p>
            <div className="space-y-2.5 text-[12.5px]">
              <div>
                <label className="block text-[10px] font-bold text-[var(--hci-text-3)] uppercase tracking-wider mb-1">Report Type</label>
                <select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                  className="w-full bg-[var(--hci-surface-2)] border border-[var(--hci-border)] rounded-lg p-2 outline-none text-[12px]"
                >
                  <option value="weekly">Weekly Summary</option>
                  <option value="monthly">Monthly Audit</option>
                  <option value="quarterly">Quarterly Compliance</option>
                  <option value="annual">Annual Executive</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[10px] font-bold text-[var(--hci-text-3)] uppercase tracking-wider mb-1">Start Date</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    className="w-full bg-[var(--hci-surface-2)] border border-[var(--hci-border)] rounded-lg p-1.5 outline-none font-mono text-[11px]"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-bold text-[var(--hci-text-3)] uppercase tracking-wider mb-1">End Date</label>
                  <input
                    type="date"
                    value={endDate}
                    onChange={(e) => setEndDate(e.target.value)}
                    className="w-full bg-[var(--hci-surface-2)] border border-[var(--hci-border)] rounded-lg p-1.5 outline-none font-mono text-[11px]"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[10px] font-bold text-[var(--hci-text-3)] uppercase tracking-wider mb-1">Sector Filter</label>
                <select
                  value={sectorFilter}
                  onChange={(e) => setSectorFilter(e.target.value)}
                  className="w-full bg-[var(--hci-surface-2)] border border-[var(--hci-border)] rounded-lg p-2 outline-none text-[12px]"
                >
                  <option value="">All Sectors</option>
                  <option value="Finance">Finance</option>
                  <option value="Power">Power & Energy</option>
                  <option value="Healthcare">Healthcare</option>
                  <option value="Telecom">Telecom</option>
                  <option value="Education">Education</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold text-[var(--hci-text-3)] uppercase tracking-wider mb-1">Export Format</label>
                <div className="grid grid-cols-3 gap-1">
                  {["pdf", "html", "markdown"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setExportFormat(f)}
                      className={`py-1 text-[11px] font-bold rounded-lg border uppercase transition-colors ${
                        exportFormat === f
                          ? "bg-[var(--hci-brand)] border-[var(--hci-brand)] text-white"
                          : "bg-[var(--hci-surface-2)] border-[var(--hci-border)] hover:border-slate-400 text-[var(--hci-text-2)]"
                      }`}
                    >
                      {f === "markdown" ? "MD" : f}
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={handleGeneratePeriodReport}
                disabled={generatingPeriod}
                className="w-full btn btn-primary text-xs flex items-center justify-center gap-1.5 mt-2"
              >
                {generatingPeriod ? <Loader size={12} className="animate-spin" /> : <Download size={12} />}
                {generatingPeriod ? "Compiling..." : "Generate & Download"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CertInReport;
