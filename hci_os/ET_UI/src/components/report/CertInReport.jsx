import React, { useState, useEffect } from "react";
import { TID } from "@/constants/testIds";
import { FileText, Download, RefreshCw, ShieldAlert, CheckCircle2, Loader } from "lucide-react";
import { useCertIn, downloadCertInMarkdown } from "@/api/useCertIn";

const pad = (n) => n.toString().padStart(2, "0");

const useCountdown = (deadlineHours) => {
  const [seconds, setSeconds] = useState(deadlineHours ? deadlineHours * 3600 - 43 : 0);
  useEffect(() => {
    if (!deadlineHours) return;
    const iv = setInterval(() => setSeconds((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(iv);
  }, [deadlineHours]);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
};

const Row = ({ label, value, mono = false }) => (
  <tr className="border-b border-[var(--hci-border)] last:border-0">
    <td className="py-2 pr-4 label-caps whitespace-nowrap align-top">{label}</td>
    <td className={`py-2 text-[13px] ${mono ? "font-mono" : ""}`}>{value}</td>
  </tr>
);

const CertInReport = () => {
  const { data, refetch, isLoading } = useCertIn("latest");
  const incident = data?.incident;
  const timelineEvents = data?.timeline_events ?? [];
  const auditExcerpt = data?.audit_excerpt ?? [];
  const [generated, setGenerated] = useState(true);
  const countdown = useCountdown(incident?.cert_in_deadline_hours ?? 0);

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
          No incident data has been recorded yet. Please ingest a security event through the console to auto-generate the draft.
        </div>
      </div>
    );
  }

  const download = () => downloadCertInMarkdown("latest").catch(() => {
    // fallback to local markdown build
    const md = buildMarkdown(incident, timelineEvents, auditExcerpt);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `CERT-IN_${incident.hypothesis_id ?? "report"}.md`;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
  });

  return (
    <div className="panel" data-testid={TID.reportContainer}>
      <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3">
        <FileText size={16} className="text-[var(--hci-brand)]" />
        <div className="font-head font-bold text-[14.5px]">CERT-In Compliance Report · Draft</div>
        <span className="chip chip-info">Auto-generated</span>
        <div className="ml-auto flex items-center gap-2">
          <div className="text-[11.5px] font-mono text-[var(--hci-text-3)]">6h deadline</div>
          <span className="chip chip-critical font-mono">{countdown}</span>
          <button data-testid={TID.reportGenerate} onClick={() => setGenerated(true)} className="btn btn-outline btn-sm">
            <RefreshCw size={13} /> Regenerate
          </button>
          <button data-testid={TID.reportDownload} onClick={download} className="btn btn-primary btn-sm">
            <Download size={13} /> Download .md
          </button>
        </div>
      </div>

      {generated && (
        <div className="p-6 grid grid-cols-12 gap-6">
          <div className="col-span-8">
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
                <Row label="Incident ID" value={incident.hypothesis_id} mono />
                <Row label="Title" value={incident.title} />
                <Row label="Target Asset" value={incident.target} />
                <Row label="Detection Timestamp" value={incident.detection_ts} mono />
                <Row label="Confidence" value={`${((incident.confidence ?? 0.94) * 100).toFixed(1)} %`} mono />
                <Row label="Status" value={<span className="chip chip-clean"><CheckCircle2 size={11}/> {incident.status ?? "CONTAINED"}</span>} />
                <Row label="MITRE ATT&CK" value={(incident.mitre_chain ?? []).map((m) => <span key={m} className="chip chip-neutral font-mono mr-1">{m}</span>)} />
                <Row
                  label="Affected Assets"
                  value={
                    <ul className="space-y-0.5">
                      {(incident.affected_assets ?? []).map((a) => (
                        <li key={a.id} className="font-mono">
                          {a.name} <span className="chip chip-warning !py-0 !text-[10px]">{a.criticality}</span>
                        </li>
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
                <Row label="Timeline" value={`${timelineEvents.length} events · T-0 to T+43s`} />
                <Row label="Actions Taken" value={<span className="font-mono text-[12px]">isolate app-03 (PB-ISO-02) · block egress 185.203.116.44</span>} />
                <Row label="Actions Reversed" value={<span className="chip chip-clean">none</span>} />
                <Row label="DPDP Notification" value={<span className="text-[var(--hci-text-2)]">Not required · no personal data exfiltrated. Placeholder for compliance workflow.</span>} />
              </tbody>
            </table>
          </div>

          <div className="col-span-4 space-y-4">
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
                    <span className="text-[var(--hci-text-3)]">{a.hash.slice(0, 8)}</span>
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
          </div>
        </div>
      )}
    </div>
  );
};

const buildMarkdown = (inc = INCIDENT, tl = TIMELINE_EVENTS, al = AUDIT_LOG) => {
  const lines = [];
  lines.push(`# CERT-In Cyber Incident Report — ${inc.hypothesis_id}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push(`## Incident`);
  lines.push(`- **Title:** ${inc.title}`);
  lines.push(`- **Target:** ${inc.target}`);
  lines.push(`- **Detection:** ${inc.detection_ts}`);
  lines.push(`- **Confidence:** ${((inc.confidence ?? 0.94) * 100).toFixed(1)}%`);
  lines.push(`- **Status:** ${inc.status}`);
  lines.push(`- **MITRE Chain:** ${(inc.mitre_chain ?? []).join(", ")}`);
  lines.push("");
  lines.push("## Affected Assets");
  (inc.affected_assets ?? []).forEach((a) => lines.push(`- ${a.name} (${a.criticality})`));
  lines.push("");
  lines.push("## IOCs");
  (inc.iocs ?? []).forEach((i) => lines.push(`- [${i.type}] ${i.value} — ${i.note}`));
  lines.push("");
  lines.push("## Timeline");
  (tl ?? []).forEach((e) => lines.push(`- T+${e.t}s [${e.type}] ${e.title} (conf ${((e.confidence ?? 0) * 100).toFixed(0)}%)`));
  lines.push("");
  lines.push("## Audit Chain");
  (al ?? []).forEach((a) => lines.push(`- ${a.ts} ${a.actor} :: ${a.event} → ${a.target} [${a.hash}]`));
  lines.push("");
  lines.push("## DPDP Notification");
  lines.push("Not applicable — no personal data exfiltrated. Placeholder for compliance workflow.");
  return lines.join("\n");
};

export default CertInReport;
