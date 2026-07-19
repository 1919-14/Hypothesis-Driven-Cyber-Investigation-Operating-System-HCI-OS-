import React, { useState, useEffect, useMemo } from "react";
import { TID } from "@/constants/testIds";
import { Play, Pause, RotateCcw, Clock, ChevronRight } from "lucide-react";
import { useTimeline } from "@/api/useTimeline";
import { useApp } from "@/context/AppContext";

const DEFAULT_T_MAX = 43;

const severityColor = (s) => ({
  critical: "#dc2626",
  suspicious: "#ea580c",
  warning: "#d97706",
  clean: "#059669",
  info: "#0a58ca",
}[s] || "#64748b");

const chipCls = (s) => ({
  critical: "chip chip-critical",
  suspicious: "chip chip-suspicious",
  warning: "chip chip-warning",
  clean: "chip chip-clean",
  info: "chip chip-info",
}[s] || "chip chip-neutral");

const Timeline = ({ selectedIdx, onSelect }) => {
  const { searchQuery } = useApp();
  const { data } = useTimeline();

  const TIMELINE_EVENTS = useMemo(() => {
    const rawEvents = data?.timeline_events ?? [];
    if (!searchQuery) return rawEvents;
    const q = searchQuery.toLowerCase();
    return rawEvents.filter((e) =>
      e.title?.toLowerCase().includes(q) ||
      e.description?.toLowerCase().includes(q) ||
      e.type?.toLowerCase().includes(q) ||
      e.asset_id?.toLowerCase().includes(q) ||
      e.severity?.toLowerCase().includes(q)
    );
  }, [data, searchQuery]);

  // Compute T_MAX from actual events so the ruler scales correctly for real data
  const T_MAX = TIMELINE_EVENTS.length > 0
    ? Math.max(DEFAULT_T_MAX, TIMELINE_EVENTS[TIMELINE_EVENTS.length - 1].t)
    : DEFAULT_T_MAX;

  const [tSec, setTSec] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    const iv = setInterval(() => {
      setTSec((t) => {
        if (t >= T_MAX) { setPlaying(false); return T_MAX; }
        return +(t + 0.5).toFixed(2);
      });
    }, 120);
    return () => clearInterval(iv);
  }, [playing]);

  const activeEvents = useMemo(() => TIMELINE_EVENTS.filter((e) => e.t <= tSec + 0.4), [tSec]);
  const currentEvent = activeEvents[activeEvents.length - 1];

  const pct = (tSec / T_MAX) * 100;

  if (TIMELINE_EVENTS.length === 0) {
    return (
      <div className="panel p-8 text-center text-[var(--hci-text-3)] flex flex-col items-center justify-center min-h-[140px]">
        <Clock size={32} className="mb-2 opacity-20 text-[var(--hci-brand)]" />
        <div className="font-semibold text-[13px]">Explainable Timeline Standby</div>
        <div className="text-[12px] mt-0.5 max-w-sm">
          No timeline events generated. Ingest a telemetry event to populate the explainable cyber investigation chain.
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3">
        <Clock size={16} className="text-[var(--hci-brand)]" />
        <div className="font-head font-bold text-[14.5px]">Explainable Timeline</div>
        <span className="chip chip-info">T-0 → T+{T_MAX}s</span>
        <span className="ml-auto label-caps">Scrubbable · Clickable</span>
      </div>

      <div className="px-6 pt-6 pb-5">
        {/* Ruler */}
        <div className="flex justify-between text-[10.5px] font-mono text-[var(--hci-text-3)] mb-2 px-1">
          {[0, 10, 20, 30, 40, T_MAX].map((tick) => (
            <span key={tick}>T+{tick}s</span>
          ))}
        </div>

        {/* Track */}
        <div className="relative py-5">
          <div className="timeline-track" />
          {/* Ticks */}
          {[0, 10, 20, 30, 40].map((tick) => (
            <span key={tick} className="timeline-tick" style={{ left: `${(tick / T_MAX) * 100}%` }} />
          ))}
          {/* Event dots */}
          {TIMELINE_EVENTS.map((ev, idx) => (
            <button
              key={idx}
              data-testid={TID.timelineEvent(idx)}
              onClick={() => { setTSec(ev.t); onSelect(idx); }}
              className="timeline-event-dot"
              style={{
                left: `${(ev.t / T_MAX) * 100}%`,
                background: severityColor(ev.severity),
                boxShadow: selectedIdx === idx ? `0 0 0 4px rgba(10,88,202,0.25)` : undefined,
              }}
              title={`T+${ev.t}s · ${ev.title}`}
            />
          ))}
          {/* Thumb */}
          <div className="timeline-thumb" style={{ left: `${pct}%` }} />
          {/* Invisible range for accessibility */}
          <input
            type="range"
            min="0"
            max={T_MAX}
            step="0.5"
            value={tSec}
            onChange={(e) => setTSec(parseFloat(e.target.value))}
            data-testid={TID.timelineSlider}
            className="absolute inset-x-0 top-0 h-full opacity-0 cursor-pointer"
          />
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 mt-1">
          <button data-testid={TID.timelinePlay} onClick={() => setPlaying(!playing)} className="btn btn-primary btn-sm">
            {playing ? <Pause size={13} /> : <Play size={13} />} {playing ? "Pause" : "Play"}
          </button>
          <button data-testid={TID.timelineReset} onClick={() => { setTSec(0); setPlaying(false); }} className="btn btn-outline btn-sm">
            <RotateCcw size={13} /> Reset
          </button>
          <div className="ml-3 font-mono text-[13px]">
            <span className="text-[var(--hci-text-3)]">Cursor</span>{" "}
            <span className="text-[var(--hci-brand)] font-semibold">T+{tSec.toFixed(1)}s</span>
          </div>
          <div className="ml-auto text-[12px] text-[var(--hci-text-3)]">
            {activeEvents.length} / {TIMELINE_EVENTS.length} events revealed
          </div>
        </div>
      </div>

      {/* Current event detail */}
      {currentEvent && (
        <div className="px-5 py-4 border-t border-[var(--hci-border)] bg-[#fbfcfd]">
          <div className="flex items-start gap-3">
            <div
              className="w-2 h-2 mt-2 rounded-full shrink-0"
              style={{ background: severityColor(currentEvent.severity) }}
            />
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-[11px] text-[var(--hci-text-3)]">T+{currentEvent.t}s</span>
                <span className={chipCls(currentEvent.severity)}>{currentEvent.type}</span>
                <span className="font-semibold text-[13.5px]">{currentEvent.title}</span>
                <span className="chip chip-neutral">conf {(currentEvent.confidence * 100).toFixed(0)}%</span>
                <span className="chip chip-neutral font-mono">{currentEvent.evidence_ref}</span>
              </div>
              <div className="text-[12.5px] text-[var(--hci-text-2)] mt-1.5 leading-relaxed">
                {currentEvent.description}
              </div>
              <div className="mt-2 text-[11.5px] font-mono text-[var(--hci-text-3)] flex items-center gap-1">
                asset: <span className="text-[var(--hci-text-2)]">{currentEvent.asset}</span>
                <ChevronRight size={12} className="mx-1" />
                <span className="text-[var(--hci-brand)] cursor-pointer hover:underline">open evidence chain →</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Timeline;
