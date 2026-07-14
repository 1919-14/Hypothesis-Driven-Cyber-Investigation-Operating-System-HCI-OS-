import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { GRAPH, TWIN_PATH } from "@/mock/data";
import { TID } from "@/constants/testIds";
import { Play, RotateCcw, FlaskConical, Bug } from "lucide-react";

const SEV = { clean: "#059669", suspicious: "#ea580c", critical: "#dc2626", warning: "#d97706" };

const DigitalTwin = () => {
  const ref = useRef(null);
  const cyRef = useRef(null);
  const [running, setRunning] = useState(false);
  const [step, setStep] = useState(-1);
  const [log, setLog] = useState([]);

  useEffect(() => {
    if (!ref.current) return;
    const nodes = GRAPH.nodes.map((n) => ({ data: { ...n.data, severity: "clean" } }));
    const cy = cytoscape({
      container: ref.current,
      elements: [...nodes, ...GRAPH.edges.filter((e) => e.data.kind !== "blocked_extra")],
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n) => SEV[n.data("severity")] || "#94a3b8",
            "border-color": "#ffffff",
            "border-width": 3,
            "label": "data(label)",
            "color": "#0f172a",
            "font-family": "JetBrains Mono, monospace",
            "font-size": 11,
            "font-weight": 600,
            "text-margin-y": 14,
            "text-valign": "bottom",
            "width": 44,
            "height": 44,
          },
        },
        {
          selector: "node.active",
          style: { "border-color": "#0a58ca", "border-width": 5 },
        },
        {
          selector: "edge",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#cbd5e1",
            "target-arrow-color": "#cbd5e1",
            "width": 2,
            "opacity": 0.6,
          },
        },
        {
          selector: "edge.hot",
          style: { "line-color": "#dc2626", "target-arrow-color": "#dc2626", "width": 4, "line-style": "solid", "opacity": 1 },
        },
      ],
      layout: { name: "breadthfirst", directed: true, padding: 30, spacingFactor: 1.25, roots: ["internet"] },
    });
    cyRef.current = cy;
    return () => cy.destroy();
  }, []);

  const simulate = () => {
    if (!cyRef.current) return;
    // reset
    cyRef.current.nodes().forEach((n) => n.data("severity", "clean"));
    cyRef.current.nodes().removeClass("active");
    cyRef.current.edges().removeClass("hot");
    cyRef.current.style().update();
    setLog([]);
    setStep(0);
    setRunning(true);

    TWIN_PATH.forEach((hop, i) => {
      setTimeout(() => {
        const node = cyRef.current.$id(hop.node);
        const severity = i === 0 ? "suspicious" : i === TWIN_PATH.length - 1 ? "critical" : i > TWIN_PATH.length / 2 ? "critical" : "suspicious";
        node.data("severity", severity);
        node.addClass("active");
        if (i > 0) {
          const prev = TWIN_PATH[i - 1].node;
          cyRef.current.edges().forEach((e) => {
            if ((e.source().id() === prev && e.target().id() === hop.node) || (e.source().id() === hop.node && e.target().id() === prev)) {
              e.addClass("hot");
            }
          });
        }
        cyRef.current.style().update();
        setStep(i);
        setLog((l) => [...l, { t: hop.t, node: hop.node, label: hop.label, sev: severity }]);
        if (i === TWIN_PATH.length - 1) setRunning(false);
      }, i * 900);
    });
  };

  const reset = () => {
    if (!cyRef.current) return;
    cyRef.current.nodes().forEach((n) => n.data("severity", "clean"));
    cyRef.current.nodes().removeClass("active");
    cyRef.current.edges().removeClass("hot");
    cyRef.current.style().update();
    setLog([]);
    setStep(-1);
  };

  return (
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-8 panel flex flex-col">
        <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3">
          <FlaskConical size={16} className="text-[var(--hci-brand)]" />
          <div className="font-head font-bold text-[14.5px]">Cyber Resilience Digital Twin</div>
          <span className="chip chip-warning font-mono">SIMULATION · RED-TEAM ONLY</span>
          <div className="ml-auto flex items-center gap-2">
            <button data-testid={TID.twinReset} onClick={reset} className="btn btn-outline btn-sm" disabled={running}>
              <RotateCcw size={13} /> Reset
            </button>
            <button data-testid={TID.twinSimulate} onClick={simulate} className="btn btn-danger btn-sm" disabled={running}>
              <Play size={13} /> {running ? "Simulating…" : "Simulate Attack"}
            </button>
          </div>
        </div>
        <div ref={ref} className="cy-container" style={{ minHeight: 460 }} />
        <div className="px-5 py-2.5 border-t border-[var(--hci-border)] bg-[#fbfcfd] text-[11.5px] text-[var(--hci-text-3)]">
          Environment is a sandboxed replica. No production side effects.
        </div>
      </div>

      <div className="col-span-4 panel flex flex-col">
        <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2">
          <Bug size={15} className="text-[var(--hci-critical)]" />
          <div className="font-head font-bold text-[13.5px]">Detection Timeline</div>
          <span className="ml-auto chip chip-neutral">{log.length} / {TWIN_PATH.length} hops</span>
        </div>
        <div className="flex-1 overflow-auto p-4 space-y-3">
          {log.length === 0 && (
            <div className="text-[12px] text-[var(--hci-text-3)] py-8 text-center">
              Press <span className="kbd">Simulate Attack</span> to trace the kill chain against the twin.
            </div>
          )}
          {log.map((l, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="w-10 shrink-0 font-mono text-[11px] text-[var(--hci-brand)] font-semibold pt-0.5">T+{l.t}s</div>
              <div
                className="w-2.5 h-2.5 rounded-full mt-1.5 shrink-0"
                style={{ background: SEV[l.sev] || "#94a3b8" }}
              />
              <div className="flex-1">
                <div className="font-mono text-[12px] font-semibold">{l.node}</div>
                <div className="text-[12px] text-[var(--hci-text-2)]">{l.label}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DigitalTwin;
