import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { TID } from "@/constants/testIds";
import { Play, RotateCcw, FlaskConical, Bug, Loader, AlertTriangle, CheckCircle2 } from "lucide-react";
import { useDigitalTwinGraph, useDigitalTwinSimulate } from "@/api/useDigitalTwin";

const SEV = {
  clean:      "#059669",
  suspicious: "#ea580c",
  critical:   "#dc2626",
  warning:    "#d97706",
};

const DigitalTwin = () => {
  const ref    = useRef(null);
  const cyRef  = useRef(null);
  const [step, setStep]     = useState(-1);
  const [log,  setLog]      = useState([]);
  const [animRunning, setAnimRunning] = useState(false);

  // --- Live backend hooks ---
  const { data: twinData, isLoading: graphLoading } = useDigitalTwinGraph();
  const simulate = useDigitalTwinSimulate();

  const graphElements = twinData?.elements ?? [];

  // Build Cytoscape whenever graph source changes
  useEffect(() => {
    if (!ref.current || graphElements.length === 0) return;
    if (cyRef.current) { try { cyRef.current.destroy(); } catch (_) {} }

    const cy = cytoscape({
      container: ref.current,
      elements: graphElements,
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
            "transition-property": "background-color, border-width, border-color",
            "transition-duration": "0.35s",
          },
        },
        {
          selector: "node.active",
          style: {
            "border-color": "#0a58ca",
            "border-width": 5,
          },
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
            "transition-property": "line-color, width, opacity",
            "transition-duration": "0.3s",
          },
        },
        {
          selector: "edge.hot",
          style: {
            "line-color": "#dc2626",
            "target-arrow-color": "#dc2626",
            "width": 4,
            "line-style": "solid",
            "opacity": 1,
          },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 30,
        spacingFactor: 1.25,
        roots: graphElements.some((el) => el.data?.id === "internet" || el.data?.id === "CBSE-WebSvr-01")
          ? [graphElements.find((el) => el.data?.id === "internet" || el.data?.id === "CBSE-WebSvr-01")?.data?.id]
          : undefined,
      },
    });
    cyRef.current = cy;
    return () => { try { cy.destroy(); } catch (_) {} };
  }, [twinData, graphElements]);

  const resetGraph = () => {
    if (!cyRef.current) return;
    cyRef.current.nodes().forEach((n) => n.data("severity", "clean"));
    cyRef.current.nodes().removeClass("active");
    cyRef.current.edges().removeClass("hot");
    cyRef.current.style().update();
    setLog([]);
    setStep(-1);
    simulate.reset?.();
  };

  const animatePath = (path) => {
    setAnimRunning(true);
    setLog([]);
    setStep(0);
    cyRef.current?.nodes().forEach((n) => n.data("severity", "clean"));
    cyRef.current?.nodes().removeClass("active");
    cyRef.current?.edges().removeClass("hot");
    cyRef.current?.style().update();

    path.forEach((hop, i) => {
      setTimeout(() => {
        if (!cyRef.current) return;
        const sev = i === 0 ? "suspicious"
                  : i === path.length - 1 ? "critical"
                  : i > path.length / 2 ? "critical"
                  : "suspicious";

        const node = cyRef.current.$id(hop.node);
        if (node.length) {
          node.data("severity", sev);
          node.addClass("active");
        }
        if (i > 0) {
          const prev = path[i - 1].node;
          cyRef.current.edges().forEach((e) => {
            const src = e.source().id();
            const tgt = e.target().id();
            if ((src === prev && tgt === hop.node) || (src === hop.node && tgt === prev)) {
              e.addClass("hot");
            }
          });
        }
        cyRef.current.style().update();
        setStep(i);
        setLog((l) => [...l, { t: hop.t, node: hop.node, label: hop.label, sev }]);
        if (i === path.length - 1) setAnimRunning(false);
      }, i * 900);
    });
  };

  const handleSimulate = async () => {
    if (animRunning) return;
    try {
      const result = await simulate.mutateAsync({});
      const backendPath = (result.attack_path ?? []).map((hop, idx) => ({
        node:  hop.node_id ?? hop.node ?? hop.id,
        t:     hop.t ?? idx * 3,
        label: hop.label ?? hop.action ?? `Hop ${idx + 1}`,
      }));
      if (backendPath.length > 0) {
        animatePath(backendPath);
      }
    } catch (_) {
      // Backend not running/failed
    }
  };

  if (graphLoading) {
    return (
      <div className="panel p-8 text-center text-slate-500 min-h-[460px] flex items-center justify-center">
        <Loader className="animate-spin mr-2" size={16} /> Loading Digital Twin infrastructure...
      </div>
    );
  }

  if (graphElements.length === 0) {
    return (
      <div className="panel p-8 text-center text-[var(--hci-text-3)] flex flex-col items-center justify-center min-h-[460px]">
        <Bug size={40} className="mb-3 opacity-20 text-[var(--hci-brand)]" />
        <div className="font-semibold text-[14px]">No Digital Twin Topology Available</div>
        <div className="text-[12.5px] mt-1 max-w-sm">
          The sandboxed simulation topology is not loaded. Please ensure the backend is running.
        </div>
      </div>
    );
  }

  const totalHops = simulate.data?.attack_path?.length ?? 0;
  const reached   = simulate.data?.reached_target;

  return (
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-8 panel flex flex-col">
        <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3">
          <FlaskConical size={16} className="text-[var(--hci-brand)]" />
          <div className="font-head font-bold text-[14.5px]">Cyber Resilience Digital Twin</div>
          <span className="chip chip-warning font-mono">SIMULATION · RED-TEAM ONLY</span>
          {reached === true  && <span className="chip chip-critical">TARGET REACHED</span>}
          {reached === false && <span className="chip chip-clean">CONTAINED</span>}
          <div className="ml-auto flex items-center gap-2">
            <button data-testid={TID.twinReset} onClick={resetGraph} className="btn btn-outline btn-sm" disabled={animRunning}>
              <RotateCcw size={13} /> Reset
            </button>
            <button
              data-testid={TID.twinSimulate}
              onClick={handleSimulate}
              className="btn btn-danger btn-sm"
              disabled={animRunning || simulate.isPending}
            >
              {(animRunning || simulate.isPending) ? <Loader size={13} className="animate-spin" /> : <Play size={13} />}
              {animRunning ? "Simulating…" : simulate.isPending ? "Loading…" : "Simulate Attack"}
            </button>
          </div>
        </div>
        <div ref={ref} className="cy-container" style={{ minHeight: 460 }} />
        <div className="px-5 py-2.5 border-t border-[var(--hci-border)] bg-[#fbfcfd] text-[11.5px] text-[var(--hci-text-3)]">
          Live infrastructure graph · {graphElements.length} elements loaded.
        </div>
      </div>

      <div className="col-span-4 panel flex flex-col">
        <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2">
          <Bug size={15} className="text-[var(--hci-critical)]" />
          <div className="font-head font-bold text-[13.5px]">Detection Timeline</div>
          <span className="ml-auto chip chip-neutral">{log.length} / {totalHops} hops</span>
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
