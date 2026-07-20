import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { TID } from "@/constants/testIds";
import { Play, RotateCcw, FlaskConical, Bug, Loader, Settings, GitBranch, Shield, ZoomIn, ZoomOut, Maximize2 } from "lucide-react";
import { useDigitalTwinGraph, useDigitalTwinSimulate } from "@/api/useDigitalTwin";

const TYPE_COLOR = {
  Campaign:    "#f472b6",
  Technique:   "#60a5fa",
  Software:    "#2dd4bf",
  Mitigation:  "#86efac",
  Computer:    "#fb923c",
  IP:          "#fbbf24",
  User:        "#a3e635",
  ThreatGroup: "#c084fc",
  Tactic:      "#818cf8",
  Asset:       "#fb923c",
  OTSensor:    "#f97316",
  Entity:      "#94a3b8",
};

const SEV_BORDER = {
  critical:   "#ef4444",
  suspicious: "#f59e0b",
  warning:    "#f59e0b",
  clean:      "rgba(255,255,255,0.18)",
};

const DigitalTwin = () => {
  const ref    = useRef(null);
  const cyRef  = useRef(null);
  const [step, setStep]     = useState(-1);
  const [log,  setLog]      = useState([]);
  const [animRunning, setAnimRunning] = useState(false);

  // --- User-controlled simulation parameters ---
  const [startNode, setStartNode]       = useState("CBSE-WebSvr-01");
  const [targetNode, setTargetNode]     = useState("CrownJewel-ExamDB");
  const [feedPipeline, setFeedPipeline] = useState(false);
  const [gnnGuided, setGnnGuided]       = useState(false);

  // --- Live backend hooks ---
  const { data: twinData, isLoading: graphLoading } = useDigitalTwinGraph();
  const simulate = useDigitalTwinSimulate();

  const graphElements = twinData?.elements ?? [];

  // Filter available nodes dynamically from graph elements
  const availableNodes = graphElements
    .filter(el => el.group === "nodes")
    .map(el => ({ id: el.data.id, label: el.data.label || el.data.id }));

  const [hovered, setHovered] = useState(null);

  // Background elements stored in refs so they are loaded dynamically on zoom-out
  const remainingNodesRef = useRef([]);
  const remainingEdgesRef = useRef([]);
  const activeGraphIdsRef = useRef(new Set());
  const lastZoomStageRef = useRef(0);

  // Build Cytoscape whenever graph source changes
  useEffect(() => {
    if (!ref.current || graphElements.length === 0) return;
    if (cyRef.current) { try { cyRef.current.destroy(); } catch (_) {} }

    lastZoomStageRef.current = 0;
    activeGraphIdsRef.current = new Set();

    // --- STEP 1: Prioritize and Partition elements ---
    const attackNodeIds = new Set();
    graphElements.filter(el => el.group === "edges").forEach(e => {
      const d = e.data || e;
      if (d.kind === "attack" || d.kind === "predicted") {
        attackNodeIds.add(d.source);
        attackNodeIds.add(d.target);
      }
    });

    const nodePriority = (n) => {
      const d = n.data || n;
      let p = 10;
      if (d.severity === "critical") p = 1;
      else if (d.severity === "suspicious") p = 2;
      else if (d.severity === "warning") p = 3;
      else if (["ThreatGroup", "Campaign"].includes(d.type || d.kind)) p = 4;
      else if (["Computer", "IP", "Asset", "OTSensor"].includes(d.type || d.kind)) p = 5;
      else if (d.type === "User") p = 6;
      
      if (attackNodeIds.has(d.id)) p -= 10; // Boost attack path nodes
      return p;
    };

    const nodes = graphElements.filter(el => el.group === "nodes");
    const edges = graphElements.filter(el => el.group === "edges");

    const sortedNodes = [...nodes].sort((a, b) => nodePriority(a) - nodePriority(b));

    const initialNodesCount = 15;
    const coreNodes = [];
    const bgNodes = [];

    sortedNodes.forEach((n, idx) => {
      if (idx < initialNodesCount) {
        coreNodes.push(n);
        activeGraphIdsRef.current.add(n.data?.id || n.id);
      } else {
        bgNodes.push(n);
      }
    });

    const coreEdges = [];
    const bgEdges = [];

    edges.forEach(e => {
      const d = e.data || e;
      if (activeGraphIdsRef.current.has(d.source) && activeGraphIdsRef.current.has(d.target)) {
        coreEdges.push(e);
      } else {
        bgEdges.push(e);
      }
    });

    remainingNodesRef.current = bgNodes;
    remainingEdgesRef.current = bgEdges;

    // --- STEP 2: Initialize Cytoscape with Core Subgraph ONLY ---
    const cy = cytoscape({
      container: ref.current,
      elements: [...coreNodes, ...coreEdges],
      wheelSensitivity: 0.35,
      hideEdgesOnViewport: true,
      textureOnViewport: false,
      pixelRatio: 1,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n) => TYPE_COLOR[n.data("type")] || "#64748b",
            "border-color": (n) => SEV_BORDER[n.data("severity")] || "rgba(255,255,255,0.18)",
            "border-width": (n) => n.data("severity") === "critical" ? 3 : 1.5,
            "label": "data(label)",
            "color": "#cbd5e1",
            "font-family": "JetBrains Mono, monospace",
            "font-size": 8,
            "text-margin-y": 11,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-outline-color": "#0d1117",
            "text-outline-width": 2,
            "width":  (n) => ["ThreatGroup","Campaign"].includes(n.data("type")) ? 22 : 14,
            "height": (n) => ["ThreatGroup","Campaign"].includes(n.data("type")) ? 22 : 14,
            "transition-property": "background-color, border-width, border-color",
            "transition-duration": "0.35s",
            "overlay-opacity": 0,
          },
        },
        {
          selector: "node.active",
          style: { "border-color": "#ffffff", "border-width": 4, "width": 22, "height": 22 },
        },
        {
          selector: "edge",
          style: {
            "curve-style": "haystack",
            "haystack-radius": 0,
            "line-color": "rgba(148,163,184,0.18)",
            "width": 1,
            "opacity": 0.8,
            "overlay-opacity": 0,
            "transition-property": "line-color, width, opacity",
            "transition-duration": "0.3s",
          },
        },
        {
          selector: "edge.hot",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#ef4444",
            "line-color": "#ef4444",
            "width": 3,
            "opacity": 1,
          },
        },
      ],
      layout: {
        name: "cose",
        animate: true,
        animationDuration: 1000,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 65,
        edgeElasticity: () => 0.12,
        gravity: 0.3,
        numIter: 800,
        initialTemp: 220,
        coolingFactor: 0.97,
        minTemp: 1.0,
        padding: 50,
        randomize: true,
        componentSpacing: 50,
        fit: true,
        stop: () => {
          setTimeout(() => {
            if (!cyRef.current) return;
            cyRef.current.fit(undefined, 50);
            const z = cyRef.current.zoom();
            if (z > 1.2) cyRef.current.zoom({ level: 1.2, renderedPosition: cyRef.current.center() });
          }, 80);
        },
      },
    });

    // --- STEP 3: Listen for Zoom/Scroll actions to dynamically load background elements ---
    cy.on("zoom", () => {
      const currentZoom = cy.zoom();
      cy.nodes().style("label", currentZoom > 0.65 ? "data(label)" : "");

      // Determine zoom stage for progressive loading
      let stage = 0;
      if (currentZoom <= 0.4) stage = 3;
      else if (currentZoom <= 0.75) stage = 2;
      else if (currentZoom <= 1.0) stage = 1;

      if (stage > lastZoomStageRef.current && remainingNodesRef.current.length > 0) {
        lastZoomStageRef.current = stage;
        
        let nodesToAdd = 0;
        if (stage === 3) nodesToAdd = remainingNodesRef.current.length; // all remaining
        else if (stage === 2) nodesToAdd = Math.min(200, remainingNodesRef.current.length);
        else if (stage === 1) nodesToAdd = Math.min(50, remainingNodesRef.current.length);

        if (nodesToAdd > 0) {
          const nextNodes = remainingNodesRef.current.splice(0, nodesToAdd);
          nextNodes.forEach(n => activeGraphIdsRef.current.add(n.data?.id || n.id));
          
          const nextEdges = [];
          const pendingEdges = [];
          remainingEdgesRef.current.forEach(e => {
            const d = e.data || e;
            if (activeGraphIdsRef.current.has(d.source) && activeGraphIdsRef.current.has(d.target)) {
              nextEdges.push(e);
            } else {
              pendingEdges.push(e);
            }
          });
          remainingEdgesRef.current = pendingEdges;

          cy.add([...nextNodes, ...nextEdges]);
          
          const bgLayout = cy.layout({
            name: "cose",
            animate: true,
            fit: false,
            randomize: false,
            maxSimulationTime: 800,
            nodeRepulsion: () => 12000,
            idealEdgeLength: () => 80,
            gravity: 0.25,
          });
          bgLayout.run();
        }
      }
    });

    cy.on("mouseover", "node", (e) => {
      const d = e.target.data();
      setHovered({ label: d.label, type: d.type || d.kind, id: d.id });
    });
    cy.on("mouseout", "node", () => setHovered(null));

    cyRef.current = cy;
    return () => { try { cy.destroy(); } catch (_) {} };
  }, [twinData, graphElements]);

  const zoomIn  = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const fit     = () => cyRef.current?.fit(undefined, 30);

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
      const result = await simulate.mutateAsync({
        startNode,
        targetNode,
        feedPipeline,
        gnnGuided,
      });
      const backendPath = (result.attack_path ?? []).map((hop, idx) => ({
        node:  hop.node_id ?? hop.node ?? hop.id ?? hop,
        t:     hop.t ?? idx * 15,
        label: hop.label ?? hop.description ?? (idx === 0 ? "Entry point compromise" : `Lateral movement hop ${idx}`),
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
      {/* Cytoscape Panel */}
      <div className="col-span-8 panel flex flex-col" style={{ background: "#0d1117", border: "1px solid rgba(255,255,255,0.07)" }}>
        {/* Header */}
        <div className="px-5 py-3.5 border-b flex items-center gap-3" style={{ borderColor: "rgba(255,255,255,0.07)" }}>
          <FlaskConical size={16} className="text-blue-400" />
          <div className="font-head font-bold text-[14.5px] text-slate-100">Cyber Resilience Digital Twin</div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full" style={{ background: "rgba(251,191,36,0.15)", color: "#fbbf24", border: "1px solid rgba(251,191,36,0.3)" }}>SIMULATION · RED-TEAM ONLY</span>
          {reached === true  && <span className="chip chip-critical">TARGET REACHED</span>}
          {reached === false && <span className="chip chip-clean">CONTAINED</span>}
          <div className="ml-auto flex items-center gap-1">
            <button onClick={zoomIn}  className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><ZoomIn  size={13}/></button>
            <button onClick={zoomOut} className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><ZoomOut size={13}/></button>
            <button onClick={fit}     className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><Maximize2 size={13}/></button>
            <button data-testid={TID.twinReset} onClick={resetGraph} className="btn btn-outline btn-sm ml-1" disabled={animRunning} style={{ borderColor: "rgba(255,255,255,0.15)", color: "#94a3b8" }}>
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

        {/* User Parameter Controls Row */}
        <div className="px-5 py-3 border-b border-[var(--hci-border)] bg-slate-50/50 flex flex-wrap gap-4 items-center text-[12px]">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-500 flex items-center gap-1"><Settings size={12} /> Parameters:</span>
          </div>

          {/* Start node */}
          <div className="flex items-center gap-1.5">
            <label className="text-slate-600 font-medium">Start Node:</label>
            <select
              className="px-2 py-1 rounded border border-slate-200 bg-white text-[12px] focus:outline-none focus:ring-1 focus:ring-blue-500"
              value={startNode}
              onChange={(e) => setStartNode(e.target.value)}
              disabled={animRunning}
            >
              {availableNodes.map(n => (
                <option key={n.id} value={n.id}>{n.label}</option>
              ))}
            </select>
          </div>

          {/* Target node */}
          <div className="flex items-center gap-1.5">
            <label className="text-slate-600 font-medium">Target Node:</label>
            <select
              className="px-2 py-1 rounded border border-slate-200 bg-white text-[12px] focus:outline-none focus:ring-1 focus:ring-blue-500"
              value={targetNode}
              onChange={(e) => setTargetNode(e.target.value)}
              disabled={animRunning}
            >
              {availableNodes.map(n => (
                <option key={n.id} value={n.id}>{n.label}</option>
              ))}
            </select>
          </div>

          {/* GNN Guided Mode Switch */}
          <div className="flex items-center gap-1.5">
            <input
              type="checkbox"
              id="gnnGuided"
              className="rounded text-blue-600 focus:ring-blue-500"
              checked={gnnGuided}
              onChange={(e) => setGnnGuided(e.target.checked)}
              disabled={animRunning}
            />
            <label htmlFor="gnnGuided" className="text-slate-700 font-semibold flex items-center gap-1 cursor-pointer select-none">
              <GitBranch size={11} className="text-purple-600" /> GNN-Guided Path
            </label>
          </div>

          {/* Ingest into loop Switch */}
          <div className="flex items-center gap-1.5">
            <input
              type="checkbox"
              id="feedPipeline"
              className="rounded text-blue-600 focus:ring-blue-500"
              checked={feedPipeline}
              onChange={(e) => setFeedPipeline(e.target.checked)}
              disabled={animRunning}
            />
            <label htmlFor="feedPipeline" className="text-slate-700 font-semibold flex items-center gap-1 cursor-pointer select-none">
              <Shield size={11} className="text-emerald-600" /> Feed A1 Ingest Loop
            </label>
          </div>
        </div>

        {/* Graph Display Area */}
        <div className="relative flex-1">
          <div ref={ref} className="cy-container" style={{ minHeight: 460, background: "#0d1117" }} />
          {hovered && (
            <div className="absolute top-3 left-3 pointer-events-none rounded-lg px-3 py-2 text-[11.5px] shadow-2xl z-10"
              style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.1)" }}>
              <div className="font-bold text-white mb-0.5">{hovered.label}</div>
              <div className="font-mono text-slate-400 text-[10.5px]">{hovered.type} · {hovered.id}</div>
            </div>
          )}
        </div>
        <div className="px-5 py-2 text-[10.5px] font-mono text-slate-600 flex items-center"
          style={{ borderTop: "1px solid rgba(255,255,255,0.05)", background: "#080c14" }}>
          <span>Neo4j KG · {graphElements.length} elements loaded</span>
          <span className="ml-auto">Scroll = zoom out to load all nodes · Drag = pan</span>
        </div>
      </div>

      {/* Right Column: Timeline */}
      <div className="col-span-4 panel flex flex-col">
        <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2">
          <Bug size={15} className="text-[var(--hci-critical)]" />
          <div className="font-head font-bold text-[13.5px]">Detection Timeline</div>
          <span className="ml-auto chip chip-neutral">{log.length} / {totalHops} hops</span>
        </div>
        <div className="flex-1 overflow-auto p-4 space-y-3">
          {log.length === 0 && (
            <div className="text-[12px] text-[var(--hci-text-3)] py-8 text-center">
              Configure parameters above and press <span className="kbd">Simulate Attack</span> to trace the red-team path.
            </div>
          )}
          {log.map((l, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="w-10 shrink-0 font-mono text-[11px] text-[var(--hci-brand)] font-semibold pt-0.5">T+{l.t}s</div>
              <div
                className="w-2.5 h-2.5 rounded-full mt-1.5 shrink-0"
                style={{ background: TYPE_COLOR[l.node] || "#fb923c" }}
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
