import React, { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { TID } from "@/constants/testIds";
import { useGnn } from "@/api/useGnn";
import { Share2, ZoomIn, ZoomOut, Maximize2, Loader } from "lucide-react";

// Neo4j Browser palette keyed by node `type`
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

const LEGEND = [
  { label: "Campaign",    color: "#f472b6" },
  { label: "Technique",   color: "#60a5fa" },
  { label: "Software",    color: "#2dd4bf" },
  { label: "Mitigation",  color: "#86efac" },
  { label: "Computer",    color: "#fb923c" },
  { label: "IP",          color: "#fbbf24" },
  { label: "ThreatGroup", color: "#c084fc" },
  { label: "Tactic",      color: "#818cf8" },
];

const AttackGraph = ({ highlightedNodes = [], compact = false }) => {
  const ref   = useRef(null);
  const cyRef = useRef(null);
  const { data, isPlaceholderData, isLoading } = useGnn();
  const graph = data?.graph ?? { nodes: [], edges: [] };
  const perf  = data?.perf  ?? {};
  const [counts, setCounts]     = useState({ n: 0, e: 0 });
  const [hovered, setHovered]   = useState(null);

  // Background elements stored in refs so they are loaded dynamically on zoom-out
  const remainingNodesRef = useRef([]);
  const remainingEdgesRef = useRef([]);
  const activeGraphIdsRef = useRef(new Set());
  const lastZoomStageRef = useRef(0);

  useEffect(() => {
    if (!ref.current) return;
    if (cyRef.current) { try { cyRef.current.destroy(); } catch (_) {} }
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (!nodes.length && !edges.length) return;

    setCounts({ n: nodes.length, e: edges.length });
    lastZoomStageRef.current = 0;
    activeGraphIdsRef.current = new Set();

    // --- STEP 1: Prioritize and Partition elements ---
    const attackNodeIds = new Set();
    edges.forEach(e => {
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
      // We only add edges where BOTH endpoints are in the initial coreNodes
      if (activeGraphIdsRef.current.has(d.source) && activeGraphIdsRef.current.has(d.target)) {
        coreEdges.push(e);
      } else {
        bgEdges.push(e);
      }
    });

    // Save remaining background elements to load when the user zooms out
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
            "border-color": "rgba(255,255,255,0.18)",
            "border-width": 1.5,
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
            "overlay-opacity": 0,
            "transition-property": "border-width,border-color,width,height",
            "transition-duration": "0.3s",
          },
        },
        {
          selector: "node:selected",
          style: { "border-color": "#fff", "border-width": 3, "width": 26, "height": 26 },
        },
        {
          selector: "node.highlight",
          style: { "border-color": "#fbbf24", "border-width": 3, "width": 24, "height": 24 },
        },
        {
          selector: "node[severity = 'critical']",
          style: { "border-color": "#ef4444", "border-width": 3 },
        },
        {
          selector: "edge",
          style: {
            "curve-style": "haystack",
            "haystack-radius": 0,
            "line-color": "rgba(148,163,184,0.18)",
            "width": 1,
            "overlay-opacity": 0,
          },
        },
        {
          selector: "edge[kind = 'attack']",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#ef4444",
            "target-arrow-color": "#ef4444",
            "width": 2,
          },
        },
        {
          selector: "edge[kind = 'predicted']",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#3b82f6",
            "target-arrow-color": "#3b82f6",
            "width": 1.5,
            "line-style": "dashed",
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
          // Fit nicely on initial load (zoomed into core subgraph)
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

      // Optimize labels based on level of detail zoom
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
          
          // Re-layout newly added nodes smoothly without disturbing existing positions
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
      setHovered({ label: d.label, type: d.type || d.kind, id: d.id, severity: d.severity });
    });
    cy.on("mouseout", "node", () => setHovered(null));

    let tick = 0;
    const pulse = setInterval(() => {
      if (!cyRef.current) { clearInterval(pulse); return; }
      tick++;
      cyRef.current.nodes("[severity = 'critical']").forEach((n) => {
        n.style("border-width", tick % 2 === 0 ? 3 : 5);
      });
    }, 700);

    cyRef.current = cy;
    return () => { clearInterval(pulse); try { cy.destroy(); } catch (_) {} };
  }, [graph]);

  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().removeClass("highlight");
    highlightedNodes.forEach((id) => cyRef.current.$id(id).addClass("highlight"));
  }, [highlightedNodes]);

  const zoomIn  = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.3);
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.3);
  const fit     = () => cyRef.current?.fit(undefined, 30);

  return (
    <div className="panel h-full flex flex-col" style={{ background: "#0d1117", border: "1px solid rgba(255,255,255,0.07)" }}>
      {/* Header */}
      <div className="px-5 py-3.5 border-b flex items-center gap-3" style={{ borderColor: "rgba(255,255,255,0.07)" }}>
        <Share2 size={16} className="text-blue-400" />
        <div className="font-head font-bold text-[14.5px] text-slate-100">Predictive Attack Topology</div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full" style={{ background: "rgba(59,130,246,0.15)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.3)" }}>
          Neo4j KG · GNN+GAT
        </span>
        {isLoading && <Loader size={12} className="animate-spin text-slate-400" />}
        {isPlaceholderData && <span className="chip chip-warning text-[10px]">mock</span>}
        <div className="ml-auto flex items-center gap-1">
          <button onClick={zoomIn}  className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><ZoomIn  size={13}/></button>
          <button onClick={zoomOut} className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><ZoomOut size={13}/></button>
          <button onClick={fit}     className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"><Maximize2 size={13}/></button>
        </div>
      </div>

      {/* Canvas */}
      <div className="relative flex-1">
        <div
          ref={ref}
          data-testid={TID.topologyGraph}
          style={{ width: "100%", height: "100%", minHeight: compact ? 360 : 500, background: "#0d1117" }}
        />

        {/* Hover tooltip */}
        {hovered && (
          <div className="absolute top-3 left-3 pointer-events-none rounded-lg px-3 py-2 text-[11.5px] shadow-2xl z-10"
            style={{ background: "#1e293b", border: "1px solid rgba(255,255,255,0.1)" }}>
            <div className="font-bold text-white mb-0.5">{hovered.label}</div>
            <div className="font-mono text-slate-400 text-[10.5px]">{hovered.type} · {hovered.id}</div>
            {hovered.severity && hovered.severity !== "clean" && (
              <div className="mt-1 font-semibold text-[10.5px]"
                style={{ color: hovered.severity === "critical" ? "#ef4444" : "#f59e0b" }}>
                ⚠ {hovered.severity.toUpperCase()}
              </div>
            )}
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-3 left-3 flex flex-wrap gap-x-3 gap-y-1 pointer-events-none">
          {LEGEND.map(l => (
            <span key={l.label} className="flex items-center gap-1 text-[9.5px] text-slate-500">
              <span className="w-2 h-2 rounded-full shrink-0" style={{ background: l.color }} />
              {l.label}
            </span>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="px-5 py-2 flex items-center gap-4 text-[10.5px] text-slate-600 font-mono"
        style={{ borderTop: "1px solid rgba(255,255,255,0.05)", background: "#080c14" }}>
        <span>{counts.n} nodes · {counts.e} edges</span>
        {perf.source && <span>source: {perf.source}</span>}
        <span className="ml-auto">Scroll = zoom out to load all nodes · Drag = pan</span>
      </div>
    </div>
  );
};

export default AttackGraph;
