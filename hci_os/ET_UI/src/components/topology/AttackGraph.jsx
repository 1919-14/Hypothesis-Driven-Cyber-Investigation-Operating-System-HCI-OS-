import React, { useEffect, useRef } from "react";
import cytoscape from "cytoscape";
import { TID } from "@/constants/testIds";
import { useGnn } from "@/api/useGnn";
import { Share2, Layers, Info, Loader } from "lucide-react";

const SEV_COLOR = {
  clean:      "#059669",
  suspicious: "#ea580c",
  critical:   "#dc2626",
  warning:    "#d97706",
};

const KIND_SHAPE = {
  cloud:    "round-rectangle",
  firewall: "diamond",
  server:   "round-rectangle",
  service:  "ellipse",
  db:       "barrel",
  crown:    "star",
};

const AttackGraph = ({ highlightedNodes = [], compact = false }) => {
  const ref    = useRef(null);
  const cyRef  = useRef(null);
  const { data, isPlaceholderData, isLoading } = useGnn();
  const graph  = data?.graph ?? { nodes: [], edges: [] };
  const perf   = data?.perf  ?? {};

  // Rebuild Cytoscape whenever the graph data changes (live updates from backend)
  useEffect(() => {
    if (!ref.current) return;
    // Destroy any stale instance before building a new one
    if (cyRef.current) { try { cyRef.current.destroy(); } catch (_) {} }

    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (nodes.length === 0 && edges.length === 0) return;

    // Determine root for breadthfirst layout — prefer "internet" node if present
    const hasInternet = nodes.some((n) => (n.data?.id ?? n.id) === "internet");

    const cy = cytoscape({
      container: ref.current,
      elements: [...nodes, ...edges],
      wheelSensitivity: 0.2,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n) => SEV_COLOR[n.data("severity")] || "#64748b",
            "border-color": "#ffffff",
            "border-width": 3,
            "shape": (n) => KIND_SHAPE[n.data("kind")] || "round-rectangle",
            "label": "data(label)",
            "color": "#0f172a",
            "font-family": "JetBrains Mono, monospace",
            "font-size": 11,
            "font-weight": 600,
            "text-margin-y": 14,
            "text-valign": "bottom",
            "text-halign": "center",
            "width":  (n) => n.data("kind") === "crown" ? 56 : 44,
            "height": (n) => n.data("kind") === "crown" ? 56 : 44,
            "overlay-opacity": 0,
            // Animate attack nodes with a growing border pulse
            "transition-property": "border-width, border-color",
            "transition-duration": "0.4s",
          },
        },
        {
          // Attack path nodes get a pulsing red ring
          selector: "node[severity = 'critical']",
          style: {
            "border-color": "#dc2626",
            "border-width": 5,
          },
        },
        {
          selector: "node.highlight",
          style: {
            "border-color": "#0a58ca",
            "border-width": 4,
          },
        },
        {
          selector: "edge",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color":         (e) => e.data("kind") === "attack"     ? "#dc2626"
                                       : e.data("kind") === "predicted"  ? "#0a58ca"
                                       : "#94a3b8",
            "target-arrow-color": (e) => e.data("kind") === "attack"     ? "#dc2626"
                                       : e.data("kind") === "predicted"  ? "#0a58ca"
                                       : "#94a3b8",
            "width":      (e) => Math.max(1.5, (e.data("weight") || 0.2) * 6),
            "line-style": (e) => e.data("kind") === "predicted" ? "dashed" : "solid",
            "opacity":    (e) => e.data("kind") === "blocked" ? 0.35 : 1,
            "label":      (e) => e.data("weight") ? e.data("weight").toFixed(2) : "",
            "font-family": "JetBrains Mono, monospace",
            "font-size": 9,
            "color": "#475569",
            "text-background-color":   "#ffffff",
            "text-background-opacity": 0.9,
            "text-background-padding": 2,
            // Smooth transition for attack propagation
            "transition-property": "line-color, width",
            "transition-duration": "0.3s",
          },
        },
        {
          selector: "edge[kind = 'blocked']",
          style: {
            "line-color":         "#94a3b8",
            "target-arrow-color": "#94a3b8",
            "line-style": "dotted",
            "label":      "✕ BLOCKED",
            "color":      "#dc2626",
            "font-weight": 700,
          },
        },
        {
          // Predicted next-hop edges: dashed blue, animated
          selector: "edge[kind = 'predicted']",
          style: {
            "line-style": "dashed",
            "line-dash-pattern": [6, 4],
          },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 30,
        spacingFactor: 1.25,
        roots: hasInternet ? ["internet"] : undefined,
      },
    });

    // Pulse animation: periodically flash critical nodes' border
    let tick = 0;
    const pulseInterval = setInterval(() => {
      if (!cyRef.current) { clearInterval(pulseInterval); return; }
      tick++;
      cyRef.current.nodes("[severity = 'critical']").forEach((n) => {
        n.style("border-width", tick % 2 === 0 ? 5 : 8);
      });
    }, 700);

    cyRef.current = cy;
    return () => {
      clearInterval(pulseInterval);
      try { cy.destroy(); } catch (_) {}
    };
  }, [graph]);  // Re-run whenever live graph data arrives from backend

  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().removeClass("highlight");
    highlightedNodes.forEach((id) => cyRef.current.$id(id).addClass("highlight"));
  }, [highlightedNodes]);

  // Derive a meaningful footer from live GNN perf data
  const attackEdges   = (graph.edges || []).filter((e) => e.data?.kind === "attack");
  const predictEdges  = (graph.edges || []).filter((e) => e.data?.kind === "predicted");
  const blockedEdges  = (graph.edges || []).filter((e) => e.data?.kind === "blocked");
  const topPredict    = predictEdges[0]?.data;
  const gatInference  = perf.gat_inference_ms ? `${perf.gat_inference_ms.toFixed(1)} ms` : null;

  return (
    <div className="panel h-full flex flex-col">
      <div className="px-5 py-3.5 border-b border-[var(--hci-border)] flex items-center gap-3">
        <Share2 size={16} className="text-[var(--hci-brand)]" />
        <div className="font-head font-bold text-[14.5px]">Predictive Attack Topology</div>
        <span className="chip chip-info">GNN + GAT attention</span>
        {isLoading && <Loader size={12} className="animate-spin text-[var(--hci-text-3)]" />}
        {isPlaceholderData && (
          <span className="chip chip-warning text-[10px]">mock · backend offline</span>
        )}
        <div className="ml-auto flex items-center gap-3 text-[11px] text-[var(--hci-text-3)]" data-testid={TID.topologyLegend}>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#dc2626]" /> Compromised</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#ea580c]" /> Suspicious</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#059669]" /> Clean</span>
          <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-[#0a58ca]" style={{ borderTop: "1px dashed #0a58ca" }} /> Predicted</span>
        </div>
      </div>
      <div
        ref={ref}
        data-testid={TID.topologyGraph}
        className="cy-container flex-1"
        style={{ minHeight: compact ? 360 : 480 }}
      />
      <div className="px-5 py-2.5 border-t border-[var(--hci-border)] bg-[#fbfcfd] text-[11.5px] text-[var(--hci-text-3)] flex items-center gap-2 flex-wrap">
        <Info size={12} />
        {topPredict ? (
          <>
            Predicted next hop{" "}
            <span className="font-mono text-[var(--hci-brand)]">
              {topPredict.source} → {topPredict.target}
            </span>{" "}
            (attention weight {(topPredict.weight || 0).toFixed(2)})
          </>
        ) : (
          <span>No predicted hops — attack contained</span>
        )}
        {blockedEdges.length > 0 && (
          <span className="text-emerald-600 font-semibold"> · {blockedEdges.length} edge{blockedEdges.length > 1 ? "s" : ""} blocked by SOAR</span>
        )}
        {gatInference && (
          <span className="ml-auto flex items-center gap-1">
            <Layers size={12} /> GAT: {gatInference}
          </span>
        )}
      </div>
    </div>
  );
};

export default AttackGraph;
