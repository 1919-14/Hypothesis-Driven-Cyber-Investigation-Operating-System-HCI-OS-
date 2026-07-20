import { useQuery, useMutation } from "@tanstack/react-query";

/**
 * Fetches the Digital Twin infrastructure graph from the SAME source as
 * AttackGraph (/api/gnn/visualization) so both views show identical topology.
 * Adapts the cytoscape payload into { elements, metadata } shape.
 */
export const useDigitalTwinGraph = () => {
  return useQuery({
    queryKey: ["twin-graph"],
    queryFn: async () => {
      const res = await fetch("/api/gnn/visualization");
      if (!res.ok) throw new Error(`Twin graph fetch failed: ${res.status}`);
      const data = await res.json();
      const cyto = data.cytoscape ?? data;
      // Normalize to flat Cytoscape elements array
      const elements = [
        ...(cyto.nodes || []),
        ...(cyto.edges || []),
      ];
      return { elements, metadata: data.perf ?? {} };
    },
    staleTime: 60_000,
  });
};

/**
 * Triggers an attack simulation on the Digital Twin.
 */
export const useDigitalTwinSimulate = () => {
  return useMutation({
    mutationFn: async ({
      startNode    = "CBSE-WebSvr-01",
      targetNode   = "CrownJewel-ExamDB",
      attackerIp   = "185.203.116.44",
      feedPipeline = false,
      gnnGuided    = false,
    } = {}) => {
      const res = await fetch("/api/digital-twin/simulate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          start_node:    startNode,
          target_node:   targetNode,
          attacker_ip:   attackerIp,
          feed_pipeline: feedPipeline,
          gnn_guided:    gnnGuided,
        }),
      });
      if (!res.ok) throw new Error(`Twin simulation failed: ${res.status}`);
      return res.json();
    },
  });
};
