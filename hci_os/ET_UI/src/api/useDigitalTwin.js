import { useQuery, useMutation } from "@tanstack/react-query";

/**
 * Fetches the Digital Twin infrastructure graph once for Cytoscape rendering.
 */
export const useDigitalTwinGraph = () => {
  return useQuery({
    queryKey: ["twin-graph"],
    queryFn: async () => {
      const res = await fetch("/api/digital-twin/graph");
      if (!res.ok) throw new Error(`Twin graph fetch failed: ${res.status}`);
      return res.json(); // { elements: [...], metadata: {...} }
    },
    staleTime: 60_000, // graph is static — refetch only after 1 min
  });
};

/**
 * Triggers an attack simulation on the Digital Twin.
 * Returns { attack_path, timeline, node_states, simulation_id, reached_target }.
 * The returned timeline drives the hop-by-hop Cytoscape animation in DigitalTwin.jsx.
 */
export const useDigitalTwinSimulate = () => {
  return useMutation({
    mutationFn: async ({
      startNode    = "CBSE-WebSvr-01",
      targetNode   = "CrownJewel-ExamDB",
      attackerIp   = "185.203.116.44",
      feedPipeline = false,
    } = {}) => {
      const res = await fetch("/api/digital-twin/simulate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({
          start_node:    startNode,
          target_node:   targetNode,
          attacker_ip:   attackerIp,
          feed_pipeline: feedPipeline,
        }),
      });
      if (!res.ok) throw new Error(`Twin simulation failed: ${res.status}`);
      return res.json();
    },
  });
};
