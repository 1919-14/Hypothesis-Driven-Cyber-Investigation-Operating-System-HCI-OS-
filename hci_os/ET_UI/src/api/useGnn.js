import { useQuery } from "@tanstack/react-query";
import { GRAPH } from "@/mock/data";

/**
 * Fetches GNN ensemble visualization from the backend (GAT + TGN + GraphSAGE).
 * Returns the cytoscape graph in the same {nodes, edges} shape as GRAPH mock,
 * plus optional tgn_timeline and sage_pca for supplementary panels.
 * Polls every 10 s so live attack-path updates appear automatically.
 */
export const useGnn = () => {
  return useQuery({
    queryKey: ["gnn-viz"],
    queryFn: async () => {
      const res = await fetch("/api/gnn/visualization");
      if (!res.ok) throw new Error(`GNN viz fetch failed: ${res.status}`);
      const data = await res.json();
      // The backend returns { cytoscape: { nodes, edges }, tgn_timeline, sage_pca }
      // but we also accept the raw cytoscape format from DigitalTwin
      const cyto = data.cytoscape ?? data;
      return {
        graph:        cyto,               // { nodes: [], edges: [] } — Cytoscape-compatible
        tgn_timeline: data.tgn_timeline ?? [],
        sage_pca:     data.sage_pca ?? [],
        perf:         data.perf ?? {},
      };
    },
    refetchInterval: 10_000,
    placeholderData: {
      graph:        GRAPH,
      tgn_timeline: [],
      sage_pca:     [],
      perf:         {},
    },
  });
};
