import { useQuery } from "@tanstack/react-query";

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
      const cyto = data.cytoscape ?? data;
      return {
        graph:        cyto,
        tgn_timeline: data.tgn_timeline ?? [],
        sage_pca:     data.sage_pca ?? [],
        perf:         data.perf ?? {},
      };
    },
    refetchInterval: 10_000,
    retry: 1,
    placeholderData: {
      graph: { nodes: [], edges: [] },
      tgn_timeline: [],
      sage_pca: [],
      perf: {},
    },
  });
};
