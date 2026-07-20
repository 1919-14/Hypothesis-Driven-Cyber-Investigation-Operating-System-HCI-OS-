import { useQuery } from "@tanstack/react-query";

export const usePipelineHistory = (limit = 50) => {
  return useQuery({
    queryKey: ["pipelineHistory", limit],
    queryFn: async () => {
      const res = await fetch(`/api/pipeline/history?limit=${limit}`);
      if (!res.ok) throw new Error(`Pipeline history failed: ${res.status}`);
      return res.json();
    },
    refetchInterval: 10_000,
  });
};
