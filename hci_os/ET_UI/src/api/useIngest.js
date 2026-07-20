import { useMutation, useQueryClient } from "@tanstack/react-query";

/**
 * Sends a single IngestRequest { raw_event, asset_id, source } to the backend.
 * On success, invalidates timeline + decisions caches so the UI refreshes.
 */
export const useIngest = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ raw_event, asset_id = "", source = "ui" }) => {
      const res = await fetch("/api/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_event, asset_id, source }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? `Ingest failed: ${res.status}`);
      }
      return res.json();
    },
    onSuccess: () => {
      // Force-refresh timeline, decisions and audit after ingestion
      queryClient.invalidateQueries({ queryKey: ["timeline"] });
      queryClient.invalidateQueries({ queryKey: ["decisions"] });
      queryClient.invalidateQueries({ queryKey: ["audit-log"] });
    },
  });
};
