import { useQuery } from "@tanstack/react-query";
import { INCIDENT, TIMELINE_EVENTS } from "@/mock/data";

/**
 * Fetches incident metadata + timeline events from the backend.
 * Falls back to static mock data so the UI always renders on first load.
 * Polls every 5 s so live investigation updates appear automatically.
 */
export const useTimeline = (hypothesisId = "latest") => {
  return useQuery({
    queryKey: ["timeline", hypothesisId],
    queryFn: async () => {
      const res = await fetch(`/api/incident/timeline/${hypothesisId}`);
      if (!res.ok) throw new Error(`Timeline fetch failed: ${res.status}`);
      return res.json();
    },
    refetchInterval: 5_000,
    // Immediately show mock data before the first API round-trip
    placeholderData: {
      incident: INCIDENT,
      timeline_events: TIMELINE_EVENTS,
    },
  });
};
