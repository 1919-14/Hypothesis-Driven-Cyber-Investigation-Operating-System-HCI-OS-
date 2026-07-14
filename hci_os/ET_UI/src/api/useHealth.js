import { useQuery } from "@tanstack/react-query";

/**
 * Polls the system health endpoint every 5 s.
 * Returns { healthy, autonomy_frozen, watchdog, sd_chain, circuit_breakers }.
 * Used by HealthPage to show live agent status cards.
 */
export const useHealth = () => {
  return useQuery({
    queryKey: ["health"],
    queryFn: async () => {
      const res = await fetch("/api/health");
      // health can return 503 when degraded — still parse the body
      return res.json();
    },
    refetchInterval: 5_000,
    placeholderData: {
      healthy:          true,
      autonomy_frozen:  false,
      watchdog:         { healthy: true, agents: {} },
      sd_chain:         { valid: true },
      circuit_breakers: {},
    },
  });
};
