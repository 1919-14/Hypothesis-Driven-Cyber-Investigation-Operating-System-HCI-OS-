import { useQuery } from "@tanstack/react-query";

/**
 * Fetches the live audit chain excerpt from the CERT-In report endpoint.
 * The CERT-In endpoint returns { audit_excerpt: [{ts, actor, event, target, hash}] }
 * which matches the shape the AuditPage table expects exactly.
 */
export const useAuditLog = () => {
  return useQuery({
    queryKey: ["audit-log"],
    queryFn: async () => {
      const res = await fetch("/api/cert-in/report/latest");
      if (!res.ok) throw new Error(`Audit log fetch failed: ${res.status}`);
      const data = await res.json();
      // audit_excerpt shape: [{ts, actor, event, target, hash}]
      return data.audit_excerpt ?? [];
    },
    refetchInterval: 8_000,
  });
};
