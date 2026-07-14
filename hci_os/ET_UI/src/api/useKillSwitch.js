import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

/**
 * Syncs kill-switch state with the real backend.
 *
 * arm(reason)                 → POST /emergency-stop
 * release({ approver, notes }) → POST /emergency-stop/release?approver=…
 * frozen                       → boolean (polls every 3 s)
 */
export const useKillSwitch = () => {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["kill-switch-status"],
    queryFn: async () => {
      const res = await fetch("/api/emergency-stop/status");
      if (!res.ok) throw new Error(`Kill switch status failed: ${res.status}`);
      return res.json(); // { frozen: bool, valid_approvers: [] }
    },
    refetchInterval: 3_000,
    placeholderData: { frozen: false, valid_approvers: ["CISO", "sysadmin"] },
  });

  const armMutation = useMutation({
    mutationFn: async (reason = "Manual override from SOC console") => {
      const res = await fetch("/api/emergency-stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      if (!res.ok) throw new Error(`Emergency stop failed: ${res.status}`);
      return res.json();
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["kill-switch-status"] }),
  });

  const releaseMutation = useMutation({
    mutationFn: async ({ approver, notes = "" }) => {
      const params = new URLSearchParams({ approver, notes });
      const res = await fetch(`/api/emergency-stop/release?${params}`, { method: "POST" });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? `Release failed: ${res.status}`);
      }
      return res.json();
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["kill-switch-status"] }),
  });

  return {
    frozen:        query.data?.frozen ?? false,
    validApprovers: query.data?.valid_approvers ?? [],
    arm:           armMutation.mutate,
    release:       releaseMutation.mutate,
    isArming:      armMutation.isPending,
    isReleasing:   releaseMutation.isPending,
    releaseError:  releaseMutation.error,
  };
};
