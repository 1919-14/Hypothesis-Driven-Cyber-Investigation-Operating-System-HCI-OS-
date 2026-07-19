import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

/**
 * Returns the list of pending human-gate decisions and mutation helpers
 * for confirm / revoke / modify / escalate.
 */
export const useDecisions = (role) => {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["decisions"],
    queryFn: async () => {
      const res = await fetch("/api/decisions/pending");
      if (!res.ok) throw new Error(`Decisions fetch failed: ${res.status}`);
      return res.json();
    },
    refetchInterval: 5_000,
  });

  const mutation = useMutation({
    mutationFn: async ({ decisionId, action, analystId, notes, newAction }) => {
      const res = await fetch(`/api/correction/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision_id:  decisionId,
          analyst_role: role?.id?.toUpperCase() ?? "SENIOR",
          analyst_id:   analystId ?? role?.email ?? "soc_analyst",
          new_action:   newAction ?? null,
          notes:        notes ?? null,
        }),
      });
      if (!res.ok) throw new Error(`Correction failed: ${res.status}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["decisions"] });
    },
  });

  return {
    ...query,
    act: mutation.mutate,
    isMutating: mutation.isPending,
    mutateError: mutation.error,
  };
};
