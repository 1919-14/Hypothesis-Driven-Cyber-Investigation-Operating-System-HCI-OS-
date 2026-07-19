import { useQuery } from "@tanstack/react-query";

/**
 * Fetches the CERT-In compliance report data.
 * Returns { incident, timeline_events, audit_excerpt }.
 * Used by CertInReport.jsx to render the live report and power the download.
 */
export const useCertIn = (hypothesisId = "latest") => {
  return useQuery({
    queryKey: ["cert-in-report", hypothesisId],
    queryFn: async () => {
      const res = await fetch(`/api/cert-in/report/${hypothesisId}`);
      if (!res.ok) throw new Error(`CERT-In report fetch failed: ${res.status}`);
      return res.json();
    },
    staleTime: 30_000,
  });
};

/**
 * Downloads the Markdown version of the CERT-In report by calling
 * GET /cert-in/report/:id?format=md and triggering a file save.
 */
export const downloadCertInMarkdown = async (hypothesisId = "latest") => {
  const res = await fetch(`/api/cert-in/report/${hypothesisId}?format=md`);
  if (!res.ok) throw new Error("CERT-In markdown download failed");
  const text = await res.text();
  const blob = new Blob([text], { type: "text/markdown" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `CERT-IN_${hypothesisId}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};
