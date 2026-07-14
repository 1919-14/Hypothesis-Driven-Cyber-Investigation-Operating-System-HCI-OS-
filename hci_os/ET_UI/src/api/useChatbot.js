import { useMutation } from "@tanstack/react-query";
import { CHATBOT_RESPONSES } from "@/mock/data";

/** Keyword fallback identical to the original Chatbot.jsx logic */
const findMockResponse = (q) => {
  const s = q.toLowerCase();
  for (const key of Object.keys(CHATBOT_RESPONSES)) {
    if (key !== "default" && s.includes(key)) return CHATBOT_RESPONSES[key];
  }
  return CHATBOT_RESPONSES.default;
};

/**
 * Sends a query to the backend A6/Groq chatbot endpoint.
 * On network/API failure, falls back to the local keyword dictionary
 * so the demo never shows a blank response.
 *
 * Returns { mutate, isPending, data: { response, source } }
 */
export const useChatbot = (hypothesisId = null) => {
  return useMutation({
    mutationFn: async ({ query, role = "SOC Analyst" }) => {
      try {
        const res = await fetch("/api/chatbot/query", {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ query, hypothesis_id: hypothesisId, role }),
        });
        if (!res.ok) throw new Error(`Chatbot API error: ${res.status}`);
        return res.json(); // { response: string, source: "groq"|"mock"|"default" }
      } catch {
        // Network-level fallback
        return { response: findMockResponse(query), source: "local_fallback" };
      }
    },
  });
};
