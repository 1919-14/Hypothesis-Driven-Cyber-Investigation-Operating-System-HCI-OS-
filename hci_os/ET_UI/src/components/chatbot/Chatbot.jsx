import React, { useState, useRef, useEffect } from "react";
import { CHATBOT_RESPONSES } from "@/mock/data";
import { TID } from "@/constants/testIds";
import { MessageSquare, X, Send, Sparkles, Loader } from "lucide-react";
import { useApp } from "@/context/AppContext";
import { useChatbot } from "@/api/useChatbot";

const findResponse = (q) => {
  const s = q.toLowerCase();
  for (const key of Object.keys(CHATBOT_RESPONSES)) {
    if (key !== "default" && s.includes(key)) return CHATBOT_RESPONSES[key];
  }
  return CHATBOT_RESPONSES.default;
};

const suggested = [
  "Why was app-03 isolated?",
  "What's the next predicted hop?",
  "Why was this flagged?",
];

const Chatbot = () => {
  const { chatOpen, setChatOpen, role } = useApp();
  const chatMutation = useChatbot();
  const [msgs, setMsgs] = useState([
    { role: "bot", text: "Hi. I'm A6, wired to Groq Cloud (llama-3.1-8b-instant). Ask about evidence, hypotheses, or predicted moves." },
  ]);
  const [input, setInput] = useState("");
  const scrollRef = useRef(null);

  const send = async (text) => {
    const q = (text ?? input).trim();
    if (!q) return;
    setMsgs((m) => [...m, { role: "user", text: q }]);
    setInput("");
    chatMutation.mutate(
      { query: q, role: role?.label },
      {
        onSuccess: (res) => {
          setMsgs((m) => [...m, { role: "bot", text: res.response }]);
        },
        onError: () => {
          const s = q.toLowerCase();
          let fallback = CHATBOT_RESPONSES.default;
          for (const key of Object.keys(CHATBOT_RESPONSES)) {
            if (key !== "default" && s.includes(key)) { fallback = CHATBOT_RESPONSES[key]; break; }
          }
          setMsgs((m) => [...m, { role: "bot", text: fallback }]);
        },
      }
    );
  };

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [msgs, chatOpen]);

  return (
    <>
      {!chatOpen && (
        <button
          data-testid={TID.chatToggle}
          onClick={() => setChatOpen(true)}
          className="fixed bottom-5 right-5 z-40 h-12 pl-3 pr-4 rounded-full bg-[var(--hci-brand)] text-white flex items-center gap-2 shadow-lg hover:bg-[var(--hci-brand-hover)] font-semibold text-[13px]"
        >
          <MessageSquare size={16} /> Ask HCI-OS
        </button>
      )}
      {chatOpen && (
        <div className="fixed bottom-5 right-5 z-40 w-[380px] max-h-[560px] panel shadow-lg flex flex-col overflow-hidden" data-testid={TID.chatPanel}>
          <div className="px-4 py-3 border-b border-[var(--hci-border)] flex items-center gap-2 bg-[#fbfcfd]">
            <span className="w-7 h-7 rounded-md bg-[var(--hci-brand)] text-white flex items-center justify-center">
              <Sparkles size={13} />
            </span>
            <div className="leading-tight flex-1">
              <div className="font-head font-bold text-[13.5px]">A6 · Reasoner Chat</div>
              <div className="text-[10.5px] label-caps !tracking-[0.18em]">Explain · Correct · What-if</div>
            </div>
            <button className="btn btn-ghost !p-1.5" onClick={() => setChatOpen(false)}>
              <X size={14} />
            </button>
          </div>
          <div ref={scrollRef} className="flex-1 overflow-auto p-3 space-y-2.5 bg-[#fafbfc]" style={{ maxHeight: 360 }}>
            <div className="flex flex-col gap-2">
              {msgs.map((m, i) => (
                <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className={`max-w-[85%] rounded-lg px-3 py-2 text-[12.5px] leading-relaxed border ${
                    m.role === "user"
                      ? "bg-[var(--hci-brand)] text-white border-[var(--hci-brand)]"
                      : "bg-white text-[var(--hci-text)] border-[var(--hci-border)]"
                  }`}>
                    {m.text}
                  </div>
                </div>
              ))}
              {chatMutation.isPending && (
                <div className="flex justify-start">
                  <div className="bg-white border border-[var(--hci-border)] rounded-lg px-3 py-2 flex items-center gap-2 text-[12px] text-[var(--hci-text-3)]">
                    <Loader size={11} className="animate-spin" /> A6 reasoning…
                  </div>
                </div>
              )}
            </div>
          </div>
          <div className="px-3 pt-2 pb-2 border-t border-[var(--hci-border)] bg-white">
            <div className="flex flex-wrap gap-1.5 mb-2">
              {suggested.map((s, i) => (
                <button key={i} onClick={() => send(s)} className="chip chip-neutral hover:!bg-[#eef2ff] hover:!text-[var(--hci-brand)] cursor-pointer">
                  {s}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <input
                data-testid={TID.chatInput}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && send()}
                placeholder="Ask about the incident…"
                className="flex-1 h-9 px-3 rounded-md bg-[#f8fafc] border border-[var(--hci-border)] text-[13px] focus:outline-none focus:ring-2 focus:ring-[var(--hci-brand)]"
              />
              <button data-testid={TID.chatSend} onClick={() => send()} className="btn btn-primary btn-sm h-9">
                <Send size={13} />
              </button>
            </div>
            <div className="text-[10.5px] text-[var(--hci-text-3)] mt-1.5">
              Powered by Groq Cloud · llama-3.1-8b-instant · fallback to local mock.
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default Chatbot;
