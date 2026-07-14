import React, { useState, useEffect } from "react";
import { useApp } from "@/context/AppContext";
import { TID } from "@/constants/testIds";
import { useKillSwitch } from "@/api/useKillSwitch";
import { AlertTriangle, Lock, Unlock, X } from "lucide-react";

const KillSwitch = () => {
  const { killActive, setKillActive, role } = useApp();
  const [modalOpen, setModalOpen] = useState(false);
  const [holdMs, setHoldMs] = useState(0);
  const [holding, setHolding] = useState(false);
  const { frozen: apiFrozen, arm, release, releaseError } = useKillSwitch();

  // Sync API frozen state into local App context so other components can read it
  useEffect(() => { setKillActive(apiFrozen); }, [apiFrozen, setKillActive]);
  const canRelease = role.id === "ciso" || role.id === "sysadmin";
  const pct = Math.min(100, (holdMs / 3000) * 100);

  useEffect(() => {
    if (!holding) return;
    const start = Date.now();
    const tick = setInterval(() => {
      const ms = Date.now() - start;
      setHoldMs(ms);
      if (ms >= 3000) {
        clearInterval(tick);
        setHolding(false);
        setModalOpen(false);
        setHoldMs(0);
        arm("Manual override from SOC console");
      }
    }, 50);
    return () => clearInterval(tick);
  }, [holding, arm]);

  return (
    <>
      <div className="relative shrink-0">
        {killActive && <span className="pulse-ring" />}
        <button
          data-testid={TID.killSwitch}
          onClick={() => setModalOpen(true)}
          className={`relative flex items-center gap-1.5 px-3 h-8 rounded-md border-2 font-mono uppercase text-[11px] font-bold tracking-[0.1em] transition-colors whitespace-nowrap ${
            killActive
              ? "bg-[var(--hci-critical)] text-white border-[var(--hci-critical)]"
              : "bg-white text-[var(--hci-critical)] border-[var(--hci-critical)] hover:bg-[#fef2f2]"
          }`}
        >
          {killActive ? <Lock size={12} /> : <AlertTriangle size={12} />}
          <span>Kill Switch</span>
          <span className={`chip ${killActive ? "chip-critical" : "chip-neutral"} !py-0 !text-[9px] !px-1.5`}>
            {killActive ? "ACTIVE" : "OFF"}
          </span>
        </button>
      </div>

      {modalOpen && (
        <div className="fixed inset-0 bg-slate-900/40 z-50 flex items-center justify-center p-6" data-testid={TID.killSwitchModal}>
          <div className="panel w-[520px] overflow-hidden">
            <div className="px-5 py-4 flex items-center justify-between border-b border-[var(--hci-border)]">
              <div className="flex items-center gap-2">
                <AlertTriangle size={20} className="text-[var(--hci-critical)]" />
                <div className="font-head font-bold text-[16px]">Emergency Autonomous Freeze</div>
              </div>
              <button className="btn btn-ghost !p-1.5" onClick={() => { setModalOpen(false); setHolding(false); setHoldMs(0); }}>
                <X size={14} />
              </button>
            </div>
            <div className="px-5 py-4 text-[13px] leading-relaxed text-[var(--hci-text-2)]">
              This will freeze <span className="font-semibold text-[var(--hci-text)]">all autonomous SOAR actions</span> across HCI-OS.
              Existing containment stays in place; new agent-initiated changes will queue for human release.
              Every activation is signed to the audit chain.
              <div className="panel-raised mt-3 p-3 font-mono text-[11.5px]">
                <div>POST /emergency-stop</div>
                <div>actor: {role.email}</div>
                <div>reason: manual_override</div>
              </div>
            </div>

            {!killActive ? (
              <div className="px-5 pb-5">
                <div className="label-caps mb-2">Hold to arm · 3 seconds</div>
                <button
                  data-testid={TID.killSwitchConfirm}
                  onMouseDown={() => setHolding(true)}
                  onMouseUp={() => { setHolding(false); setHoldMs(0); }}
                  onMouseLeave={() => { setHolding(false); setHoldMs(0); }}
                  onTouchStart={() => setHolding(true)}
                  onTouchEnd={() => { setHolding(false); setHoldMs(0); }}
                  className="relative w-full h-12 rounded-md bg-[var(--hci-critical)] text-white font-mono uppercase tracking-[0.14em] font-bold overflow-hidden select-none"
                >
                  <div
                    className="absolute inset-y-0 left-0 bg-[#7f1d1d]"
                    style={{ width: `${pct}%`, transition: "width 0.05s linear" }}
                  />
                  <span className="relative">
                    {holding ? `ARMING… ${(3 - holdMs / 1000).toFixed(1)}s` : "HOLD TO ACTIVATE KILL SWITCH"}
                  </span>
                </button>
                <div className="text-[11px] text-[var(--hci-text-3)] mt-2">
                  Release before 3s to cancel.
                </div>
              </div>
            ) : (
              <div className="px-5 pb-5">
                <div className="panel-raised p-3 mb-3 text-[12.5px] text-[var(--hci-critical)] font-mono flex items-center gap-2">
                  <span className="live-dot" /> KILL SWITCH ACTIVE · agents frozen
                </div>
                <button
                  data-testid={TID.killSwitchRelease}
                  disabled={!canRelease}
                  onClick={() => { release({ approver: role.id }); setModalOpen(false); }}
                  className={`w-full btn ${canRelease ? "btn-primary" : "btn-outline"} !h-11 justify-center`}
                >
                  <Unlock size={16} strokeWidth={2.5} /> Release Kill Switch ({role.short})
                </button>
                {!canRelease && (
                  <div className="text-[11.5px] text-[var(--hci-critical)] mt-2 font-mono">
                    Only CISO or SysAdmin can release. Current role: {role.label}.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};

export default KillSwitch;
