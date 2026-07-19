import React, { useState, useEffect, useRef } from "react";
import { useApp } from "@/context/AppContext";
import { TID } from "@/constants/testIds";
import { ROLES } from "@/mock/data";
import { useTimeline } from "@/api/useTimeline";
import { ChevronDown, Search, Bell, HelpCircle } from "lucide-react";
import KillSwitch from "./KillSwitch";

const RoleSwitcher = () => {
  const { roleId, setRoleId, role } = useApp();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        data-testid={TID.roleSwitcher}
        onClick={() => setOpen(!open)}
        className="btn btn-outline !py-1.5 !pl-1.5 !pr-3 gap-2"
      >
        <span className="w-7 h-7 rounded-md bg-[var(--hci-brand)] text-white text-[11px] font-mono font-bold flex items-center justify-center">
          {role.short}
        </span>
        <div className="text-left leading-tight">
          <div className="text-[12.5px] font-semibold">{role.label}</div>
          <div className="text-[10.5px] text-[var(--hci-text-3)] font-mono">{role.email}</div>
        </div>
        <ChevronDown size={12} />
      </button>
      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] w-72 panel shadow-lg z-40 overflow-hidden">
          <div className="px-3 py-2 label-caps border-b border-[var(--hci-border)]">Switch Role · RBAC</div>
          {ROLES.map((r) => (
            <button
              key={r.id}
              data-testid={TID.roleOption(r.id)}
              onClick={() => { setRoleId(r.id); setOpen(false); }}
              className={`w-full text-left px-3 py-2.5 flex items-center gap-3 hover:bg-[#f8fafc] ${
                r.id === roleId ? "bg-[#eef2ff]" : ""
              }`}
            >
              <span className="w-8 h-8 rounded-md bg-slate-100 border border-slate-200 flex items-center justify-center font-mono text-[11px] font-bold text-[var(--hci-brand)]">
                {r.short}
              </span>
              <div className="flex-1">
                <div className="text-[13px] font-semibold">{r.label}</div>
                <div className="text-[11px] text-[var(--hci-text-3)] font-mono">{r.email}</div>
              </div>
              {r.id === roleId && <span className="chip chip-info">ACTIVE</span>}
            </button>
          ))}
          <div className="px-3 py-2 text-[11px] text-[var(--hci-text-3)] bg-[#f8fafc] border-t border-[var(--hci-border)]">
            Login flow not wired · switch here to preview views.
          </div>
        </div>
      )}
    </div>
  );
};

const Header = () => {
  const { data } = useTimeline();
  const incident = data?.incident;
  const { searchQuery, setSearchQuery } = useApp();

  return (
    <header className="h-14 shrink-0 border-b border-[var(--hci-border)] bg-white px-4 flex items-center gap-3 sticky top-0 z-30 overflow-hidden">
      {/* Left: live incident badge — fixed width, never grows */}
      <div className="shrink-0">
        {incident ? (
          <span className="chip chip-critical whitespace-nowrap" data-testid="incident-badge">
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            LIVE · {incident.hypothesis_id}
          </span>
        ) : (
          <span className="chip chip-neutral whitespace-nowrap" data-testid="incident-badge">
            STANDBY
          </span>
        )}
      </div>

      {/* Center: search — fills remaining space, collapses before other items */}
      <div className="flex-1 min-w-0 max-w-xl relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
        <input
          data-testid="global-search"
          placeholder="Search evidence, hypotheses, assets…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full h-8 pl-9 pr-12 rounded-md bg-[#f8fafc] border border-[var(--hci-border)] text-[12.5px] focus:outline-none focus:ring-2 focus:ring-[var(--hci-brand)] focus:border-transparent"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            className="absolute right-12 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 text-[11px]"
            title="Clear search"
          >
            Clear
          </button>
        )}
        <span className="kbd absolute right-3 top-1/2 -translate-y-1/2 hidden sm:block">⌘K</span>
      </div>

      {/* Right: icons + role + kill switch — all shrink-0 so they never collapse */}
      <div className="shrink-0 flex items-center gap-1.5">
        <button className="btn btn-ghost !p-2" data-testid="notifications-btn"><Bell size={15} /></button>
        <button className="btn btn-ghost !p-2" data-testid="help-btn"><HelpCircle size={15} /></button>
        <div className="divider-v mx-1" />
        <RoleSwitcher />
        <div className="divider-v mx-1" />
        <KillSwitch />
      </div>
    </header>
  );
};

export default Header;
