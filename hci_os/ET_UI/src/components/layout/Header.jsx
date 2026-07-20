import React, { useState, useEffect, useRef } from "react";
import { useApp } from "@/context/AppContext";
import { TID } from "@/constants/testIds";
import { ROLES } from "@/mock/data";
import { useTimeline } from "@/api/useTimeline";
import { useAuditLog } from "@/api/useAuditLog";
import { ChevronDown, Search, Bell, X } from "lucide-react";
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
        <div className="absolute right-0 top-[calc(100%+6px)] w-72 panel shadow-lg z-[200] overflow-hidden">
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
            Role determines which pages and actions are available.
          </div>
        </div>
      )}
    </div>
  );
};

// Live notifications panel backed by audit log
const NotificationPanel = ({ onClose }) => {
  const { data: entries = [] } = useAuditLog();
  const recent = entries.slice(0, 8);
  return (
    <div className="absolute right-0 top-[calc(100%+6px)] w-80 panel shadow-xl z-[200] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-[var(--hci-border)] flex items-center justify-between">
        <span className="font-semibold text-[13px]">Recent Alerts</span>
        <div className="flex items-center gap-2">
          <span className="chip chip-info text-[10px]">{recent.length} entries</span>
          <button onClick={onClose} className="btn btn-ghost !p-1"><X size={12} /></button>
        </div>
      </div>
      {recent.length === 0 ? (
        <div className="px-4 py-6 text-center text-[12px] text-slate-400">
          No events yet — ingest an attack event to see alerts here.
        </div>
      ) : (
        <div className="max-h-72 overflow-auto divide-y divide-[var(--hci-border)]">
          {recent.map((e, i) => (
            <div key={i} className="px-4 py-2.5 hover:bg-slate-50">
              <div className="flex items-center gap-2">
                <span className="chip chip-info text-[9.5px] font-mono">{e.event}</span>
                <span className="text-[10.5px] text-slate-400 ml-auto font-mono">{e.ts?.slice(11, 19)}</span>
              </div>
              <div className="text-[11.5px] text-slate-700 mt-0.5 font-mono truncate">
                {e.actor} → {e.target}
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="px-4 py-2 border-t border-[var(--hci-border)] text-[10.5px] text-slate-400 bg-slate-50">
        From immutable A12 audit chain · live
      </div>
    </div>
  );
};

const Header = () => {
  const { data } = useTimeline();
  const incident = data?.incident;
  const { searchQuery, setSearchQuery, setRoute } = useApp();
  const [bellOpen, setBellOpen] = useState(false);
  const bellRef = useRef(null);
  const { data: auditEntries = [] } = useAuditLog();
  const unread = auditEntries.length;

  useEffect(() => {
    const onDoc = (e) => { if (bellRef.current && !bellRef.current.contains(e.target)) setBellOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const handleSearch = (e) => {
    if (e.key === "Enter" && searchQuery.trim()) {
      // Navigate to AI Monitor which shows all agent activity, or incident if matches HYP
      if (searchQuery.toLowerCase().includes("hyp") || searchQuery.toLowerCase().includes("incident")) {
        setRoute("incident");
      } else if (searchQuery.toLowerCase().includes("audit") || searchQuery.toLowerCase().includes("log")) {
        setRoute("audit");
      } else if (searchQuery.toLowerCase().includes("gate") || searchQuery.toLowerCase().includes("decision")) {
        setRoute("gate");
      } else {
        setRoute("aimonitor");
      }
    }
  };

  return (
    <header className="h-14 shrink-0 border-b border-[var(--hci-border)] bg-white px-4 flex items-center gap-3 sticky top-0 z-[9999]">
      {/* Left: live incident badge */}
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

      {/* Center: search */}
      <div className="flex-1 min-w-0 max-w-xl relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
        <input
          data-testid="global-search"
          placeholder="Search evidence, hypotheses, assets… (Enter to navigate)"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyDown={handleSearch}
          className="w-full h-8 pl-9 pr-12 rounded-md bg-[#f8fafc] border border-[var(--hci-border)] text-[12.5px] focus:outline-none focus:ring-2 focus:ring-[var(--hci-brand)] focus:border-transparent"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            className="absolute right-12 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 text-[11px]"
          >
            Clear
          </button>
        )}
        <span className="kbd absolute right-3 top-1/2 -translate-y-1/2 hidden sm:block">⌘K</span>
      </div>

      {/* Right */}
      <div className="shrink-0 flex items-center gap-1.5">
        {/* Notification bell wired to audit log */}
        <div className="relative" ref={bellRef}>
          <button
            className="btn btn-ghost !p-2 relative"
            data-testid="notifications-btn"
            onClick={() => setBellOpen(o => !o)}
          >
            <Bell size={15} />
            {unread > 0 && (
              <span className="absolute top-1 right-1 w-3.5 h-3.5 rounded-full bg-[var(--hci-critical)] text-white text-[8px] font-bold flex items-center justify-center">
                {Math.min(unread, 9)}
              </span>
            )}
          </button>
          {bellOpen && <NotificationPanel onClose={() => setBellOpen(false)} />}
        </div>

        <div className="divider-v mx-1" />
        <RoleSwitcher />
        <div className="divider-v mx-1" />
        <KillSwitch />
      </div>
    </header>
  );
};

export default Header;
