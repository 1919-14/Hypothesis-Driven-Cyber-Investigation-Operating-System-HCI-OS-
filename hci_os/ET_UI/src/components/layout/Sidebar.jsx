import React, { useEffect, useState } from "react";
import { useApp } from "@/context/AppContext";
import { TID } from "@/constants/testIds";
import {
  ShieldCheck,
  Activity,
  Share2,
  Users,
  FileText,
  Bug,
  Cpu,
  Lock,
  LineChart,
  UploadCloud,
  Brain,
  GitBranch,
} from "lucide-react";
import { useDecisions } from "@/api/useDecisions";
import { useHealth } from "@/api/useHealth";
import PipelineTraceModal from "@/components/trace/PipelineTraceModal";

const NAV = [
  { id: "incident",  label: "Incident Timeline", icon: Activity,    roles: ["soc", "reviewer", "ciso", "sysadmin"] },
  { id: "ingest",    label: "Ingest Events",     icon: UploadCloud, roles: ["soc", "reviewer", "ciso", "sysadmin"] },
  { id: "aimonitor", label: "AI Monitor",         icon: Brain,       roles: ["soc", "reviewer", "ciso", "sysadmin"] },
  { id: "topology",  label: "Attack Topology",   icon: Share2,      roles: ["soc", "reviewer", "ciso", "sysadmin"] },
  { id: "gate",      label: "Human Gate",        icon: Users,       roles: ["soc", "reviewer", "sysadmin"] },
  { id: "twin",      label: "Digital Twin",      icon: Bug,         roles: ["soc", "reviewer", "sysadmin"] },
  { id: "report",    label: "CERT-In Report",    icon: FileText,    roles: ["soc", "reviewer", "ciso", "sysadmin"] },
  { id: "exec",      label: "Executive View",    icon: LineChart,   roles: ["ciso"] },
  { id: "audit",     label: "Audit Chain",       icon: Lock,        roles: ["reviewer", "ciso", "sysadmin"] },
  { id: "health",    label: "Agent Health",      icon: Cpu,         roles: ["sysadmin"] },
];

const Sidebar = () => {
  const { route, setRoute, roleId, role } = useApp();
  const items = NAV.filter((n) => n.roles.includes(roleId));
  const [showTrace, setShowTrace] = useState(false);

  // Dynamic Human Gate pending decisions count
  const { data: decisions } = useDecisions(role);
  const pendingCount = (decisions ?? []).length;

  const { data: health } = useHealth();
  const agentsMonitored = health?.watchdog?.agents_monitored ?? 11;
  const systemStatusLabel = health?.healthy ? "System Healthy" : "Degraded State";

  // Auto-redirect if switched to a role that does not have access to current route
  useEffect(() => {
    const isAllowed = items.some((item) => item.id === route);
    if (!isAllowed && items.length > 0) {
      setRoute(items[0].id);
    }
  }, [roleId, items, route, setRoute]);

  return (
    <aside className="w-64 shrink-0 border-r border-[var(--hci-border)] bg-white flex flex-col">
      <div className="h-16 px-5 flex items-center gap-2 border-b border-[var(--hci-border)]">
        <div className="w-8 h-8 rounded-md bg-[var(--hci-brand)] text-white flex items-center justify-center">
          <ShieldCheck size={18} strokeWidth={2.5} />
        </div>
        <div className="leading-tight">
          <div className="font-head font-bold text-[15px]">HCI-OS</div>
          <div className="text-[10.5px] label-caps !tracking-[0.18em] !text-[var(--hci-text-3)]">Investigation Console</div>
        </div>
      </div>

      <div className="px-4 pt-5 pb-2 label-caps">Navigation</div>
      <nav className="px-3 pb-4 flex flex-col gap-1">
        {items.map((n) => {
          const Icon = n.icon;
          const active = route === n.id;
          return (
            <button
              key={n.id}
              data-testid={TID.sidebarItem(n.id)}
              onClick={() => setRoute(n.id)}
              className={`side-item text-left ${active ? "active" : ""}`}
            >
              <Icon size={16} weight={active ? "fill" : "regular"} />
              <span className="flex-1">{n.label}</span>
              {n.id === "gate" && pendingCount > 0 && (
                <span className="chip chip-critical !py-0 !px-2 !text-[10px]">{pendingCount}</span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Pipeline Trace quick-access button */}
      <div className="px-3 pb-3">
        <button
          onClick={() => setShowTrace(true)}
          className="side-item w-full text-left text-violet-600 hover:text-violet-700 hover:bg-violet-50"
        >
          <GitBranch size={16} />
          <span className="flex-1">Pipeline Trace</span>
          <span className="chip chip-neutral text-[10px]">HITL</span>
        </button>
      </div>

      <div className="mt-auto p-4 border-t border-[var(--hci-border)]">
        <div className="label-caps mb-2">Deployment</div>
        <div className="panel-raised p-3 text-[12px] leading-relaxed">
          <div className="flex items-center gap-2 mb-1">
            <span className={`live-dot ${health?.healthy ? "" : "!bg-amber-500"}`} />
            <span className="font-mono text-slate-700">prod-in-south-1</span>
          </div>
          <div className="text-[var(--hci-text-3)] font-mono text-[11px]">{agentsMonitored} AGENTS ONLINE · {systemStatusLabel.toUpperCase()}</div>
        </div>
      </div>

      {showTrace && <PipelineTraceModal onClose={() => setShowTrace(false)} />}
    </aside>
  );
};

export default Sidebar;
