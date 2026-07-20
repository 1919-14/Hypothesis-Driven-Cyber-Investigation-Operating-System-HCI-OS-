import "@/App.css";
import React from "react";
import { AppProvider, useApp } from "@/context/AppContext";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import Chatbot from "@/components/chatbot/Chatbot";
import IncidentPage from "@/pages/IncidentPage";
import IngestPage from "@/pages/IngestPage";
import AIMonitorPage from "@/pages/AIMonitorPage";
import DigitalTwin from "@/components/twin/DigitalTwin";
import CertInReport from "@/components/report/CertInReport";
import { TopologyPage, GatePage, AuditPage, ExecPage, HealthPage } from "@/pages/OtherPages";

const Router = () => {
  const { route } = useApp();
  switch (route) {
    case "incident": return <IncidentPage />;
    case "ingest":   return <IngestPage />;
    case "aimonitor":return <AIMonitorPage />;
    case "topology": return <TopologyPage />;
    case "gate":     return <GatePage />;
    case "twin":     return <DigitalTwin />;
    case "report":   return <CertInReport />;
    case "audit":    return <AuditPage />;
    case "exec":     return <ExecPage />;
    case "health":   return <HealthPage />;
    default:         return <IncidentPage />;
  }
};

const Shell = () => {
  const { killActive } = useApp();

  return (
    <div className="flex min-h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header />
        {killActive && (
          <div className="bg-red-600 text-white font-mono text-[12px] font-bold px-4 py-2 flex items-center justify-between animate-pulse shrink-0 border-b border-red-700">
            <div className="flex items-center gap-2">
              <span className="live-dot !bg-white" style={{ width: 8, height: 8 }} />
              <span>CRITICAL: EMERGENCY STOP ACTIVE · AUTONOMOUS MITIGATIONS FROZEN</span>
            </div>
            <div className="text-[10px] bg-red-800 px-2 py-0.5 rounded">SD-8 PROTECTION ACTIVE</div>
          </div>
        )}
        <main className="flex-1 blueprint-grid p-5 overflow-x-hidden overflow-y-auto">
          <Router />
        </main>
      </div>
      <Chatbot />
    </div>
  );
};

function App() {
  return (
    <AppProvider>
      <div className="App">
        <Shell />
      </div>
    </AppProvider>
  );
}

export default App;
