import "@/App.css";
import React from "react";
import { AppProvider, useApp } from "@/context/AppContext";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import Chatbot from "@/components/chatbot/Chatbot";
import IncidentPage from "@/pages/IncidentPage";
import DigitalTwin from "@/components/twin/DigitalTwin";
import CertInReport from "@/components/report/CertInReport";
import { TopologyPage, GatePage, AuditPage, ExecPage, HealthPage } from "@/pages/OtherPages";

const Router = () => {
  const { route } = useApp();
  switch (route) {
    case "incident": return <IncidentPage />;
    case "topology": return <TopologyPage />;
    case "gate": return <GatePage />;
    case "twin": return <DigitalTwin />;
    case "report": return <CertInReport />;
    case "audit": return <AuditPage />;
    case "exec": return <ExecPage />;
    case "health": return <HealthPage />;
    default: return <IncidentPage />;
  }
};

const Shell = () => {
  return (
    <div className="flex min-h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header />
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
