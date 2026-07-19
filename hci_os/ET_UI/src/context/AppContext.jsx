import React, { createContext, useContext, useState, useMemo } from "react";
import { ROLES } from "@/mock/data";

const AppCtx = createContext(null);

export const AppProvider = ({ children }) => {
  const [roleId, setRoleId] = useState("soc");
  const [killActive, setKillActive] = useState(false);
  const [route, setRoute] = useState("incident"); // incident | gate | twin | report | audit | health
  const [selectedEventIdx, setSelectedEventIdx] = useState(null);
  const [chatOpen, setChatOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const role = useMemo(() => ROLES.find((r) => r.id === roleId), [roleId]);

  const value = {
    roleId, setRoleId, role,
    killActive, setKillActive,
    route, setRoute,
    selectedEventIdx, setSelectedEventIdx,
    chatOpen, setChatOpen,
    searchQuery, setSearchQuery,
  };
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
};

export const useApp = () => {
  const ctx = useContext(AppCtx);
  if (!ctx) throw new Error("useApp must be inside AppProvider");
  return ctx;
};
