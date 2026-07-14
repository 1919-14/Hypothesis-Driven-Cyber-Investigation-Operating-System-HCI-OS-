export const TID = {
  killSwitch: "kill-switch-btn",
  killSwitchModal: "kill-switch-modal",
  killSwitchConfirm: "kill-switch-confirm-btn",
  killSwitchRelease: "kill-switch-release-btn",
  roleSwitcher: "role-switcher",
  roleOption: (id) => `role-option-${id}`,
  sidebarItem: (id) => `sidebar-item-${id}`,

  // Timeline
  timelineSlider: "timeline-slider",
  timelineEvent: (i) => `timeline-event-${i}`,
  timelinePlay: "timeline-play-btn",
  timelineReset: "timeline-reset-btn",

  // Topology
  topologyGraph: "topology-graph",
  topologyLegend: "topology-legend",

  // Human Gate
  gateRow: (id) => `gate-row-${id}`,
  gateConfirm: (id) => `gate-confirm-${id}`,
  gateRevoke: (id) => `gate-revoke-${id}`,
  gateModify: (id) => `gate-modify-${id}`,
  gateEscalate: (id) => `gate-escalate-${id}`,

  // Digital Twin
  twinSimulate: "twin-simulate-btn",
  twinReset: "twin-reset-btn",

  // Report
  reportGenerate: "cert-in-generate-btn",
  reportDownload: "cert-in-download-btn",
  reportContainer: "cert-in-report",

  // Chatbot
  chatToggle: "chatbot-toggle",
  chatInput: "chatbot-input",
  chatSend: "chatbot-send",
  chatPanel: "chatbot-panel",
};
