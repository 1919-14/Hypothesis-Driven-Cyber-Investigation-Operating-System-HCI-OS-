import { useState, useEffect } from "react";

const pad = (n) => n.toString().padStart(2, "0");
const CERT_IN_SLA_HOURS = 6; // CERT-In mandatory 6-hour reporting window (Section 70B)

export const useCountdown = (detectionTs) => {
  const getRemainingSeconds = () => {
    if (!detectionTs) return 0;
    let parsed;
    if (typeof detectionTs === "string") {
      // If naive local ISO string has 'Z' appended, strip 'Z' to parse in local timezone
      const cleanTs = detectionTs.endsWith("Z") ? detectionTs.slice(0, -1) : detectionTs;
      parsed = new Date(cleanTs).getTime();
      if (isNaN(parsed)) {
        parsed = new Date(detectionTs).getTime();
      }
    } else {
      parsed = new Date(detectionTs).getTime();
    }
    if (isNaN(parsed)) return 0;

    const deadlineTime = parsed + (CERT_IN_SLA_HOURS * 3600 * 1000);
    const diffSeconds = Math.floor((deadlineTime - Date.now()) / 1000);
    // Guarantee countdown is strictly capped between 0 and 6 hours (21600 seconds)
    return Math.min(CERT_IN_SLA_HOURS * 3600, Math.max(0, diffSeconds));
  };

  const [seconds, setSeconds] = useState(getRemainingSeconds);

  useEffect(() => {
    setSeconds(getRemainingSeconds());
    const iv = setInterval(() => setSeconds(getRemainingSeconds()), 1000);
    return () => clearInterval(iv);
  }, [detectionTs]);

  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
};
