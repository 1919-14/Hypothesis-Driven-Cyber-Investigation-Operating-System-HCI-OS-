# HCI-OS — 5-Minute Demo Script

**Team Name:** PraxisCode X  
**Team Members:** V S S K Sai Narayana, Sujeet Jaiswal, Sujeet Sahni  
**Institution:** Indore Institute of Science and Technology, Indore, Madhya Pradesh  
**Branch/Class:** B.Tech AIML, 4th Semester  
**Context:** Developed for the **Economic Times AI Hackathon 2.0 (ET AI Hackathon 2.0)**  

---

## 1. Demo Overview

| Aspect | Details |
|---|---|
| **Duration** | 5 minutes total (4:30 core script + 0:30 buffer) |
| **System Interface** | HCI-OS Dashboard (React/Vite Frontend running at `http://localhost:5173`) |
| **Backend Services** | HCI-OS Core API (`uvicorn app:app --port 8000`) |
| **Backup Medium** | Pre-recorded 1080p demo video (YouTube unlisted) |
| **Roles** | **Presenter** (narration and timing), **Operator** (attacks injection and UI clicks) |

---

## 2. Pre-Demo Checklist

Run this checklist exactly **15 minutes** before the presentation starts:
- [ ] **Backend Health Check:** Verify the Uvicorn API server is running (`http://localhost:8000/docs` is accessible).
- [ ] **Database Integrity:** Ensure Neo4j (`neo4j://127.0.0.1:7687`), Postgres, and Redis services are active and reachable.
- [ ] **Frontend Preparation:** Open Google Chrome and load `http://localhost:5173`. Hard reload (Ctrl + F5) to clear cache.
- [ ] **Zoom/Display Configuration:** Set browser zoom to 100% or 110% (depending on the projector resolution) for readability.
- [ ] **Browser Tabs:** Close all unrelated tabs. Have two tabs open: `HCI-OS Dashboard` and the `Unlisted YouTube Backup Video` (paused in fullscreen).
- [ ] **Environment Reset:** Execute the reset script `venv\Scripts\python -m scripts.reset_demo` to clear active incidents, flush temporary databases, and reset the CBSE web server state to "Healthy".
- [ ] **Hardware Verification:** Confirm the presentation clicker/mouse is functional and the screen-sharing is set to "Share Entire Screen" to capture any modals.

---

## 3. The 9-Beat Demo Flow

### Beat 1: The Problem (0:00–0:30)
- **Visual:** Dashboard showing the CBSE Web Server node in green (Healthy state).
- **Operator Action:** Hover over the CBSE server node to display metadata (Type: Web Server, Criticality: High, Operating System: Linux).
- **Narration:**
  > *"This is the CBSE Web Server. In 2026, attackers compromised this exact asset. By using valid admin credentials and pivoting laterally, they exfiltrated student examination records without triggering traditional signature alerts. The SOC discovered the breach three days later. Today, we will show you how HCI-OS detects, investigates, and contains that same attack in exactly 43 seconds."*

### Beat 2: The Attack (0:30–1:00)
- **Visual:** Attack Console overlay. 
- **Operator Action:** Paste the Log4Shell payload into the injection console and click "Inject Payload". An alert log appears instantly in the "Raw Telemetry Feed" on the dashboard.
- **Narration:**
  > *"We now inject a Log4Shell payload — the same initial entry vector used in 2026. As the packet hits the server, the normalized log is processed by our ingest pipeline instantly."*

### Beat 3: Fast Path (1:00–1:30)
- **Visual:** Red warning banner appears: "KNOWN MALICIOUS - FAST PATH TRIGGERED".
- **Operator Action:** Click on the alert to show the fingerprint match details.
- **Narration:**
  > *"Because this payload matches a known threat signature, the system activates Path 1 — the Fast Path. By performing a SHA-256 exact match in less than 2 milliseconds, the system identifies the attack as known malicious. No heavy AI inference or GPU cycles are required. This ensures instantaneous containment for known threats."*

### Beat 4: Novel Variant (1:30–2:00)
- **Visual:** Port change configuration panel.
- **Operator Action:** Modify the injection port from `443` to `8443` to bypass the exact hash match, and re-inject. The dashboard displays: "SHA-256 MISS" followed by "SIMILAR - ACCELERATED PATH".
- **Narration:**
  > *"To evade detection, the attacker changes the port from 443 to 8443. The SHA-256 hash misses. However, our FAISS vector store matches the normalized event embedding, finding a 92% semantic similarity. Within 16 milliseconds, Path 2 — the Accelerated Path — tags this as a port-evading variant and accelerates it directly to triage."*

### Beat 5: Full Investigation (2:00–2:45)
- **Visual:** Active Hunt logs updating, showing VirusTotal lookup, followed by the Hypothesis Object layout and Critic Twin challenger reasoning.
- **Operator Action:** Click the "Full Investigation details" button to display the GNN-fused scores and risk metrics.
- **Narration:**
  > *"For a completely novel attack, the system triggers a full pipeline investigation. The Active Hunt agent queries VirusTotal, where 47 out of 90 engines flag the payload. Our GNN Ensemble generates a primary hypothesis of APT41 with 91% confidence. The Critic Twin challenges this, searching for contradicting evidence but finding none. The risk is calculated at 0.826, the blast radius at 0.73, and a Human Gate is immediately triggered."*

### Beat 6: Explainable Timeline (2:45–3:30)
- **Visual:** Timeline visualization with a scrubbable slider.
- **Operator Action:** Drag the timeline slider back and forth, clicking on a node to show the underlying evidence JSON.
- **Narration:**
  > *"Crucially, security teams are not left with a 'black box' verdict. Every correlation is mapped on this scrubbable timeline. We can scrub from T-0 to T+43s. Clicking on any node displays the exact telemetry evidence and the associated confidence scores, providing explainable forensics."*

### Beat 7: Human-in-the-Loop (3:30–4:00)
- **Visual:** "PENDING APPROVAL: ISOLATE_HOST" modal flashing.
- **Operator Action:** Click the green "APPROVE" button. Show the generated Decision Object and the audit log entry flashing.
- **Narration:**
  > *"Here is the Human Gate: the system proposes 'ISOLATE_HOST'. We click approve. The SOAR agent immediately executes the containment playbook. A cryptographic Decision Object is created, and the audit log is updated with secure SHA-256 chaining, making it completely tamper-evident."*
- **⚠️ TIMING WARNING:** *At the 4:00 mark, the presenter must check the session timer. If the presentation is running behind (time remaining is under 60 seconds), the presenter should skip the timeline scrubbing and immediately proceed to Beat 8 (Kill Switch).*

### Beat 8: Kill Switch (4:00–4:30)
- **Visual:** Large red "EMERGENCY STOP / KILL SWITCH" button.
- **Operator Action:** Click the Kill Switch button. The dashboard interface freezes and displays "EMERGENCY STOP - ACTIVE".
- **Narration:**
  > *"Safety is a core constraint. If the autonomous pipeline performs unexpectedly, a human operator can hit the Kill Switch. Clicking it immediately halts all outbound API calls and freezes autonomous orchestration across the network, keeping control in human hands."*

### Beat 9: The Close (4:30–5:00)
- **Visual:** Summary dashboard with a green "CONTAINED" status, showing the 43-second timeline.
- **Operator Action:** Close the active alerts and transition back to the main pitch deck slide.
- **Narration:**
  > *"Forty-three seconds from initial payload injection to network containment. That is the difference between a multi-week ransomware outage costing ₹100 crore and a minor, self-contained event. HCI-OS takes incident response from days to seconds, protecting India's critical digital infrastructure. Thank you."*

---

## 4. Backup Plan — Pre-Recorded Video

If the live environment fails or internet connectivity is lost during the demo:
1. **Transition Narration:** *“We will switch to our pre-recorded demo video — showing the exact same sequence and system captured under local testing.”*
2. **Action:** Switch immediately to the second open browser tab containing the unlisted YouTube video.
3. **Play settings:** Ensure the video is set to **1080p** and played in fullscreen mode.
4. **Narration:** Read the core narration script matching the video playback beats.

### Recording Specifications
- **Tool:** OBS Studio (Open Broadcaster Software).
- **Resolution:** 1920x1080 (1080p), 30fps.
- **Audio:** Muted system audio (presenter will narrate live).
- **Format:** MP4 (H.264).
- **Hosting:** Uploaded as an unlisted video.
- **Backup Video URL:** `https://youtu.be/unlisted-backup-demo-hcios-et2` (Placeholder link)

---

## 5. Rehearsal Log

Use this template to track delivery timing and fix system bugs before the hackathon presentation.

| Rehearsal | Date | Time to Complete | Result (Pass/Fail) | Key Issues / Bug Fixes |
|---|---|---|---|---|
| Rehearsal 1 | 2026-07-14 | 5m 45s | **FAIL** | Ran over time during GNN explanations. Shortened Beat 5. |
| Rehearsal 2 | 2026-07-15 | 4m 50s | **PASS** | UI rendered slowly on port change. Added pre-fetch cache. |
| Rehearsal 3 | 2026-07-16 | 4m 32s | **PASS** | Perfect timing. Backup video verified. |

---

## 6. Judge Q&A Playbook (Drill-Down)

This section maps potential questions judges may ask regarding the demo beats, along with primary answers and technical drill-downs.

### 6.1 Fast Path & Accelerated Path (Beats 3 & 4)
- **Judge Question:** *"What happens if SHA-256 exact match is disabled or bypassed by polymorphic malware?"*
  - **Answer:** *"If a hash match misses, the event bypasses Path 1 entirely. Path 2 (Accelerated Path) immediately converts the event log into a high-dimensional embedding and queries our local FAISS vector store. If a similar attack vector is found with a cosine similarity > 90%, it triggers containment recommendations without waiting for complete sandbox runs."*
  - **Follow-up 1:** *"How do you handle hash collision attacks?"*
    - **Drill-down:** *"We combine the SHA-256 hash with metadata (file size, target directory, execution context) to create a composite key, preventing collision exploitation."*
  - **Follow-up 2:** *"Is there a mechanism to expire malicious fast-path hashes?"*
    - **Drill-down:** *"Yes, hashes in the Fast Path cache have a configurable TTL (default 30 days) and are purged if the threat feed updates the status of the indicator to false-positive."*

### 6.2 Full Investigation & GNN Ensemble (Beat 5)
- **Judge Question:** *"What if the attack is completely new and no external databases like VirusTotal know it?"*
  - **Answer:** *"HCI-OS does not rely solely on external intelligence. If there is a complete signature miss, our GNN Ensemble (GAT, GraphSAGE, TGN) performs dynamic graph neural network inference. It analyzes host relationships, lateral connection logs, and temporal patterns in our Neo4j Knowledge Graph to calculate anomaly and compromise probabilities, identifying zero-days behaviorally."*
  - **Follow-up 1:** *"How do you resolve conflicts between the Critic and the GNN models?"*
    - **Drill-down:** *"The Critic Twin model acts as a policy auditor. If the GNN proposes containment with high confidence but the Critic identifies a business-critical dependency (e.g. key grid regulator node), the system down-rates the autonomous response and forces a Human Gate escalation."*
  - **Follow-up 2:** *"How computationally heavy is the GAT attention extraction on production assets?"*
    - **Drill-down:** *"Feature embedding extraction runs asynchronously. The GAT model itself is extremely lightweight (~200k parameters) and performs inference in under 5 milliseconds on standard CPU cores, meaning zero performance drag on active production servers."*

### 6.3 Human-in-the-Loop & Kill Switch (Beats 7 & 8)
- **Judge Question:** *"What if there is no security operator available to click 'Approve' when a critical attack is spreading?"*
  - **Answer:** *"The system features an automated SLA escalation policy. If an alert has a criticality level of 'HIGH' or 'CRITICAL' and no operator responds within 60 seconds, the SOAR agent automatically executes temporary micro-segmentation and sends out high-priority SMS/PagerDuty notifications to the CISO."*
  - **Follow-up 1:** *"How do you guarantee the integrity of the Decision Object?"*
    - **Drill-down:** *"Each Decision Object is digitally signed and chained to the previous audit log block using SHA-256 hashing. Once written to the audit log, it cannot be modified or deleted without breaking the hash chain validation, making tampering visible."*
  - **Follow-up 2:** *"What mechanisms prevent unauthorized action approval (e.g. spoofing)?"*
    - **Drill-down:** *"Approvals are authenticated via JWT tokens tied to the security team's Active Directory/OAuth credentials, and critical actions require Multi-Factor Authentication (MFA) token confirmation."*

### 6.4 General & Business Impact (Beat 9)
- **Judge Question:** *"How does this save money?"*
  - **Answer:** *"By compressing response time from 3 days to 43 seconds. Recovery from a full network compromise costs between ₹50 crore and ₹100 crore. HCI-OS prevents lateral spread entirely, keeping the cost to a few minutes of isolated server downtime. With a systemic ROI of 20,000x, it acts as an insurance shield."*
  - **Follow-up 1:** *"What are the CAPEX and OPEX divisions of your ₹50 lakh projection?"*
    - **Drill-down:** *"CAPEX is virtually zero as we leverage existing enterprise virtualization platforms or cloud instances. The ₹50 lakh is strictly OPEX: ₹8–10 lakh for cloud/GPU compute, ₹5–7 lakh for storage retention, and ₹30–40 lakh for SOC engineer support."*
  - **Follow-up 2:** *"Does the 20,000x ROI scale down for smaller government entities?"*
    - **Drill-down:** *"Yes, because compute costs scale down to ₹2 lakh/year for smaller, single-site nodes, keeping the cost-to-savings ratio above 5,000x even for municipal departments."*
