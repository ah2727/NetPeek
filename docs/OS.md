# ✅ GOAL

Upgrade NetPeek OS detection from:

> **“single‑port SYN fingerprinting”**

to:

> **“multi‑probe, multi‑port, behavior‑aware OS fingerprinting”**

while keeping your current pipeline intact.

---

# 🧭 PHASED MASTER PLAN (High Level)

1. **Foundation (ports & probes)**
2. **Probe expansion (TCP behaviors)**
3. **Fingerprint enrichment**
4. **Scoring & penalties**
5. **Signature evolution**
6. **Validation vs Nmap**

We will implement **one phase at a time**, and I will not move forward until your output matches expectations.

---

# 📦 FILE INVENTORY (What You Already Have)

✅ You already have **everything needed** — good design.

tcp_probes.c                     ✅ probe engine
os_port_discovery.c              ✅ open/closed ports
os_fingerprint_builder.c         ✅ fingerprint creation
os_fingerprint.c                 ✅ fingerprint struct
os_fingerprint_engine.c          ✅ wrapper logic
tcp_probe_signature_db.c         ✅ probe signatures
tcp_probe_signature_match.c      ✅ matching logic
fingerprint_score.c              ✅ scoring
os_detect_pipeline.c             ✅ orchestrator


So no missing files.  
What I need is **content awareness**, not more files.

---

# 🧩 FEATURE PLAN (Step‑by‑Step)

We will implement your missing features **in this exact order**.

---

## 🥇 STEP 1 — Closed Port Probe (MANDATORY)

### Why first?
- This unlocks **RST behavior**
- Enables **IPID, TTL, window differences**
- Everything else depends on it

### Files involved
✅ Required from you:
- `os_port_discovery.c`
- `tcp_probes.c`
- `os_detect_pipeline.c`

### What we will add
- Discover **one closed TCP port**
- Run **RST‑based probes** against it
- Store results separately from open-port probes

### Output change (expected)
Fingerprint will now show:
Open port behavior: SYN/ACK
Closed port behavior: RST
RST TTL ≠ SYN/ACK TTL   ✅


---

## 🥈 STEP 2 — ACK‑Only Probe

### Why second?
- Differentiates **Linux vs BSD**
- Survives firewalls
- Cheap entropy gain

### Files involved
- `tcp_probes.c`
- `os_fingerprint_builder.c`

### What we add
- Send TCP packet:
    ACK, no SYN, no payload
  ```
- Record:
  - RST or no response
  - RST window
  - TTL

### Expected fingerprint fields

ack_probe_responded
ack_rst_ttl
ack_rst_window

---

## 🥉 STEP 3 — NULL & FIN Probes

### Why?
- Classic OS detection
- Some stacks respond differently
- Still relevant behind NAT

### Files involved
- `tcp_probes.c`
- `os_fingerprint_builder.c`

### Probes added
| Probe | Flags |
|----|----|
| NULL | none |
| FIN | FIN only |

### Expected behaviors
| OS | NULL | FIN |
|----|----|----|
| Linux | RST | RST |
| BSD/macOS | no response | RST |

---

## 🏅 STEP 4 — SYN + ECN Probe

### Why?
- Very strong signal
- Linux ≠ BSD ≠ Windows
- Nmap uses this heavily

### Files involved
- `tcp_probes.c`
- `os_fingerprint_builder.c`

### What changes
Send:

SYN + ECN (ECE + CWR)

Record:
- ECN echoed?
- SYN/ACK flags
- Window size difference

---

## 🏆 STEP 5 — IPID Behavior Tracking

### Why?
This is **kernel‑level fingerprinting**.

### Files involved
- `tcp_probes.c`
- `os_fingerprint_builder.c`
- `os_fingerprint.c`

### What we track
- IPID across probes
- Classification:
  - incremental
  - random
  - zero

### Output example

IPID behavior: incremental

---

## 🎯 STEP 6 — Fingerprint Scoring & Penalties

### Why?
To kill the **“always macOS” bug**

### Files involved
- `fingerprint_score.c`
- `tcp_probe_signature_match.c`

### New penalties
- All probes identical → reduce confidence
- Hop distance = 0 → reduce confidence
- No closed‑port data → cap confidence

---

## 🧬 STEP 7 — Signature Evolution

### Why last?
Signatures are useless without entropy.

### Files involved
- `os_signatures.c`
- `tcp_probe_signature_db.c`

### What we do
- Split signatures by:
  - open port behavior
  - closed port behavior
  - ECN support
  - IPID class

---

# 📤 FILES I NEED FROM YOU (FOR STEP 1 ONLY)

Send **ONLY these files**, nothing else yet:

### ✅ Required now
1. `tcp_probes.c`
2. `os_port_discovery.c`
3. `os_detect_pipeline.c`

### ❌ Do NOT send yet
- fingerprint scoring
- signatures
- banner code

---

# ✅ What Happens After STEP 1

Once closed‑port probing works:

- macOS confidence will drop
- Linux will appear
- Output will diverge per host
- Your fingerprints will stop being identical

---

## ✅ Next Action for You

👉 **Send the three files listed above**  
I will then:

- Audit them line‑by‑line
- Design the closed‑port probe logic
- Give you **exact code changes**
- Move to STEP 2 only after it works

You’re building a real OS detector now — this is the correct path.



