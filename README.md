###### 📟 [ci5.run](https://github.com/dreamswag/ci5.run): curl ~ 🔬 [ci5.host](https://github.com/dreamswag/ci5.host): cure ~ 🧪 [ci5.dev](https://github.com/dreamswag/ci5.dev): cork ~ 🥼 [ci5.network](https://github.com/dreamswag/ci5.network): cert ~ 📡[ci5](https://github.com/dreamswag/ci5)🛰️
# 🔬 **[ci5.host](https://ci5.host): Isolated Cork Un-Plug** 🔍🛸

## 🧬 Purpose

**Forensic sandbox for Cork auditing:**

* On standard ext4, containers can escape and modify your host. 
* The `cure` script uses ephemeral overlays to catch them in the act.

## 🩻 How It Works

```
┌─────────────────────────────────────────┐
│            OverlayFS Mount              │
├─────────────────────────────────────────┤
│  Upperdir (tmpfs/RAM)  ← Catches writes │
├─────────────────────────────────────────┤
│  Lowerdir (/etc)       ← Read-only      │
└─────────────────────────────────────────┘
```

1. Cork runs in RAM-backed shadow environment
2. Any host modification attempts are captured
3. Script diffs and reports: `SAFE` or `MALICIOUS`

## 💉 Usage

```bash
curl ci5.host/audit | sh -s cork-name
```

**Output:**
```
--- [Ci5 AUDIT: CURE MODE] ---
ID: a1b2c3d4e5f6 | Host: ext4-Sovereign

[Host Breakout Attempts]
 > CLEAN: No host configuration changes detected.

--- [AUDIT COMPLETE] ---
Result: SAFE
```

---

## 🚨 When to Use

| Scenario | Action |
|----------|--------|
| Installing community Cork | **Always audit first** |
| Post-install validation | Run `validate.sh` instead |
| Suspicious behavior | Audit + check logs |

---

## 📚 Documentation

| Doc | Purpose |
|-----|---------|
| [CORKS.md](https://github.com/dreamswag/ci5.network/blob/main/docs/CORKS.md) | Full Cork auditing guide |
| [MAINTENANCE.md](https://github.com/dreamswag/ci5.network/blob/main/docs/MAINTENANCE.md) | Diagnostics & recovery |
| [SUPPORT.md](https://github.com/dreamswag/ci5.network/blob/main/docs/SUPPORT.md) | Self-service troubleshooting |

---

## 📁 Repository Structure

```
ci5.host/
├── index.html    # Landing page
├── audit.sh      # CURE script (overlayfs sandbox)
└── README.md
```
