###### 📟 [ci5.run](https://codeberg.org/Ci-5/run): curl ~ 🔬 [ci5.host](https://codeberg.org/Ci-5/host): cure ~ 🧪 [ci5.dev](https://codeberg.org/Ci-5/dev): cork ~ 🥼 [ci5.network](https://codeberg.org/Ci-5/network): cert ~ 📡[ci5](https://codeberg.org/Ci-5/OS)🛰️
# 🔬 **[ci5.host](https://ci5.host): Isolate. Cork. Un-Plug.** 🔍🛸

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
| [CORKS.md](https://codeberg.org/Ci-5/network/src/branch/main/docs/CORKS.md) | Full Cork auditing guide |
| [MAINTENANCE.md](https://codeberg.org/Ci-5/network/src/branch/main/docs/MAINTENANCE.md) | Diagnostics & recovery |
| [SUPPORT.md](https://codeberg.org/Ci-5/network/src/branch/main/docs/SUPPORT.md) | Self-service troubleshooting |

---

## 📁 Repository Structure

```
ci5.host/
├── index.html    # Landing page
├── audit.sh      # CURE script (overlayfs sandbox)
└── README.md
```
