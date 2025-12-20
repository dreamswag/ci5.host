# ci5.host // The Laboratory

This is the **Forensic Layer** of the Ci5 project. 

While `ci5.dev` provides the tools, `ci5.host` provides the **Truth**. This repository contains the scripts necessary to run "Corks" in a high-security sandbox to verify their "Tangible Change Profile."

### Why this exists:
1. **Zero Trust:** Never trust a community-submitted Cork without seeing its diff.
2. **Overlay Integrity:** Because OpenWrt uses an `/overlay` filesystem, we can track every single byte written to your Pi 5 in real-time.
3. **Network Crumple Zones:** Audited Corks are trapped in `br-audit`, a bridge with no route to your LAN.

### Usage:
Run the auditor directly on your Ci5-powered Raspberry Pi 5:
```bash
curl ci5.host/audit | sh -s [name-of-cork]