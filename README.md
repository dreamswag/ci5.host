###### 📟 [ci5.run](https://github.com/dreamswag/ci5.run): curl ~ 🔬 [ci5.host](https://github.com/dreamswag/ci5.host): cure ~ 🧪 [ci5.dev](https://github.com/dreamswag/ci5.dev): cork ~ 🥼 [ci5.network](https://github.com/dreamswag/ci5.network): cert ~ 📡[ci5](https://github.com/dreamswag/ci5)🛰️
# 🔬 [ci5.host](https://github.com/dreamswag/ci5.host): Isolated Cork Inspection 🔍🛸

This repository provides the **Forensic Laboratory** for the Ci5 project. 

## 💾 The Problem:
**On standard Raspberry Pi 5 images (ext4), there is no read-only safety net.** 
* If a Docker container (Cork) escapes its sandbox, it can permanently:
    *   modify your router's configuration (`/etc/config`)
    *   install backdoors
    *   ruin your packet discipline.

## 🩻 The Solution: Ephemeral Overlays 
The `cure` script uses the Linux kernel's `overlayfs` to create a temporary, RAM-based "Shadow FS." 
- **Lowerdir:** Your real, permanent ext4 filesystem.
- **Upperdir:** A volatile 50MB RAM-disk (`tmpfs`).
- **Merged:** What the Cork sees.

* When the audit runs, the Cork is given a "Shadow View" of your router: 
 * If it tries to modify a file, the change is written to the RAM-disk.
    * The script then diffs the RAM-disk to reveal exactly what the Cork tried to do to your host.

## 💉 Usage
To audit a community cork:
```bash
curl ci5.host/audit | sh -s community-cork-name
