# CADT Cyber Security Project

## Quick Overview

This repository contains a paired demonstration: a simulated hybrid malware (`chimera_real.py`) and a host-based defense system (`aegis_real.py`), plus a simple command-and-control server (`c2_server.py`). All material is intended for controlled, educational use in isolated virtual machines.

### Core Project Files

1. **`chimera_real.py`** - Simulated ransomware/wiper/exfiltration payload (Red Team artifact)
2. **`aegis_real.py`** - Host-based defense and detection system (Blue Team artifact)
3. **`c2_server.py`** - Simple TCP-based Command & Control server (Attacker infrastructure)

### Documentation & User Guide

- **`DOCUMENTATION.md`** — In-depth documentation, architecture, and learning objectives.
- **`USER_GUIDE.md`** — Step-by-step user guide for setup, demo scenarios, and troubleshooting.

## Quick Start (High-level)

### ⚠️ CRITICAL WARNING
**Run these demos ONLY in isolated virtual machines on networks you control. Do not run on production or personal machines.**

### Setup Summary

1. **Attacker Machine (Kali Linux)** — start the C2 server:
```bash
cd /home/kali/Demo
python3 c2_server.py
```

2. **Victim Machine (Windows VM)** — install requirements and run defense first:
```powershell
# Open Command Prompt as Administrator
pip install cryptography watchdog psutil

# Start defense (keep running)
python aegis_real.py

# In a separate terminal, run malware for demo purposes
python chimera_real.py
```

## What You'll Learn

- Ransomware encryption and persistence techniques
- System corruption (wiper) concepts
- Data exfiltration and C2 interaction
- Host-based detection approaches and automated responses

## Current Project Status (Leader Overview)

- **Total techniques required (course deliverable):** 12 (6 malicious techniques + 6 anti-malicious techniques)
- **Implemented so far:** ~5 techniques (Registry Run Key, Scheduled Task persistence, USB replication, Registry watchdog, USB auto-scan)
- **Estimated completion:** ~40%

**Notes for the team leader:**
- Prioritize adding the remaining core functions: Hosts-file wiper, data exfiltration (read first 100 bytes and send to C2), and heuristic encryption detection.
- Next integration priorities: HTML smuggling & LNK delivery (for Red Team deliverables), Magic number analysis & script deobfuscation (for Blue Team deliverables), and SMB spread/monitoring.

## Leader Action Plan (next sprint)

- Integrate missing malicious core functions into `chimera_real.py` (wiper, exfiltration)
- Implement heuristic encryption detection and hosts-file integrity restore in `aegis_real.py`
- Add SMB spreading module and corresponding SMB-based defenses
- Test and validate all modules in an isolated VM network; capture logs and prepare the demo script

## Project Structure

```
Project/
├── DOCUMENTATION.md      # Comprehensive documentation
├── USER_GUIDE.md         # Complete user guide and demo steps
├── README.md             # This file (summary + leader plan)
├── chimera_real.py       # Malicious code (Red Team)
├── aegis_real.py         # Defense system (Blue Team)
└── c2_server.py          # C2 server (Attacker infra)
```

## Quick Links

- Read the full user guide: `USER_GUIDE.md`
- Read the full documentation: `DOCUMENTATION.md`

## Demo & Usage Notes

- Use the step-by-step scenarios in `USER_GUIDE.md` for the demo flow. The user guide contains commands, expected outputs, and troubleshooting steps.

## Safety Reminders

1. ✅ **Virtual Machines Only** — Never run on production systems.
2. ✅ **Network Isolation** — Use host-only or NAT networks.
3. ✅ **Snapshots** — Take VM snapshots before testing.
4. ✅ **Authorization** — Only test on systems you control and with permission.
5. ✅ **Ethical Use** — This material is for learning and research only.

## Getting Help

- Check inline comments and docstrings inside the Python files for implementation details.
- Use `DOCUMENTATION.md` for architecture and rationale.
- Use `USER_GUIDE.md` for hands-on demo steps and troubleshooting.

## License & Date

Educational use only. Created for CADT Cyber Security Course.

**Date**: November 28, 2025

---

If you'd like, I can also:
- Add a short changelog section to this README
- Generate a simple Gantt/sprint plan for the remaining tasks
- Create a `requirements.txt` for reproducible installs

Tell me which of these you want next and I will proceed.

## Safety Reminders

1. ✅ **Virtual Machines Only** - Never run on real systems
2. ✅ **Network Isolation** - Use isolated VM networks
3. ✅ **Snapshots** - Take VM snapshots before testing
4. ✅ **Authorization** - Only test on systems you own
5. ✅ **Ethical Use** - Educational purposes only

## Getting Help

All code is now thoroughly commented. To understand:
- **What each line does**: Read inline comments
- **How systems work**: Read function docstrings
- **Overall architecture**: Read `DOCUMENTATION.md`
- **Attack flow**: See sequence diagrams in documentation

## License

Educational use only. Created for CADT Cyber Security Course.

**Date**: November 28, 2025

---

**Remember**: With great knowledge comes great responsibility. Use ethically! 🛡️
# Cyber-Security-Project
