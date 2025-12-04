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

## Current Project Status (Enhanced v2.0)

- **Total techniques required (course deliverable):** 12 (6 malicious techniques + 6 anti-malicious techniques)
- **Implemented:** 12/12 techniques ✅
- **Completion:** 100% 🎉
- **Latest Version:** v2.0 (Enhanced Protection)

**Recent Enhancements (v2.0):**
- ✅ **Aegis Defense Enhanced**: Now ACTIVELY STOPS ransomware (not just monitors)
- ✅ **Improved Detection**: Lower threshold (>2 files in 2 seconds vs >3 in 1 second)
- ✅ **Enhanced Termination**: 3-stage kill process (terminate → kill → SIGKILL)
- ✅ **Persistent Encryption Key**: Consistent key across malware restarts for reliable decryption
- ✅ **Multi-format Decryption**: Supports URL-safe base64 and automatic format detection
- ✅ **Faster Response**: 300ms scan interval (was 500ms) for quicker threat detection

**All Core Functions Integrated:**
- ✅ Ransomware, Wiper, Spyware (chimera_real.py)
- ✅ Heuristic Detection, File Integrity, Network Filtering (aegis_real.py)
- ✅ C2 Communication with remote command execution
- ✅ HTML smuggling, LNK delivery, Registry/Task persistence
- ✅ USB/SMB propagation and corresponding defenses
- ✅ Ready for production demonstration

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

## Version History

**v2.0 (December 4, 2025)** - Enhanced Protection Release
- Aegis defense now actively stops ransomware (not just monitors)
- Improved detection threshold and 3-stage termination
- Persistent encryption key with multi-format decryption support
- Faster scan intervals for quicker threat response

**v1.0 (November 28, 2025)** - Initial Release
- Complete malware suite with C2 communication
- Basic defense system with monitoring capabilities
- All 12 required techniques implemented

## License

Educational use only. Created for CADT Cyber Security Course.

**Date**: December 4, 2025

---

**Remember**: With great knowledge comes great responsibility. Use ethically! 🛡️
# Cyber-Security-Project
