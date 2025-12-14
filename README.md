# CADT Cyber Security Project - FULLY INTEGRATED

## 🎓 Educational Cybersecurity Demonstration

This repository contains a **fully integrated** Red Team vs Blue Team demonstration featuring complete malware attack chains and comprehensive defense mechanisms. All material is intended for controlled, educational use in isolated virtual machines.

**Version 2.0 - Full Team Integration Complete (December 13, 2025)**

---

## 📋 Quick Overview

### Core Project Files

1. **`chimera_real.py`** - **INTEGRATED RED TEAM SOLUTION**
   - Complete malware suite with all attack techniques
   - Includes modules from 3 Red Team specialists (Puleu, Homey, Kimkheng)
   - Features: Delivery, Persistence, Lateral Movement, Ransomware, Wiper, Spyware, C2

2. **`aegis_real.py`** - **INTEGRATED BLUE TEAM SOLUTION**
   - Complete defense system with multi-layer protection
   - Includes modules from 3 Blue Team specialists (Sakura, Titya, Vicheakta)
   - Features: Anti-Delivery, Anti-Persistence, Anti-Spreading, Behavioral Detection

3. **`c2_server.py`** - Command & Control server (Attacker infrastructure)

### Documentation

- **`DOCUMENTATION.md`** — In-depth technical documentation and architecture
- **`USER_GUIDE.md`** — Step-by-step setup and usage instructions

---

## 🚀 Quick Start Guide

### ⚠️ CRITICAL WARNING
**Run these demos ONLY in isolated virtual machines on air-gapped networks. Do NOT run on production systems or personal machines.**

### Prerequisites

- **Attacker VM**: Kali Linux (for C2 server)
- **Victim VM**: Windows 10/11 (for malware & defense demo)
- **Network**: Isolated virtual network (no internet access)
- **Python**: 3.8+ with pip installed

### Setup Summary

#### 1. Install Dependencies (Windows VM)

```powershell
# Open Command Prompt as Administrator
pip install cryptography watchdog psutil pywin32
```

#### 2. Start C2 Server (Kali Linux)

```bash
cd /path/to/project
python3 c2_server.py
```

#### 3. Run Defense System (Windows VM - Terminal 1)

```powershell
# Keep this terminal running
python aegis_real.py
```

#### 4. Run Malware (Windows VM - Terminal 2)

```powershell
# For demonstration purposes only
python chimera_real.py
```

---

## 📚 What You'll Learn

### Red Team Techniques (MITRE ATT&CK)
- **Initial Access**: HTML smuggling, LNK file generation
- **Persistence**: Registry Run keys, Scheduled Tasks
- **Lateral Movement**: USB worm replication, SMB propagation
- **Impact**: File encryption (ransomware), System corruption (wiper)
- **Exfiltration**: Document stealing, Data exfiltration
- **Command & Control**: C2 communication, Remote command execution

### Blue Team Techniques (MITRE D3FEND)
- **File Analysis**: Magic number detection, Signature scanning
- **Script Analysis**: HTML smuggling detection, Obfuscation detection
- **Behavioral Detection**: Heuristic ransomware detection
- **Integrity Monitoring**: Hash-based file protection
- **Network Filtering**: C2 blocking, SMB traffic monitoring
- **Quarantine**: Automated threat isolation

---

## 🏗️ Project Architecture

### INTEGRATED RED TEAM (`chimera_real.py`)

#### Core Malware
- **Ransomware**: AES-256 file encryption with ransom notes
- **Wiper**: System corruption (hosts file, shadow copies, Defender)
- **Spyware**: Document exfiltration, system reconnaissance
- **C2 Communication**: Remote command execution, Status reporting

#### Integrated Modules

**Puleu - Delivery Specialist**
- HTML Smuggling (3 phishing templates: DHL, Invoice, Office365)
- LNK Generation (4 variants: Classic, RTLO, Word/Excel disguise)
- PowerShell download cradles

**Homey - Persistence Specialist**
- Registry Persistence (Multiple Run key locations)
- Scheduled Task Persistence (Multi-trigger tasks)
- Stealth techniques (hidden tasks, disguised names)

**Kimkheng - Lateral Movement Specialist**
- USB Worm Replication (Autorun, hidden folders, decoys)
- SMB Lateral Movement (Network discovery, Share enumeration, WMI execution)

### INTEGRATED BLUE TEAM (`aegis_real.py`)

#### Core Defense
- **Heuristic Encryption Detection**: Behavioral ransomware detection
- **File Integrity Monitor**: Hash-based system file protection
- **Network Egress Filtering**: C2 communication blocking

#### Integrated Modules

**Sakura - Anti-Delivery Specialist**
- **DeliveryThreatAnalyzer**: Unified file signature + HTML smuggling analysis
- **AntiDeliverySystem**: Download folder monitoring and automatic quarantine

**Titya - Anti-Persistence Specialist**
- **RegistryWatchdog**: Monitors registry Run keys, detects and removes malicious entries
- **TaskAuditor**: Enumerates scheduled tasks, detects and deletes suspicious tasks
- Perfect 1:1 defense against Homey's RegistryPersistence and ScheduledTaskPersistence

**Vicheakta - Anti-Spreading Specialist**
- SMB Monitor (Port 445 traffic blocking)
- USB Sentinel (Removable drive scanning)
- Network propagation prevention

---

## 🎯 Current Project Status (v2.0 - FULLY INTEGRATED)

✅ **COMPLETED:**
- Full Red Team integration (Puleu, Homey, Kimkheng)
- Full Blue Team integration (Sakura, Titya, Vicheakta)
- Comprehensive inline documentation
- MITRE ATT&CK & D3FEND mapping
- Modular architecture with clean integration points
- Error-free validation

✅ **ALL FEATURES OPERATIONAL:**
- Delivery methods (HTML smuggling, LNK generation)
- Persistence mechanisms (Registry, Scheduled Tasks)
- Lateral movement (USB, SMB)
- Anti-delivery protection
- Anti-persistence monitoring
- Anti-spreading defenses

---

## 👥 Team Contributions

### Red Team
- **Puleu**: Delivery Specialist (HTML Smuggling, LNK Generation)
- **Homey**: Persistence Specialist (Registry, Scheduled Tasks)
- **Kimkheng**: Lateral Movement Specialist (USB Worm, SMB Propagation)

### Blue Team
- **Sakura**: Anti-Delivery Specialist (Delivery Threat Analyzer, Anti-Delivery System)
- **Titya**: Anti-Persistence Specialist (Registry Watchdog, Task Auditor)
- **Vicheakta**: Anti-Spreading Specialist (SMB Monitor, USB Sentinel)

---

## 📖 Additional Documentation

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
