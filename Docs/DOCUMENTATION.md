# Cybersecurity Project Documentation
#
# Core Malicious & Anti-Malicious Methods

## Core Malicious Methods (chimera_real.py)

1. **File Encryption (Ransomware)**
   - Encrypts user files (.txt, .docx, .pdf, .jpg, etc.) using AES-256
   - Creates ransom notes and demands payment

2. **System Corruption (Wiper)**
   - Corrupts Windows hosts file to block security sites
   - Deletes shadow copies and disables Windows Defender (simulated)

3. **Data Exfiltration (Spyware)**
   - Steals system info and samples from documents
   - Sends stolen data to C2 server

## Core Anti-Malicious Methods (aegis_real.py)

1. **Heuristic Encryption Detection**
   - Monitors for rapid file modifications (high entropy writes)
   - Kills process if >3 files modified in 1 second

2. **System File Integrity Monitor**
   - Hashes and restores Windows hosts file if tampered

3. **Network Egress Filtering**
   - Monitors outbound traffic
   - Blocks unauthorized data exfiltration attempts

---

## Project Progress & Next Steps

**Techniques required:** 12 (6 malicious, 6 anti-malicious)
**Techniques implemented:** ~5/12

- Registry Run Key persistence (malicious)
- Scheduled Task persistence (malicious)
- USB worm propagation (malicious)
- Registry watchdog (anti-malicious)
- USB auto-scan (anti-malicious)

**Completion:** ~40%

**Next Steps:**
- Integrate missing core methods (wiper, exfiltration, heuristic detection)
- Add SMB worm and SMB traffic blocker
- Implement magic number analysis, script de-obfuscation, and task scheduler audit
- Test and validate all modules in isolated VM network
- Update documentation and prepare for demo

## Project Overview
This project is a **cybersecurity demonstration** consisting of three Python files that simulate a realistic malware attack scenario and defense system. This is designed for educational purposes to understand how malware works and how defense systems detect and neutralize threats.

**⚠️ WARNING: These files contain actual malicious code functionality. Use ONLY in isolated, controlled environments (virtual machines) for educational purposes.**

---

## File Descriptions

### 1. `chimera_real.py` - Ransomware Malware Simulator

**Purpose**: Simulates a sophisticated ransomware attack with multiple attack vectors including encryption, persistence, propagation, and data exfiltration.

#### Key Features:

##### **Persistence Mechanisms**
- **Registry Key Persistence**: Adds itself to Windows registry `Run` key to execute on every system startup
- **Scheduled Task Persistence**: Creates a Windows scheduled task that runs the malware every hour

##### **Propagation Methods**
- **USB Worm**: Automatically copies itself to any connected USB drive
- **Autorun Infection**: Creates `autorun.inf` files on USB drives for automatic execution when plugged into other systems
- **File Hiding**: Uses Windows `attrib` command to hide malicious files with system and hidden attributes

##### **Malicious Payloads**

1. **Ransomware Encryption**
   - Uses AES encryption via the `cryptography.fernet` module
   - Targets specific file extensions: `.txt`, `.docx`, `.pdf`, `.jpg`
   - Scans user folders: Documents, Desktop, Downloads
   - Renames encrypted files with `.chimera_encrypted` extension
   - Creates ransom note (`READ_ME_FOR_DECRYPT.txt`) demanding Bitcoin payment

2. **Data Exfiltration**
   - Steals system information (computer name, username, Windows version)
   - Searches for browser data locations (Chrome, Edge)
   - Saves stolen data locally

3. **Command & Control (C2) Communication**
   - Connects to remote C2 server (configured IP and port)
   - Sends victim information to attacker's server
   - Establishes botnet-style communication

#### Technical Details:
- **Language**: Python 3.x
- **Dependencies**: `cryptography` library for AES encryption
- **Target OS**: Windows (uses `winreg`, Windows-specific commands)
- **Network**: Socket-based TCP communication on port 4444

---

### 2. `aegis_real.py` - Defense & Detection System

**Purpose**: Real-time defense system that monitors, detects, and neutralizes malware threats including the Chimera ransomware.

#### Key Features:

##### **Process Monitoring**
- Continuously scans running processes every 5 seconds
- Detects known malware signatures by process name
- Automatically terminates malicious processes
- Monitors for: `chimera_real.exe`, `WindowsUpdate.exe`

##### **Registry Protection**
- Monitors Windows registry keys for persistence attempts
- Checks `Run` and `RunOnce` registry keys every 10 seconds
- Automatically removes suspicious registry entries
- Prevents malware from achieving persistence

##### **File System Monitoring**
- Real-time monitoring using `watchdog` library
- Detects suspicious file extensions (`.chimera_encrypted`)
- Scans protected folders: Documents, Desktop, Downloads
- File hash-based detection using MD5 checksums
- Automatically deletes detected malware files

##### **USB Protection**
- Monitors for newly connected drives (D: through Z:)
- Scans USB drives for malware when connected
- Removes malicious executables from USB devices
- Prevents USB-based worm propagation

##### **Alert System**
- Three-tier severity levels: MEDIUM, HIGH, CRITICAL
- Timestamped logging of all security events
- Color-coded console output (red alerts)
- Alert history maintained in memory

#### Technical Details:
- **Language**: Python 3.x
- **Dependencies**: `watchdog`, `psutil`
- **Target OS**: Windows (uses `winreg`, Windows-specific APIs)
- **Architecture**: Multi-threaded for concurrent monitoring

---

### 3. `c2_server.py` - Command & Control Server

**Purpose**: Simulates an attacker's Command & Control (C2) server that receives connections from infected machines (bots).

#### Key Features:

##### **Server Functionality**
- Listens on all network interfaces (`0.0.0.0`) on port 4444
- Handles multiple simultaneous bot connections
- Multi-threaded architecture for concurrent client handling
- Receives status messages from infected machines

##### **Communication Protocol**
- TCP socket-based communication
- Receives infection confirmation messages
- Sends acknowledgment responses
- Logs connection details (IP address, port)

#### Technical Details:
- **Language**: Python 3.x
- **Dependencies**: Built-in `socket` and `threading` modules
- **Network**: TCP server on port 4444
- **Scalability**: Thread-per-connection model

---

## System Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Victim Machine │◄────────┤   C2 Server      │────────►│ Attacker System │
│                 │  Port   │   (Kali Linux)   │         │                 │
│ chimera_real.py │  4444   │  c2_server.py    │         │   Dashboard     │
└─────────────────┘         └──────────────────┘         └─────────────────┘
         ▲
         │ Detects & Blocks
         │
┌────────┴────────┐
│ Defense System  │
│ aegis_real.py   │
└─────────────────┘
```

---

## Attack Flow Sequence

1. **Execution**: `chimera_real.py` runs on victim machine
2. **Persistence**: Establishes registry keys and scheduled tasks
3. **Propagation**: Infects USB drives with worm copies
4. **Data Theft**: Exfiltrates system information
5. **Encryption**: Encrypts target files with AES
6. **Ransom**: Creates ransom note demanding payment
7. **C2 Communication**: Connects to C2 server and reports infection
8. **Defense Response**: `aegis_real.py` detects and neutralizes threats

---

## Defense Detection Methods

| Attack Technique | Detection Method | Response Action |
|-----------------|------------------|-----------------|
| Process Execution | Process name scanning | Kill malicious process |
| Registry Persistence | Registry key monitoring | Delete malicious entries |
| File Encryption | File extension detection | Alert and quarantine |
| USB Propagation | Drive monitoring | Scan and clean USB |
| Hash Signatures | MD5 file hashing | Remove known malware |

---

## Configuration Parameters

### Chimera Malware
```python
TARGET_EXTENSIONS = ['.txt', '.docx', '.pdf', '.jpg']
C2_SERVER = "192.168.1.100"  # Update to your Kali IP
C2_PORT = 4444
```

### Aegis Defense
```python
KNOWN_MALWARE_SIGNATURES = ["chimera_real.exe", "WindowsUpdate.exe"]
SUSPICIOUS_EXTENSIONS = [".chimera_encrypted"]
PROTECTED_FOLDERS = ["Documents", "Desktop", "Downloads"]
```

### C2 Server
```python
SERVER_IP = "0.0.0.0"
SERVER_PORT = 4444
```

---

## Installation Requirements

### For Chimera & Aegis (Windows VM):
```bash
pip install cryptography psutil watchdog
```

### For C2 Server (Kali Linux):
```bash
# No additional packages needed - uses built-in libraries
python3 c2_server.py
```

---

## Usage Instructions

### ⚠️ IMPORTANT: Use only in isolated virtual machines!

#### Step 1: Setup C2 Server (Attacker Machine - Kali Linux)
```bash
python3 c2_server.py
```

#### Step 2: Configure Chimera
- Edit `C2_SERVER` variable with your Kali Linux IP address
- Save the file

#### Step 3: Run Defense System (Victim Machine - Windows VM)
```bash
python aegis_real.py
```

#### Step 4: Execute Malware (Victim Machine - Windows VM)
```bash
python chimera_real.py
```

#### Expected Results:
- Aegis will detect and terminate malicious processes
- Alerts will appear in red in the console
- Registry entries will be removed
- Encrypted files will be detected

---

## Educational Learning Objectives

### Students will understand:
1. **Malware Techniques**: How ransomware achieves persistence and spreads
2. **Encryption**: Practical application of AES encryption for malicious purposes
3. **Network Communication**: Client-server architecture in botnets
4. **Detection Methods**: Signature-based and behavior-based detection
5. **Incident Response**: Real-time threat neutralization

### Cybersecurity Concepts Demonstrated:
- ✓ Persistence mechanisms (Registry, Scheduled Tasks)
- ✓ Lateral movement (USB worm propagation)
- ✓ Data exfiltration techniques
- ✓ Cryptographic ransomware
- ✓ C2 infrastructure
- ✓ Multi-layered defense strategies
- ✓ Real-time threat monitoring
- ✓ Automated incident response

---

## Security Considerations

### ⚠️ CRITICAL WARNINGS:

1. **Never run on production systems** - These files contain real malicious functionality
2. **Use isolated VMs** - Always use virtual machines with network isolation
3. **Disable Windows Defender** - For testing purposes only in isolated environment
4. **Snapshot VMs** - Take VM snapshots before testing to restore clean state
5. **No real data** - Never test with personal or sensitive files
6. **Legal compliance** - Ensure you have authorization for any security testing

### Ethical Guidelines:
- ✓ Educational purposes only
- ✓ Controlled environment testing
- ✓ Proper authorization required
- ✗ Never deploy on unauthorized systems
- ✗ Never use for malicious intent
- ✗ Never distribute to untrusted parties

---

## Troubleshooting

### Chimera won't connect to C2:
- Verify C2 server is running
- Check firewall settings
- Confirm correct IP address in `C2_SERVER` variable
- Ensure port 4444 is not blocked

### Aegis not detecting threats:
- Run as Administrator
- Check if `psutil` and `watchdog` are installed
- Verify protected folders exist
- Check if processes are in signature list

### Permission errors:
- Run Python scripts as Administrator on Windows
- Some operations require elevated privileges

---

## Additional Resources

### Recommended Reading:
- MITRE ATT&CK Framework (Tactics and Techniques)
- Ransomware Defense Best Practices
- Cryptography in Cybersecurity
- Incident Response Playbooks

### Further Enhancements:
- Implement decryption functionality
- Add network traffic analysis
- Integrate machine learning detection
- Develop forensics logging
- Add sandbox analysis capabilities

---

## Disclaimer

This project is created strictly for **educational and research purposes** to help students and cybersecurity professionals understand malware behavior and defense mechanisms. The authors and contributors are not responsible for any misuse of this code. Always comply with local laws and regulations regarding cybersecurity research and testing.

**USE RESPONSIBLY AND ETHICALLY.**

---

## License & Attribution

Created for CADT Cyber Security Project
Date: November 28, 2025

For educational use in controlled environments only.
