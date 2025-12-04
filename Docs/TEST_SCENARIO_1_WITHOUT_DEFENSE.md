# TEST SCENARIO 1: ATTACK WITHOUT DEFENSE
## Demonstrating Chimera Malware with NO Protection

**Purpose:** Show what happens when malware runs on an unprotected system  
**Expected Outcome:** Full compromise - ransomware, wiper, and spyware succeed  
**Duration:** ~2-3 minutes

---

## 📋 PREPARATION STEPS

### 1. Setup Test Environment (Windows VM)

```powershell
# Create test victim folder with sample files
New-Item -Path "$env:USERPROFILE\Documents\TestVictim" -ItemType Directory -Force

# Create 20 test files for encryption
1..20 | ForEach-Object {
    "This is test document number $_. Important business data goes here." | 
    Out-File -FilePath "$env:USERPROFILE\Documents\TestVictim\document_$_.txt"
}

# Create some additional file types
"Sample spreadsheet data" | Out-File -FilePath "$env:USERPROFILE\Documents\TestVictim\financial_report.xlsx"
"Sample presentation" | Out-File -FilePath "$env:USERPROFILE\Documents\TestVictim\meeting_slides.pptx"
"Sample document" | Out-File -FilePath "$env:USERPROFILE\Documents\TestVictim\contract.docx"
"Sample PDF content" | Out-File -FilePath "$env:USERPROFILE\Documents\TestVictim\invoice.pdf"

Write-Host "[+] Created test files in Documents\TestVictim\"
```

### 2. Take VM Snapshot
```
VMware > VM > Snapshot > Take Snapshot
Name: "Before Attack - Clean State"
Description: "Clean system before malware execution"
```
**⚠️ CRITICAL: Always take snapshot before running malware!**

---

## 🎬 EXECUTION STEPS

### Step 1: Verify Clean System State

```powershell
# Check test files exist
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" | Measure-Object
# Expected: Should show 24 files

# Check hosts file is clean
Get-Content "C:\Windows\System32\drivers\etc\hosts"
# Expected: Should only have localhost entries

# Check no encrypted files exist
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" -Filter "*.chimera_encrypted"
# Expected: Should return nothing

Write-Host "`n[✓] System is clean and ready for attack demonstration`n" -ForegroundColor Green
```

### Step 2: Start C2 Server (Kali Linux - Optional)

**On Kali Linux VM:**
```bash
cd /path/to/project
python3 c2_server.py
```

**Expected Output:**
```
[2025-12-03 10:00:00] [INFO] Enhanced C2 Server started on 0.0.0.0:4444
[2025-12-03 10:00:00] [INFO] Waiting for bot connections...

🎮 ENHANCED C2 SERVER - INTERACTIVE CONSOLE
======================================================================
Type 'help' for available commands
======================================================================

C2>
```

**Note:** If you want to test without C2 server (offline mode), skip this step. The malware will still execute all local payloads.

### Step 3: Execute Chimera Malware (Windows VM)

**Open PowerShell (Administrator recommended for full functionality):**

```powershell
# Navigate to project directory
cd "C:\Path\To\Project"

# Run the malware
python chimera_real.py
```

### Step 4: Observe Attack Progress

**Watch the console output carefully:**

```
╔═══════════════════════════════════════════════╗
║              CHIMERA MALWARE                  ║
║         Complete Attack Sequence              ║
║         Educational Purpose Only              ║
╚═══════════════════════════════════════════════╝

[+] Establishing Persistence...
    [+] Registry persistence established
    [+] Scheduled task created

[+] Propagating via USB...
[+] USB Propagation: Infected 0 drives

[+] Executing Core Malicious Payloads...

[+] Starting Ransomware Encryption...
    [+] Encrypted 10 files...
    [+] Encrypted 20 files...
[+] Ransomware: Encrypted 24 files
[+] Sending encryption key to C2 server...
    [+] Attempt 1/5: Sending key to 192.168.1.100:4444...
    [+] Encryption key sent successfully!
    [+] Fallback: Key saved to ENCRYPTION_KEY_BACKUP.txt

[+] Starting System Corruption...
    [+] Corrupted hosts file - blocked security sites
    [+] Deleted volume shadow copies via WMIC
    [+] Disabled 5/5 Windows Defender protections
[+] System Corruption: Completed 6 destructive actions

[+] Starting Data Exfiltration...
    [+] Saved stolen data locally
[+] Data Exfiltration: Stole 15 document samples

[+] Starting C2 Communication Handler...
    [+] Connected to C2 server: 192.168.1.100:4444
    [+] Sent handshake with system info
    [+] Waiting for commands from C2...

╔═══════════════════════════════════════════════╗
║             INITIAL ATTACK COMPLETE           ║
║         C2 Communication Active               ║
║         Waiting for remote commands...        ║
╚═══════════════════════════════════════════════╝
```

---

## 🔍 VERIFICATION & DAMAGE ASSESSMENT

### Verify Ransomware Impact

```powershell
# Check encrypted files
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" -Filter "*.chimera_encrypted"
# Expected: Should show 24 encrypted files

# Check original files are gone
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" -Filter "*.txt"
# Expected: Should return nothing (all encrypted)

# Check ransom note
Get-Content "$env:USERPROFILE\Desktop\READ_ME_FOR_DECRYPT.txt"
# Expected: Should display ransom note with decryption key

# Try to open encrypted file (will fail)
notepad "$env:USERPROFILE\Documents\TestVictim\document_1.txt.chimera_encrypted"
# Expected: Unreadable encrypted content

Write-Host "`n[!] RANSOMWARE IMPACT: All 24 files encrypted!" -ForegroundColor Red
```

### Verify System Corruption (Wiper)

```powershell
# Check hosts file corruption
Get-Content "C:\Windows\System32\drivers\etc\hosts" | Select-String "CHIMERA"
# Expected: Should show "# CHIMERA MALWARE REDIRECTS - DO NOT REMOVE"

Get-Content "C:\Windows\System32\drivers\etc\hosts" | Select-String "microsoft.com"
# Expected: Should show malicious redirects to 127.0.0.1

# Test if security sites are blocked
ping microsoft.com
# Expected: Should ping 127.0.0.1 (localhost) instead of real Microsoft

# Check shadow copies deleted
vssadmin list shadows
# Expected: "No items found that satisfy the query" OR error

# Check Windows Defender status
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring
# Expected: Both should be True (disabled)

Write-Host "`n[!] WIPER IMPACT: System corrupted, recovery disabled!" -ForegroundColor Red
```

### Verify Data Exfiltration (Spyware)

```powershell
# Check exfiltrated data file
Get-Content "chimera_exfiltrated_data.json" | ConvertFrom-Json | Format-List

# Expected output structure:
<#
system_info        : @{computer_name=VICTIM-PC; username=JohnDoe; ...}
document_samples   : @{document_1.txt=...; document_2.txt=...; ...}
network_info       : @{hostname=VICTIM-PC; local_ip=192.168.1.50; ...}
browser_data       : @{chrome=...; edge=...; ...}
timestamp          : 1733223000.123
#>

Write-Host "`n[!] SPYWARE IMPACT: Sensitive data stolen!" -ForegroundColor Red
```

### Verify Persistence

```powershell
# Check Registry persistence
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | 
    Select-Object WindowsUpdateService
# Expected: Should show malware path

# Check Scheduled Task
schtasks /query /tn "MicrosoftWindowsUpdate" /fo LIST
# Expected: Should show task scheduled to run hourly

Write-Host "`n[!] PERSISTENCE: Malware will survive reboot!" -ForegroundColor Red
```

### Check C2 Communication (if C2 server running)

**On Kali Linux C2 Console:**
```
C2> list
```

**Expected Output:**
```
============================================================
ACTIVE BOTS
============================================================
BOT_0001: VICTIM-PC (JohnDoe)
  Status: ACTIVE, Last Seen: 2.3s ago
  IP: 192.168.1.50:54321
  🔑 Encryption Key: Available (24 files)
```

**Try sending commands:**
```
C2> send BOT_0001 status
```

**Expected Response:**
```
📩 COMMAND RESULT FROM BOT_0001
======================================================================
Command: status
Timestamp: Tue Dec 03 10:05:30 2025
----------------------------------------------------------------------
Result:
✓ Bot Status Report:

Bot ID: VICTIM-PC_JohnDoe
Status: ACTIVE
Files Encrypted: 24
Documents Exfiltrated: 15
C2 Connection: ACTIVE
Persistence: Established
Last Activity: Tue Dec 03 10:05:30 2025
======================================================================
```

**Check encryption keys:**
```
C2> keys
```

**Expected:** Display all received encryption keys with decrypt commands

---

## 📊 ATTACK SUMMARY - NO DEFENSE

| Attack Vector | Status | Impact |
|---------------|--------|--------|
| **Ransomware** | ✅ Success | 24 files encrypted |
| **Key Exfiltration** | ✅ Success | Key sent to C2 server |
| **Hosts File Corruption** | ✅ Success | Security sites blocked |
| **Shadow Copy Deletion** | ✅ Success | Recovery disabled |
| **Defender Disabling** | ✅ Success | 5/5 protections off |
| **Data Theft** | ✅ Success | 15 documents stolen |
| **Persistence** | ✅ Success | Registry + Task |
| **C2 Communication** | ✅ Success | Bot registered |

**TOTAL DAMAGE:** 100% system compromise with NO resistance

---

## 🔄 FILE RECOVERY TEST (Decryption)

### Step 1: Get Decryption Key

```powershell
# Option 1: From ransom note
Get-Content "$env:USERPROFILE\Desktop\READ_ME_FOR_DECRYPT.txt"

# Option 2: From attack report
Get-Content "chimera_attack_report.txt"

# Option 3: From local backup
Get-Content "ENCRYPTION_KEY_BACKUP.txt"

# Option 4: From C2 server (if running)
# Use 'keys' command on C2 console
```

**Copy the encryption key (it looks like base64 string):**
```
Example: gAAAAABmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==
```

### Step 2: Decrypt Files

```powershell
# Run decryption with the key
python chimera_real.py --decrypt <PASTE_KEY_HERE>
```

**Expected Output:**
```
[*] Scanning for encrypted files in: C:\Users\JohnDoe\Documents\TestVictim
[*] Found 24 encrypted files
[*] Starting decryption...

Decrypting: document_1.txt.chimera_encrypted
Decrypting: document_2.txt.chimera_encrypted
[Progress updates every 10 files...]

==================================================
DECRYPTION COMPLETE
==================================================
✓ Successfully decrypted: 24 files
Total processed: 24 files
```

### Step 3: Verify Files Restored

```powershell
# Check original files are back
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" -Filter "*.txt"
# Expected: All 20 .txt files restored

# Check encrypted files removed
Get-ChildItem "$env:USERPROFILE\Documents\TestVictim" -Filter "*.chimera_encrypted"
# Expected: Should return nothing

# Verify file content
Get-Content "$env:USERPROFILE\Documents\TestVictim\document_1.txt"
# Expected: Original text visible

Write-Host "`n[✓] FILES SUCCESSFULLY DECRYPTED!" -ForegroundColor Green
```

---

## 🧹 CLEANUP AFTER TEST

### Option 1: Restore VM Snapshot (Recommended)
```
VMware > VM > Snapshot > Revert to Snapshot
Select: "Before Attack - Clean State"
```
**Fastest way to return to clean state!**

### Option 2: Manual Cleanup (if needed)

```powershell
# Remove persistence
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService"
schtasks /delete /tn "MicrosoftWindowsUpdate" /f

# Remove malware files
Remove-Item "chimera_attack_report.txt" -Force
Remove-Item "chimera_exfiltrated_data.json" -Force
Remove-Item "ENCRYPTION_KEY_BACKUP.txt" -Force

# Restore hosts file (requires admin)
Set-Content "C:\Windows\System32\drivers\etc\hosts" -Value @"
# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
::1             localhost
"@

# Re-enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false

# Decrypt files (if not already done)
# python chimera_real.py --decrypt <KEY>

Write-Host "`n[✓] Cleanup complete!" -ForegroundColor Green
```

---

## 🎓 DEMONSTRATION TALKING POINTS

**While demonstrating this scenario, explain:**

1. **Why No Detection?**
   - "Without defense software running, the malware operates freely"
   - "Traditional antivirus might catch known signatures, but this is custom malware"
   - "No behavioral analysis = no ransomware detection"

2. **Speed of Attack:**
   - "Notice how quickly it encrypts 24 files (seconds)"
   - "Real ransomware can encrypt thousands of files in minutes"
   - "By the time user notices, damage is done"

3. **System Corruption:**
   - "Hosts file modification blocks security updates and antivirus sites"
   - "Shadow copy deletion prevents Windows built-in recovery"
   - "Defender disabled = no protection even if user tries to enable it"

4. **Data Exfiltration:**
   - "Before encryption, malware steals sensitive documents"
   - "This data is sold on dark web or used for blackmail"
   - "Double extortion: pay to decrypt AND prevent data leak"

5. **Persistence:**
   - "Malware survives reboots via Registry and Scheduled Tasks"
   - "Continues to operate and can download additional payloads"
   - "Complete system compromise"

6. **C2 Communication:**
   - "Attacker maintains remote control of infected machine"
   - "Can execute additional commands at any time"
   - "Encryption key automatically backed up to attacker's server"

---

## 📸 SCREENSHOTS TO TAKE

1. **Before Attack:** Clean TestVictim folder with normal files
2. **During Attack:** Console output showing encryption progress
3. **After Attack:** Folder with .chimera_encrypted files
4. **Ransom Note:** READ_ME_FOR_DECRYPT.txt content
5. **Hosts File:** Showing malicious redirects
6. **C2 Server:** Bot connection and command execution
7. **After Decryption:** Restored files in folder

---

## ⏱️ ESTIMATED TIMELINE

| Phase | Duration | Activity |
|-------|----------|----------|
| Preparation | 2 minutes | Create test files, snapshot |
| Attack Execution | 30 seconds | Run chimera_real.py |
| Observation | 1 minute | Watch console output |
| Verification | 2 minutes | Check encryption, corruption, data theft |
| C2 Demo | 1 minute | Show remote commands |
| Decryption | 30 seconds | Restore files |
| Discussion | 5 minutes | Explain attack methodology |
| **TOTAL** | **~12 minutes** | Complete demonstration |

---

## ✅ SUCCESS CRITERIA

**This scenario is successful if:**
- ✅ All 24 test files are encrypted
- ✅ Original files are deleted
- ✅ Ransom note appears on Desktop
- ✅ Hosts file is corrupted with malicious entries
- ✅ Shadow copies are deleted
- ✅ Windows Defender is disabled
- ✅ Data exfiltration JSON file is created
- ✅ Persistence mechanisms are installed
- ✅ C2 connection is established (if C2 running)
- ✅ Encryption key is backed up
- ✅ Files can be decrypted with correct key

---

**Next:** Proceed to TEST_SCENARIO_2_WITH_DEFENSE.md to see how Aegis blocks this attack!
