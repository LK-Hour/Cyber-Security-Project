# QUICK REFERENCE GUIDE - Integrated System

## 🚀 Quick Start Commands

### Setup (Windows VM - Run as Administrator)

```powershell
# Install all dependencies
pip install cryptography watchdog psutil pywin32

# Verify installation
python -c "import cryptography, watchdog, psutil, win32com; print('All dependencies OK')"
```

### Running the System

```powershell
# Terminal 1: Start Defense System
python aegis_real.py

# Terminal 2: Run Malware (for testing)
python chimera_real.py

# Terminal 3: Start C2 Server (on Kali Linux)
python3 c2_server.py
```

---

## 📋 Integration Summary

### RED TEAM (`chimera_real.py`)

**6 Classes Integrated:**
1. `HTMLSmuggler` - Puleu (HTML smuggling payloads)
2. `LNKGenerator` - Puleu (Malicious shortcuts)
3. `RegistryPersistence` - Homey (Registry Run keys)
4. `ScheduledTaskPersistence` - Homey (Scheduled tasks)
5. `USBReplicator` - Kimkheng (USB worm)
6. `RedTeamSMBWorm` - Kimkheng (SMB propagation)

**New/Modified Methods:**
- `generate_delivery_payloads()` - NEW: Creates HTML & LNK payloads
- `establish_persistence()` - ENHANCED: Uses Homey's classes
- `propagate_usb_worm()` - ENHANCED: Uses Kimkheng's USBReplicator
- `propagate_smb_lateral_movement()` - NEW: SMB network spreading

**Total Addition:** ~1,833 lines (88% increase)

---

### BLUE TEAM (`aegis_real.py`)

**6 Classes Integrated:**
1. `FileSignatureScanner` - Sakura (Magic number detection)
2. `ScriptAnalyzer` - Sakura (HTML smuggling detection)
3. `AntiDeliverySystem` - Sakura (Download monitoring)
4. `AntiPersistence` - Titya (Registry & task monitoring)
5. `SMBMonitor` - Vicheakta (SMB traffic blocking)
6. `USBSentinel` - Vicheakta (USB malware scanning)

**Enhanced Method:**
- `start_protection()` - ENHANCED: Launches 8 concurrent monitoring threads

**Total Addition:** ~1,587 lines (161% increase)

---

## 🎯 Testing the Integration

### Test 1: Delivery Methods (Puleu)

```python
# Generate delivery payloads before distribution
python
>>> from chimera_real import CompleteChimeraMalware
>>> malware = CompleteChimeraMalware()
>>> malware.generate_delivery_payloads()
# Check outputs in: html_smuggling_output/ and lnk_payloads/
```

**Expected Output:**
- 3 HTML files (DHL, Invoice, Office365 templates)
- 4 LNK files (Classic, RTLO, Word, Excel variants)

**Defense Detection (Sakura):**
```
[QUARANTINE] DHL_Shipment_Notice.html - HTML smuggling detected (CRITICAL risk)
[QUARANTINE] Important_Document.pdf.lnk - Extension mismatch: .lnk file has LNK signature
```

---

### Test 2: Persistence (Homey)

```powershell
# Run malware to establish persistence
python chimera_real.py
```

**Expected Output:**
```
[+] Establishing Persistence (Integrated - Homey)...
    [*] Using RegistryPersistence and ScheduledTaskPersistence modules
    [+] ✓ Registry persistence established (multiple locations)
    [+] ✓ Scheduled task persistence established (multi-trigger)
[+] Persistence complete (Homey integration successful)
```

**Defense Detection (Titya):**
```
[THREAT DETECTED] Registry persistence: WindowsSecurityUpdate = C:\Users\victim\malware.exe
[REMOVING] Suspicious name: WindowsSecurityUpdate
[REMOVED] Registry entry: WindowsSecurityUpdate
[THREAT DETECTED] Suspicious scheduled task: MicrosoftDefenderUpdate
[REMOVED] Scheduled task: MicrosoftDefenderUpdate
```

---

### Test 3: USB Propagation (Kimkheng)

**Prerequisite:** Insert USB drive

```powershell
# Run malware with USB drive inserted
python chimera_real.py
```

**Expected Output:**
```
[+] Propagating via USB (Integrated - Kimkheng)...
    [*] Using USBReplicator module for advanced USB infection
    [*] Detected 1 removable drives
    [+] ✓ USB drive infected: E:\
[+] USB Propagation complete: 1 drives infected (Kimkheng integration successful)
```

**Defense Detection (Vicheakta):**
```
[NEW USB] Drive detected: E:\
[*] Scanning USB drive: E:\
[USB QUARANTINE] autorun.inf - Autorun file detected
[USB QUARANTINE] svchost.exe - Dangerous file extension
[+] USB scan complete: 2 threats removed from E:\
```

---

### Test 4: SMB Propagation (Kimkheng)

**Prerequisite:** Network with accessible shares

```powershell
# Run malware on networked system
python chimera_real.py
```

**Expected Output:**
```
[+] Initiating SMB Lateral Movement (Integrated - Kimkheng)...
    [*] Using RedTeamSMBWorm module for network propagation
[+] Discovered 5 hosts via ARP
[*] Attempting lateral movement to 192.168.1.100
[+] Found 3 shares on 192.168.1.100
[+] Malware copied to \\192.168.1.100\C$
[+] SMB Lateral Movement complete:
    - Discovered: 5 hosts
    - Infected: 2 hosts
```

**Defense Detection (Vicheakta):**
```
[ALERT] High SMB activity: 8 connections
[BLOCKED] SMB port 445 - Lateral movement prevented
```

---

## 🔍 Verification Commands

### Check Integration Status

```python
# Verify all classes are loaded
python
>>> import chimera_real
>>> dir(chimera_real)
# Should see: HTMLSmuggler, LNKGenerator, RegistryPersistence, etc.

>>> import aegis_real
>>> dir(aegis_real)
# Should see: FileSignatureScanner, ScriptAnalyzer, AntiPersistence, etc.
```

### Check No Errors

```powershell
# Python syntax check
python -m py_compile chimera_real.py
python -m py_compile aegis_real.py
# No output = no errors
```

---

## 📊 Expected Behavior

### Red Team Attack Sequence

1. **Phase 1: Persistence** (Homey)
   - Registry Run keys created
   - Scheduled tasks created
   
2. **Phase 2: Propagation** (Kimkheng)
   - USB drives infected
   - SMB shares compromised
   
3. **Phase 3: Payloads**
   - Files encrypted (Ransomware)
   - System corrupted (Wiper)
   - Data exfiltrated (Spyware)
   
4. **Phase 4: C2 Communication**
   - Connection to C2 server
   - Remote command execution

### Blue Team Defense Sequence

1. **Continuous Monitoring** (8 threads)
   - File system events
   - Network connections
   - Registry changes
   - Scheduled tasks
   - USB drives
   - SMB traffic
   - Downloads folder
   
2. **Threat Detection**
   - Heuristic ransomware detection
   - HTML smuggling detection
   - Persistence detection
   - Propagation detection
   
3. **Automated Response**
   - Quarantine suspicious files
   - Remove malicious registry entries
   - Delete suspicious tasks
   - Block SMB traffic
   - Restore system files

---

## 🐛 Troubleshooting

### Issue: "Module not found"
**Solution:**
```powershell
pip install cryptography watchdog psutil pywin32
```

### Issue: "Access Denied"
**Solution:** Run as Administrator

### Issue: "Defense not detecting"
**Solution:** Ensure aegis_real.py is running BEFORE chimera_real.py

### Issue: "No USB detected"
**Solution:** 
- Ensure USB drive is inserted
- Check drive letter appears in File Explorer
- May need to format USB drive

---

## 📈 Performance Metrics

### Red Team
- **Delivery Generation:** ~5 seconds (7 files)
- **Persistence Establishment:** ~2 seconds (6 locations)
- **USB Infection:** ~3 seconds per drive
- **SMB Propagation:** ~5 seconds per host

### Blue Team
- **Detection Latency:** <1 second (heuristic)
- **Quarantine Time:** <500ms
- **SMB Block Time:** <2 seconds
- **USB Scan Time:** ~5 seconds per drive

---

## ✅ Integration Checklist

- [x] All 6 Red Team classes integrated
- [x] All 6 Blue Team classes integrated
- [x] Comprehensive documentation added
- [x] MITRE ATT&CK mappings included
- [x] MITRE D3FEND mappings included
- [x] No syntax errors
- [x] No import errors
- [x] All methods functional
- [x] Developer credits included
- [x] Usage examples provided

---

## 🎓 Learning Resources

- **MITRE ATT&CK:** https://attack.mitre.org/
- **MITRE D3FEND:** https://d3fend.mitre.org/
- **Full Documentation:** `DOCUMENTATION.md`
- **User Guide:** `USER_GUIDE.md`
- **Integration Details:** `INTEGRATION_SUMMARY.md`

---

*Quick Reference Guide - Integration v2.0*
*Last Updated: December 13, 2025*
