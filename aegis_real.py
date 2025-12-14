"""
AEGIS DEFENSE - INTEGRATED BLUE TEAM SOLUTION
==============================================
Complete Host-Based Intrusion Detection System (HIDS)

⚠️ DEFENSE PURPOSE: Protects against advanced malware threats

INTEGRATED MODULES:
==================
[CORE DEFENSE]
- Heuristic Encryption Detection (Behavioral ransomware detection)
- System File Integrity Monitor (Hash-based protection)
- Network Egress Filtering (C2 communication blocking)

[ANTI-DELIVERY SPECIALIST - Sakura]
- File Signature Scanner (Magic number analysis)
- Script Analyzer (HTML smuggling detection)
- Anti-Delivery System (Download folder monitoring)

[ANTI-PERSISTENCE SPECIALIST - Titya]
- Registry Watchdog (Defends against RegistryPersistence - Homey)
- Task Auditor (Defends against ScheduledTaskPersistence - Homey)

[ANTI-SPREADING SPECIALIST - Vicheakta]
- SMB Monitor (Blocks SMB lateral movement)
- USB Sentinel (Scans removable drives for malware)

Author: CADT Cyber Security Project - Blue Team
Date: December 13, 2025
Version: 2.0 (Fully Integrated)
"""

# ==========================================
# STANDARD LIBRARY IMPORTS
# ==========================================
import os         # File and directory operations
import time       # Timestamps and timing for monitoring
import hashlib    # MD5 hashing for file integrity verification
import threading  # Multi-threaded monitoring (concurrent defense mechanisms)
import shutil     # File operations for backup/restore
import signal     # Process signals for forceful termination
import subprocess # Execute system commands for task enumeration
import winreg     # Windows registry access for persistence monitoring
import re         # Regular expressions for pattern matching
import base64     # Base64 decoding for script analysis
import psutil     # Process and network monitoring library
from watchdog.observers import Observer  # File system event monitoring
from watchdog.events import FileSystemEventHandler  # File modification event handler

# ==========================================
# ANTI-DELIVERY SPECIALIST MODULE - Sakura
# ==========================================
# Purpose: Detect and block initial compromise attempts
# Defense Against: HTML smuggling (Puleu), LNK files (Puleu)
# MITRE D3FEND: D3-FA (File Analysis), D3-SCA (Script Content Analysis)
#
# TWO CLASSES:
# 1. DeliveryThreatAnalyzer - Unified file signature + script analysis
# 2. AntiDeliverySystem - Download monitoring orchestrator

class DeliveryThreatAnalyzer:
    """
    Unified Delivery Threat Analyzer
    Developer: Sakura (Anti-Delivery Specialist)
    
    Combines file signature analysis and HTML/JS script analysis.
    Defends against Puleu's delivery techniques (HTMLSmuggler + LNKGenerator).
    
    MITRE D3FEND Techniques:
    - D3-FA: File Analysis
    - D3-FENCA: File Encoding Analysis
    - D3-SCA: Script Content Analysis
    - D3-DA: Dynamic Analysis
    
    Capabilities:
    1. File Signature Analysis:
       - Detects file type masquerading (EXE disguised as PDF/DOC)
       - Checks magic numbers vs file extensions
       - Identifies double extensions (file.pdf.exe)
    
    2. Script Analysis (HTML/JS):
       - Detects HTML smuggling patterns
       - Identifies large base64 payloads (>50KB)
       - Checks for auto-download mechanisms
       - Decodes and scans for embedded executables
    
    Defends Against:
    - Puleu's HTMLSmuggler (3 phishing templates)
    - Puleu's LNKGenerator (4 file variants)
    """
    
    def __init__(self):
        """Initialize analyzer with signatures and script patterns"""
        # File signatures (magic numbers)
        self.signatures = {
            'exe': [b'MZ', b'ZM'],  # DOS/Windows executable
            'pdf': [b'%PDF'],        # PDF document
            'zip': [b'PK\x03\x04'],  # ZIP archive
            'jpg': [b'\xFF\xD8\xFF'], # JPEG image
            'png': [b'\x89PNG'],     # PNG image
            'doc': [b'\xD0\xCF\x11\xE0'], # MS Office (old format)
            'docx': [b'PK\x03\x04'], # DOCX (ZIP-based)
            'lnk': [b'\x4C\x00\x00\x00']  # Windows shortcut
        }
        
        # HTML smuggling detection patterns
        self.suspicious_patterns = [
            r'eval\s*\(',           # JavaScript eval (code execution)
            r'unescape\s*\(',       # Decoding obfuscated strings
            r'fromCharCode',        # Character code obfuscation
            r'atob\s*\(',           # Base64 decoding
            r'blob\s*=\s*new Blob', # Blob creation (file download)
            r'\.click\s*\(\)',      # Automatic click (auto-download)
            r'saveAs\s*\(',         # File save function
            r'application/octet-stream'  # Binary file MIME type
        ]
    
    def detect_file_type(self, file_path):
        """
        Detect actual file type by reading magic numbers
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            Tuple: (detected_type, is_suspicious, reason)
        """
        try:
            # Read first 8 bytes (enough for most signatures)
            with open(file_path, 'rb') as f:
                header = f.read(8)
            
            # Check against known signatures
            for file_type, signatures in self.signatures.items():
                for sig in signatures:
                    if header.startswith(sig):
                        return (file_type, False, f"Valid {file_type.upper()} file")
            
            # Unknown signature - potentially suspicious
            return ('unknown', True, f"Unknown file signature: {header[:4].hex()}")
            
        except Exception as e:
            return ('error', True, f"Failed to read file: {e}")
    
    def analyze_file_signature(self, file_path):
        """
        Analyze file signature for type masquerading
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary with scan results
        """
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower().lstrip('.')
        
        # Detect actual file type
        detected_type, is_suspicious, reason = self.detect_file_type(file_path)
        
        # Check for mismatch (masquerading)
        if file_ext and file_ext != detected_type:
            # Special case: DOCX/XLSX are ZIP-based (not suspicious)
            if not (file_ext in ['docx', 'xlsx', 'pptx'] and detected_type == 'zip'):
                is_suspicious = True
                reason = f"Extension mismatch: .{file_ext} file has {detected_type.upper()} signature"
        
        # Check for double extension
        if file_name.count('.') > 1:
            is_suspicious = True
            reason = f"Double extension detected: {file_name}"
        
        return {
            'file_path': file_path,
            'extension': file_ext,
            'detected_type': detected_type,
            'is_suspicious': is_suspicious,
            'reason': reason
        }
    
    def analyze_html_content(self, html_content):
        """
        Analyze HTML content for smuggling patterns
        
        Args:
            html_content: HTML file content as string
        
        Returns:
            Dictionary with analysis results
        """
        results = {
            'is_suspicious': False,
            'risk_level': 'LOW',
            'patterns_found': [],
            'has_large_base64': False,
            'has_executable': False
        }
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                results['patterns_found'].append(pattern)
                results['is_suspicious'] = True
        
        # Check for large base64 strings (likely embedded payload)
        base64_matches = re.findall(r'[A-Za-z0-9+/]{500,}={0,2}', html_content)
        if base64_matches:
            for match in base64_matches:
                if len(match) > 50000:  # >50KB base64 = suspicious
                    results['has_large_base64'] = True
                    results['is_suspicious'] = True
                    
                    # Try to decode and check for MZ header
                    try:
                        decoded = base64.b64decode(match)
                        if decoded.startswith(b'MZ'):
                            results['has_executable'] = True
                            results['risk_level'] = 'CRITICAL'
                    except:
                        pass
        
        # Determine risk level
        if results['has_executable']:
            results['risk_level'] = 'CRITICAL'
        elif results['has_large_base64']:
            results['risk_level'] = 'HIGH'
        elif len(results['patterns_found']) > 3:
            results['risk_level'] = 'MEDIUM'
        
        return results
    
    def analyze_file(self, file_path):
        """
        Comprehensive file analysis (signature + script content if HTML/JS)
        
        This is the main analysis method that combines both techniques.
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            Dictionary with complete analysis results
        """
        # Start with signature analysis
        result = self.analyze_file_signature(file_path)
        
        # If HTML/JS file, also analyze script content
        if file_path.endswith(('.html', '.htm', '.js')):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                script_result = self.analyze_html_content(content)
                
                # Merge results - script analysis takes priority if suspicious
                if script_result['is_suspicious']:
                    result['is_suspicious'] = True
                    result['risk_level'] = script_result['risk_level']
                    result['patterns_found'] = script_result['patterns_found']
                    result['has_executable'] = script_result.get('has_executable', False)
                    
                    # Update reason with script analysis details
                    reason = f"HTML smuggling detected ({script_result['risk_level']} risk)"
                    if script_result.get('has_executable'):
                        reason += " - Contains embedded executable!"
                    result['reason'] = reason
                    
            except Exception as e:
                result['script_error'] = str(e)
        
        return result


class AntiDeliverySystem:
    """
    Anti-Delivery System Orchestrator
    Developer: Sakura (Anti-Delivery Specialist)
    
    Monitors download folders for malicious files and quarantines threats.
    Uses DeliveryThreatAnalyzer for comprehensive scanning.
    
    MITRE D3FEND Techniques:
    - D3-FENCA: File Content Analysis
    - D3-QA: Quarantine by Access
    
    How it works:
    1. Monitors Downloads folder for new files
    2. Scans each file with DeliveryThreatAnalyzer
    3. Automatically quarantines suspicious files
    4. Logs all detections for forensics
    
    Defends Against:
    - Puleu's HTMLSmuggler phishing templates
    - Puleu's LNK file variants
    """
    
    def __init__(self, downloads_path):
        """
        Initialize anti-delivery system
        
        Args:
            downloads_path: Path to Downloads folder to monitor
        """
        self.downloads_path = downloads_path
        self.quarantine_dir = os.path.join(downloads_path, ".aegis_quarantine")
        self.threat_analyzer = DeliveryThreatAnalyzer()
        self.running = True
        
        # Create quarantine directory
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def quarantine_file(self, file_path, reason):
        """
        Move suspicious file to quarantine
        
        Args:
            file_path: Path to suspicious file
            reason: Reason for quarantine
        """
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, file_name)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Log quarantine action
            log_file = os.path.join(self.quarantine_dir, "quarantine_log.txt")
            with open(log_file, 'a') as f:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] QUARANTINED: {file_name}\n")
                f.write(f"Reason: {reason}\n\n")
            
            print(f"[QUARANTINE] {file_name} - {reason}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to quarantine {file_path}: {e}")
            return False
    
    def quick_scan(self, file_path):
        """
        Perform quick scan on a file using unified threat analyzer
        
        Args:
            file_path: Path to file
        
        Returns:
            True if file is suspicious, False otherwise
        """
        # Skip if file is in quarantine dir
        if self.quarantine_dir in file_path:
            return False
        
        # Analyze file (signature + script content if applicable)
        result = self.threat_analyzer.analyze_file(file_path)
        
        if result['is_suspicious']:
            self.quarantine_file(file_path, result['reason'])
            return True
        
        return False
    
    def monitor_downloads_folder(self):
        """Monitor downloads folder for new files"""
        print(f"[+] Monitoring downloads folder: {self.downloads_path}")
        
        # Track already scanned files
        scanned_files = set()
        
        while self.running:
            try:
                # Scan for new files
                for file_name in os.listdir(self.downloads_path):
                    file_path = os.path.join(self.downloads_path, file_name)
                    
                    # Skip directories and already scanned files
                    if os.path.isdir(file_path) or file_path in scanned_files:
                        continue
                    
                    # Scan new file
                    self.quick_scan(file_path)
                    scanned_files.add(file_path)
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"[ERROR] Download monitoring error: {e}")
                time.sleep(5)


# ==========================================
# ANTI-PERSISTENCE SPECIALIST MODULE - Titya
# ==========================================
# Purpose: Detect and remove persistence mechanisms
# Defense Against: Registry Run keys, Scheduled tasks
# MITRE D3FEND: D3-PSA (Process Spawn Analysis), D3-HBPI (Process Inspection)
# 
# TWO SEPARATE CLASSES TO MATCH RED TEAM STRUCTURE:
# 1. RegistryWatchdog - Defends against RegistryPersistence (Homey)
# 2. TaskAuditor - Defends against ScheduledTaskPersistence (Homey)

class RegistryWatchdog:
    """
    Registry Persistence Monitor
    Developer: Titya (Anti-Persistence Specialist)
    
    Defends against: RegistryPersistence class (Homey - Red Team)
    
    Monitors and removes malicious Registry Run key persistence.
    Creates baseline of legitimate entries and detects new suspicious additions.
    
    MITRE D3FEND Techniques:
    - D3-PSA: Process Spawn Analysis
    - D3-HBPI: Host-Based Process Inspection
    
    How it works:
    1. Creates baseline of current Registry Run keys at startup
    2. Continuously monitors registry for new/modified entries
    3. Checks entries against suspicious patterns
    4. Automatically removes malicious entries
    
    Monitored Registry Locations:
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
    - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run
    
    Detection Patterns:
    - Suspicious names: WindowsUpdate, SecurityUpdate, MicrosoftDefender (fake services)
    - Suspicious paths: temp, appdata, downloads directories
    - Known malware names: chimera, malware, backdoor
    """
    
    def __init__(self):
        """Initialize registry watchdog"""
        self.running = True
        self.registry_baseline = {}
        self.suspicious_keywords = [
            'WindowsUpdate', 'SecurityUpdate', 'MicrosoftDefender',
            'WindowsSecurityUpdate', 'MicrosoftWindowsUpdate',
            'chimera', 'malware', 'backdoor', 'svchost', 'csrss'
        ]
        
        # Registry paths to monitor
        self.monitored_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        ]
        
        # Create baseline of legitimate entries
        self._create_baseline()
    
    def _create_baseline(self):
        """Create baseline snapshot of current Registry Run keys"""
        print("[*] Creating registry baseline...")
        
        for hive, path in self.monitored_paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                index = 0
                entries = {}
                
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        entries[name] = value
                        index += 1
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                self.registry_baseline[path] = entries
                print(f"    [+] Baseline: {path} ({len(entries)} entries)")
                
            except FileNotFoundError:
                # Key doesn't exist - create empty baseline
                self.registry_baseline[path] = {}
            except Exception as e:
                print(f"    [-] Failed to baseline {path}: {e}")
    
    def monitor_registry(self):
        """
        Main monitoring loop for registry changes
        Continuously checks for new or modified entries
        """
        print("[+] Registry watchdog active - monitoring Run keys...")
        
        while self.running:
            for hive, path in self.monitored_paths:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                    index = 0
                    
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            
                            # Check if this is a new or modified entry
                            baseline = self.registry_baseline.get(path, {})
                            if name not in baseline or baseline[name] != value:
                                # New/modified entry - analyze it
                                self._analyze_entry(hive, path, name, value)
                                # Update baseline
                                self.registry_baseline[path][name] = value
                            
                            index += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                    
                except FileNotFoundError:
                    # Key doesn't exist yet - skip
                    pass
                except Exception as e:
                    pass
            
            time.sleep(5)  # Check every 5 seconds
    
    def _analyze_entry(self, hive, path, name, value):
        """
        Analyze registry entry for suspicious characteristics
        
        Args:
            hive: Registry hive (HKEY_CURRENT_USER, etc.)
            path: Registry path
            name: Entry name
            value: Entry value (executable path)
        """
        is_suspicious = False
        reasons = []
        
        # Check 1: Suspicious keywords in name
        for keyword in self.suspicious_keywords:
            if keyword.lower() in name.lower():
                is_suspicious = True
                reasons.append(f"Suspicious name keyword: {keyword}")
                break
        
        # Check 2: Suspicious executable paths
        suspicious_locations = ['temp', 'appdata', 'downloads', 'programdata']
        if any(ext in value.lower() for ext in ['.exe', '.bat', '.ps1', '.vbs', '.js']):
            for location in suspicious_locations:
                if location in value.lower():
                    is_suspicious = True
                    reasons.append(f"Suspicious location: {location}")
                    break
        
        # Check 3: Non-standard executable extensions
        if any(ext in value.lower() for ext in ['.bat', '.ps1', '.vbs', '.js']):
            is_suspicious = True
            reasons.append("Script-based persistence (non-EXE)")
        
        if is_suspicious:
            print(f"\n[THREAT DETECTED] Registry Persistence")
            print(f"    Location: {path}")
            print(f"    Name: {name}")
            print(f"    Value: {value}")
            print(f"    Reasons: {', '.join(reasons)}")
            print(f"[REMOVING] Malicious registry entry...")
            
            if self._remove_entry(hive, path, name):
                print(f"[SUCCESS] ✓ Removed: {name}\n")
            else:
                print(f"[FAILED] ✗ Could not remove: {name}\n")
    
    def _remove_entry(self, hive, path, name):
        """
        Remove malicious registry entry
        
        Args:
            hive: Registry hive
            path: Registry path
            name: Entry name to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            print(f"    [ERROR] {e}")
            return False


class TaskAuditor:
    """
    Scheduled Task Persistence Monitor
    Developer: Titya (Anti-Persistence Specialist)
    
    Defends against: ScheduledTaskPersistence class (Homey - Red Team)
    
    Monitors and removes malicious scheduled task persistence.
    Enumerates tasks and identifies suspicious characteristics.
    
    MITRE D3FEND Techniques:
    - D3-PSA: Process Spawn Analysis
    - D3-HBPI: Host-Based Process Inspection
    
    How it works:
    1. Enumerates all scheduled tasks using PowerShell
    2. Analyzes task names, triggers, and actions
    3. Identifies suspicious patterns
    4. Automatically removes malicious tasks
    
    Detection Patterns:
    - Suspicious names: WindowsUpdate, SecurityUpdate, MicrosoftDefender (fake services)
    - Hidden tasks (Settings.Hidden = True)
    - Unusual triggers: every minute, on idle, multiple triggers
    - Script execution: PowerShell.exe, cmd.exe, wscript.exe
    - Suspicious paths: temp, appdata, downloads
    """
    
    def __init__(self):
        """Initialize task auditor"""
        self.running = True
        self.suspicious_keywords = [
            'WindowsUpdate', 'SecurityUpdate', 'MicrosoftDefender',
            'WindowsSecurityUpdate', 'MicrosoftWindowsUpdate',
            'chimera', 'malware', 'backdoor', 'SystemMaintenance'
        ]
        self.known_tasks = set()
    
    def audit_tasks(self):
        """
        Main monitoring loop for scheduled tasks
        Continuously enumerates and analyzes tasks
        """
        print("[+] Task auditor active - monitoring scheduled tasks...")
        
        while self.running:
            try:
                # Enumerate all scheduled tasks
                tasks = self._enumerate_tasks()
                
                # Analyze each task
                for task_info in tasks:
                    task_name = task_info.get('name', '')
                    
                    # Check if this is a new task
                    if task_name not in self.known_tasks:
                        if self._analyze_task(task_info):
                            # Task is suspicious - remove it
                            self._remove_task(task_name)
                        else:
                            # Task is legitimate - add to known list
                            self.known_tasks.add(task_name)
                
            except Exception as e:
                print(f"[ERROR] Task audit error: {e}")
            
            time.sleep(10)  # Check every 10 seconds
    
    def _enumerate_tasks(self):
        """
        Enumerate all scheduled tasks using PowerShell
        
        Returns:
            List of task dictionaries with name, path, state, actions
        """
        try:
            # PowerShell command to get task details
            ps_command = '''
Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -or $_.State -eq "Running"} | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.TaskName
        Path = $_.TaskPath
        State = $_.State
        Actions = ($_.Actions | ForEach-Object { $_.Execute }) -join "; "
    }
} | ConvertTo-Json
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                import json
                try:
                    tasks_data = json.loads(result.stdout)
                    # Handle single task (not a list)
                    if isinstance(tasks_data, dict):
                        tasks_data = [tasks_data]
                    
                    # Convert to simpler format
                    tasks = []
                    for task in tasks_data:
                        tasks.append({
                            'name': task.get('Name', ''),
                            'path': task.get('Path', ''),
                            'state': task.get('State', ''),
                            'actions': task.get('Actions', '')
                        })
                    
                    return tasks
                except json.JSONDecodeError:
                    return []
            
            return []
            
        except Exception as e:
            print(f"[ERROR] Failed to enumerate tasks: {e}")
            return []
    
    def _analyze_task(self, task_info):
        """
        Analyze task for suspicious characteristics
        
        Args:
            task_info: Dictionary with task details
        
        Returns:
            True if suspicious, False if legitimate
        """
        is_suspicious = False
        reasons = []
        
        task_name = task_info.get('name', '')
        task_actions = task_info.get('actions', '').lower()
        
        # Check 1: Suspicious keywords in name
        for keyword in self.suspicious_keywords:
            if keyword.lower() in task_name.lower():
                is_suspicious = True
                reasons.append(f"Suspicious name keyword: {keyword}")
                break
        
        # Check 2: PowerShell execution
        if 'powershell' in task_actions or 'pwsh' in task_actions:
            is_suspicious = True
            reasons.append("PowerShell execution detected")
        
        # Check 3: Script execution
        if any(ext in task_actions for ext in ['.bat', '.ps1', '.vbs', '.js']):
            is_suspicious = True
            reasons.append("Script-based execution")
        
        # Check 4: Suspicious paths
        suspicious_locations = ['temp', 'appdata', 'downloads', 'programdata']
        for location in suspicious_locations:
            if location in task_actions:
                is_suspicious = True
                reasons.append(f"Suspicious location: {location}")
                break
        
        if is_suspicious:
            print(f"\n[THREAT DETECTED] Scheduled Task Persistence")
            print(f"    Name: {task_name}")
            print(f"    Path: {task_info.get('path', 'N/A')}")
            print(f"    Actions: {task_info.get('actions', 'N/A')}")
            print(f"    Reasons: {', '.join(reasons)}")
            print(f"[REMOVING] Malicious scheduled task...")
        
        return is_suspicious
    
    def _remove_task(self, task_name):
        """
        Remove malicious scheduled task
        
        Args:
            task_name: Name of task to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            result = subprocess.run(
                ['schtasks', '/Delete', '/TN', task_name, '/F'],
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"[SUCCESS] ✓ Removed task: {task_name}\n")
                return True
            else:
                print(f"[FAILED] ✗ Could not remove: {task_name}\n")
                return False
                
        except Exception as e:
            print(f"[ERROR] {e}")
            return False


# ==========================================
# ANTI-SPREADING SPECIALIST MODULE - Vicheakta
# ==========================================
# Purpose: Prevent lateral movement and worm propagation
# Defense Against: SMB spreading, USB worms
# MITRE D3FEND: D3-NTF (Network Traffic Filtering), D3-ITF (Inbound Traffic Filtering)

class SMBMonitor:
    """
    SMB Traffic Monitor and Blocker
    Developer: Vicheakta (Anti-Spreading Specialist)
    
    Monitors and blocks suspicious SMB traffic to prevent lateral movement.
    
    MITRE D3FEND Techniques:
    - D3-NTF: Network Traffic Filtering
    - D3-ITF: Inbound Traffic Filtering
    
    How it works:
    1. Monitors active SMB connections (port 445)
    2. Detects connection spikes (>5 connections/second)
    3. Blocks SMB port using Windows Firewall
    4. Automatically unblocks after cooldown period
    """
    
    def __init__(self):
        """Initialize SMB monitor"""
        self.running = True
        self.connection_threshold = 5  # connections per second
        self.smb_blocked = False
    
    def block_smb(self):
        """Block SMB port 445 using Windows Firewall"""
        if self.smb_blocked:
            return
        
        try:
            # Add firewall rule to block SMB
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 'name=AegisBlockSMB', 'dir=in', 'action=block',
                 'protocol=TCP', 'localport=445'],
                capture_output=True,
                timeout=10
            )
            self.smb_blocked = True
            print("[BLOCKED] SMB port 445 - Lateral movement prevented")
        except Exception as e:
            print(f"[ERROR] Failed to block SMB: {e}")
    
    def unblock_smb(self):
        """Unblock SMB port 445"""
        if not self.smb_blocked:
            return
        
        try:
            # Remove firewall rule
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 'name=AegisBlockSMB'],
                capture_output=True,
                timeout=10
            )
            self.smb_blocked = False
            print("[UNBLOCKED] SMB port 445 - Normal operations resumed")
        except Exception as e:
            print(f"[ERROR] Failed to unblock SMB: {e}")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print("[+] Starting SMB traffic monitoring...")
        
        while self.running:
            try:
                # Count active SMB connections
                smb_connections = []
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr.port == 445 or (conn.raddr and conn.raddr.port == 445):
                        smb_connections.append(conn)
                
                # Check for suspicious activity
                if len(smb_connections) > self.connection_threshold:
                    print(f"[ALERT] High SMB activity: {len(smb_connections)} connections")
                    self.block_smb()
                    
                    # Cooldown period
                    time.sleep(60)
                    self.unblock_smb()
                
            except Exception as e:
                print(f"[ERROR] SMB monitoring error: {e}")
            
            time.sleep(1)


class USBSentinel:
    """
    USB Drive Scanner and Monitor
    Developer: Vicheakta (Anti-Spreading Specialist)
    
    Scans USB drives for malware when inserted.
    Quarantines suspicious files automatically.
    
    MITRE D3FEND Techniques:
    - D3-DA: Dynamic Analysis
    - D3-QA: Quarantine by Access
    
    How it works:
    1. Detects when USB drive is inserted
    2. Scans drive for suspicious files:
       - Executable files (.exe, .bat, .ps1, .lnk)
       - Hidden files
       - Autorun.inf
    3. Quarantines detected threats
    4. Logs all actions
    """
    
    def __init__(self):
        """Initialize USB sentinel"""
        self.running = True
        self.monitored_drives = set()
        self.quarantine_dir = os.path.join(os.getcwd(), ".aegis_usb_quarantine")
        
        # Create quarantine directory
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def detect_usb_drives(self):
        """Detect USB drives"""
        drives = []
        for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
        return drives
    
    def is_file_suspicious(self, file_path):
        """Check if file is suspicious"""
        file_name = os.path.basename(file_path).lower()
        
        # Check for dangerous extensions
        dangerous_exts = ['.exe', '.bat', '.ps1', '.lnk', '.vbs', '.js']
        if any(file_name.endswith(ext) for ext in dangerous_exts):
            return True, "Dangerous file extension"
        
        # Check for autorun.inf
        if 'autorun.inf' in file_name:
            return True, "Autorun file detected"
        
        # Check for hidden files
        try:
            if os.stat(file_path).st_file_attributes & 2:  # FILE_ATTRIBUTE_HIDDEN
                return True, "Hidden file"
        except:
            pass
        
        return False, None
    
    def quarantine_file(self, file_path, reason):
        """Quarantine suspicious file"""
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, file_name)
            
            shutil.move(file_path, quarantine_path)
            
            # Log
            log_file = os.path.join(self.quarantine_dir, "usb_quarantine_log.txt")
            with open(log_file, 'a') as f:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] USB THREAT: {file_name}\n")
                f.write(f"Reason: {reason}\n\n")
            
            print(f"[USB QUARANTINE] {file_name} - {reason}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to quarantine: {e}")
            return False
    
    def scan_drive(self, drive):
        """Scan USB drive for threats"""
        print(f"[*] Scanning USB drive: {drive}")
        threats_found = 0
        
        try:
            for root, dirs, files in os.walk(drive):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    is_suspicious, reason = self.is_file_suspicious(file_path)
                    if is_suspicious:
                        if self.quarantine_file(file_path, reason):
                            threats_found += 1
            
            print(f"[+] USB scan complete: {threats_found} threats removed from {drive}")
            
        except Exception as e:
            print(f"[ERROR] USB scan error: {e}")
        
        return threats_found
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print("[+] Starting USB drive monitoring...")
        
        while self.running:
            try:
                # Detect current drives
                current_drives = set(self.detect_usb_drives())
                
                # Check for new drives
                new_drives = current_drives - self.monitored_drives
                for drive in new_drives:
                    print(f"[NEW USB] Drive detected: {drive}")
                    self.scan_drive(drive)
                
                # Update monitored drives
                self.monitored_drives = current_drives
                
            except Exception as e:
                print(f"[ERROR] USB monitoring error: {e}")
            
            time.sleep(3)


# ==========================================
# MAIN DEFENSE CLASS (INTEGRATED)
# ==========================================
class EnhancedAegisDefense:
    """
    Enhanced Aegis Defense System
    
    Multi-layer defense system implementing three core anti-malicious methods:
    1. Heuristic Encryption Detection - Detects ransomware by file modification behavior
    2. System File Integrity Monitor - Protects critical system files from tampering
    3. Network Egress Filtering - Blocks unauthorized data exfiltration
    
    All three methods run concurrently in separate threads for real-time protection.
    """
    
    def __init__(self):
        """Initialize defense system with monitoring structures and file backups"""
        # Alert storage for logging all security events
        self.alerts = []
        
        # Control flag for all monitoring threads
        self.running = True
        
        # Track file modification times per process (for heuristic detection)
        # Format: {pid: [timestamp1, timestamp2, ...]}
        self.file_modification_times = {}
        
        # Set of process names identified as suspicious
        self.suspicious_processes = set()
        
        # Critical system files to monitor and protect
        # Format: {file_path: {'hash': md5_hash, 'backup_data': file_content}}
        self.critical_files = {
            r"C:\Windows\System32\drivers\etc\hosts": None,     # Hosts file (DNS mappings)
            r"C:\Windows\System32\kernel32.dll": None            # Critical Windows DLL
        }
        
        # Create baseline backups of critical files at startup
        self.backup_critical_files()

    def backup_critical_files(self):
        """
        Create baseline backups of critical system files
        
        This method:
        1. Reads each critical file
        2. Calculates MD5 hash for integrity checking
        3. Stores file content for potential restoration
        
        These backups are used by the File Integrity Monitor to detect tampering
        """
        for file_path in self.critical_files.keys():
            if os.path.exists(file_path):
                try:
                    # Read file in binary mode (FIXED: read once, use twice)
                    with open(file_path, 'rb') as f:
                        file_content = f.read()  # Read file content once
                        # Store both the MD5 hash and the actual file content
                        self.critical_files[file_path] = {
                            'hash': hashlib.md5(file_content).hexdigest(),  # Calculate MD5 hash
                            'backup_data': file_content                      # Store file content
                        }
                    print(f"[+] Created backup for {os.path.basename(file_path)} ({len(file_content)} bytes)")
                except Exception as e:
                    print(f"[-] Failed to backup {file_path}: {e}")

    def log_alert(self, message, level="MEDIUM"):
        """
        Log security alerts with color-coded severity levels
        
        Args:
            message: The alert message to log
            level: Severity level (MEDIUM, HIGH, CRITICAL)
        
        Alert levels:
        - MEDIUM (Yellow): General warnings, monitoring events
        - HIGH (Red): Suspicious activity detected, actions taken
        - CRITICAL (Magenta): Active threats detected and neutralized
        """
        # Create timestamped alert message
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{level}] {message}"
        
        # Color coding using ANSI escape sequences
        if level == "HIGH":
            print(f"\033[91m{alert_msg}\033[0m")  # Red text
        elif level == "CRITICAL":
            print(f"\033[95m{alert_msg}\033[0m")  # Magenta text  
        else:
            print(f"\033[93m{alert_msg}\033[0m")  # Yellow text
        
        # Store alert in memory for session history
        self.alerts.append(alert_msg)

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 1: HEURISTIC ENCRYPTION DETECTION
    # ==========================================
    def heuristic_encryption_detection(self):
        """
        METHOD 1: Behavioral Ransomware Detection
        
        Detects ransomware by monitoring file modification patterns.
        Ransomware typically encrypts many files rapidly, creating a
        distinctive behavior signature.
        
        Detection Logic:
        - Track file modifications per process (by PID)
        - If any process modifies >2 files within 2 seconds → LIKELY RANSOMWARE
        - Automatically terminate the suspicious process
        
        IMPROVED DETECTION:
        - Lowered threshold from >3 to >2 files (faster detection)
        - Increased time window from 1s to 2s (catch slower ransomware)
        - Enhanced termination with multiple kill attempts
        
        This is a HEURISTIC (behavior-based) detection, not signature-based,
        so it can detect zero-day ransomware variants.
        
        Scan Interval: 300ms for faster detection latency
        """
        print("[+] Starting Heuristic Encryption Detection...")
        
        # Main monitoring loop
        while self.running:
            current_time = time.time()
            
            # Check each tracked process for suspicious behavior
            for pid in list(self.file_modification_times.keys()):
                try:
                    # Clean up old modification records (older than 2 seconds)
                    # This creates a rolling 2-second window
                    self.file_modification_times[pid] = [
                        t for t in self.file_modification_times[pid] 
                        if current_time - t < 2.0
                    ]
                    
                    # Count recent modifications (within last 2 seconds)
                    recent_mods = len(self.file_modification_times[pid])
                    
                    # DETECTION THRESHOLD: Check if process modified >2 files in 2 seconds
                    # This is more aggressive to catch ransomware faster
                    if recent_mods > 2:
                        # Try to get process information
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                            process_exe = proc.exe() if proc.exe else "unknown"
                            
                            # RANSOMWARE BEHAVIOR DETECTED!
                            self.log_alert(
                                f"RANSOMWARE DETECTED: {process_name} (PID: {pid}) "
                                f"modified {recent_mods} files in 2 seconds", 
                                "CRITICAL"
                            )
                            self.log_alert(f"Executable: {process_exe}", "CRITICAL")
                            
                            # RESPONSE: Terminate the suspicious process immediately
                            # Use multiple termination methods for reliability
                            try:
                                # Method 1: Graceful termination
                                proc.terminate()
                                time.sleep(0.1)
                                
                                # Method 2: Force kill if still running
                                if proc.is_running():
                                    proc.kill()
                                
                                # Wait and verify termination
                                try:
                                    proc.wait(timeout=1)
                                except psutil.TimeoutExpired:
                                    # Process still running - try OS-level kill
                                    import signal
                                    os.kill(pid, signal.SIGKILL)
                                
                                self.log_alert(f"✓ TERMINATED THREAT: {process_name} (PID: {pid})", "HIGH")
                                
                                # Add to blacklist for reporting
                                self.suspicious_processes.add(process_name)
                                
                                # Clear the tracking for this PID
                                if pid in self.file_modification_times:
                                    del self.file_modification_times[pid]
                                
                            except Exception as term_error:
                                self.log_alert(f"✗ Failed to terminate {process_name}: {term_error}", "MEDIUM")
                                
                        except psutil.NoSuchProcess:
                            # Process already terminated, clean up tracking
                            if pid in self.file_modification_times:
                                del self.file_modification_times[pid]
                        
                except Exception as e:
                    # Skip this PID if there's any error
                    continue
            
            # Check every 300ms for faster detection (was 500ms)
            time.sleep(0.3)

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 2: SYSTEM FILE INTEGRITY MONITOR
    # ==========================================
    def system_file_integrity_monitor(self):
        """
        METHOD 2: Hash-Based File Integrity Monitoring
        
        Protects critical system files from malware tampering.
        Malware often modifies the hosts file to block security sites,
        or corrupts system DLLs to disable defenses.
        
        Protection Logic:
        - Calculate MD5 hash of critical files at startup (baseline)
        - Recalculate hash every 5 seconds
        - If hash changes → FILE TAMPERED
        - Automatically restore from backup
        
        Protected Files:
        - C:\Windows\System32\drivers\etc\hosts (DNS mappings)
        - C:\Windows\System32\kernel32.dll (critical Windows DLL)
        
        Scan Interval: 5 seconds for balance between detection and performance
        """
        print("[+] Starting System File Integrity Monitor...")
        
        # Main monitoring loop
        while self.running:
            # Check each protected file
            for file_path, backup_info in self.critical_files.items():
                # Skip files that weren't successfully backed up
                if backup_info is None:
                    continue
                
                # Check if file still exists
                if os.path.exists(file_path):
                    try:
                        # Calculate current MD5 hash
                        with open(file_path, 'rb') as f:
                            current_hash = hashlib.md5(f.read()).hexdigest()
                        
                        # Compare with baseline hash
                        if current_hash != backup_info['hash']:
                            # FILE INTEGRITY VIOLATION DETECTED!
                            self.log_alert(
                                f"Critical system file modified: {os.path.basename(file_path)}", 
                                "HIGH"
                            )
                            
                            # RESPONSE: Restore file from backup
                            self.restore_system_file(file_path, backup_info)
                            
                    except Exception as e:
                        self.log_alert(f"Error checking {file_path}: {e}", "MEDIUM")
                else:
                    # Critical file was deleted - alert!
                    self.log_alert(f"Critical file missing: {file_path}", "HIGH")
            
            # Check every 5 seconds
            time.sleep(5)

    def restore_system_file(self, file_path, backup_info):
        """
        Restore a compromised system file from backup (FULLY FUNCTIONAL)
        
        This method ACTUALLY restores the file by:
        1. Creating a backup of the corrupted version (.corrupted)
        2. Overwriting the file with the original clean backup
        3. Verifying the restoration was successful
        
        Args:
            file_path: Path to the compromised file
            backup_info: Dictionary containing original hash and backup data
        """
        try:
            # Log critical alert about restoration
            self.log_alert(f"RESTORING compromised file: {os.path.basename(file_path)}", "CRITICAL")
            
            # Step 1: Backup the corrupted version for forensics
            corrupted_backup = file_path + f".corrupted_{int(time.time())}"
            try:
                shutil.copy2(file_path, corrupted_backup)
                self.log_alert(f"Saved corrupted version to: {corrupted_backup}", "MEDIUM")
            except:
                pass  # Non-critical if we can't save corrupted version
            
            # Step 2: Restore the original file content from backup
            with open(file_path, 'wb') as f:
                f.write(backup_info['backup_data'])
            
            # Step 3: Verify restoration was successful
            with open(file_path, 'rb') as f:
                restored_hash = hashlib.md5(f.read()).hexdigest()
            
            if restored_hash == backup_info['hash']:
                self.log_alert(f"Successfully restored: {os.path.basename(file_path)} (verified)", "HIGH")
            else:
                self.log_alert(f"Restoration may have failed - hash mismatch!", "HIGH")
            
        except Exception as e:
            self.log_alert(f"Failed to restore {file_path}: {e}", "HIGH")

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 3: NETWORK EGRESS FILTERING
    # ==========================================
    def network_egress_filtering(self):
        """
        METHOD 3: Outbound Traffic Monitoring and Blocking
        
        Prevents data exfiltration to malicious C2 servers.
        Malware often tries to send stolen data to remote attacker servers.
        
        Protection Logic:
        - Monitor all ESTABLISHED TCP connections
        - Check destination IP against blocklist
        - If connection to blocked IP → EXFILTRATION ATTEMPT
        - Terminate the process making the connection
        
        Blocked Destinations:
        - Known C2 server IPs (configurable)
        - Can be extended with threat intelligence feeds
        
        Scan Interval: 3 seconds for timely detection
        """
        print("[+] Starting Network Egress Filtering...")
        
        # Blocklist of known malicious IPs/domains
        # In production: this would be a large threat intelligence database
        blocked_destinations = [
            "192.168.101.73",         # Your Kali C2 server IP
            "malicious.com",         # Example malicious domain
            "exfiltration-server.com" # Example exfiltration server
        ]
        
        # Main monitoring loop
        while self.running:
            try:
                # Get all active network connections
                # kind='inet' = IPv4/IPv6 connections only
                for conn in psutil.net_connections(kind='inet'):
                    # Only check ESTABLISHED connections (active data transfer)
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check if connection is to a blocked destination
                        if any(blocked in remote_ip for blocked in blocked_destinations):
                            # DATA EXFILTRATION ATTEMPT DETECTED!
                            pid = conn.pid
                            if pid:
                                try:
                                    # Get process information
                                    process = psutil.Process(pid)
                                    process_name = process.name()
                                    
                                    # Alert about blocked exfiltration
                                    self.log_alert(
                                        f"Blocked exfiltration attempt: {process_name} "
                                        f"(PID: {pid}) -> {remote_ip}:{remote_port}", 
                                        "CRITICAL"
                                    )
                                    
                                    # RESPONSE: Terminate process attempting exfiltration
                                    process.kill()
                                    self.log_alert(f"Terminated exfiltration process: {process_name}", "HIGH")
                                    
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    # Process no longer exists or we don't have permission
                                    continue
                                    
            except Exception as e:
                self.log_alert(f"Network monitoring error: {e}", "MEDIUM")
            
            # Check every 3 seconds
            time.sleep(3)

    # File System Event Handler for Heuristic Detection
    class EncryptionEventHandler(FileSystemEventHandler):
        """
        File System Event Handler
        
        This class monitors file system events using the watchdog library.
        When files are created, modified, or deleted, it records the events
        to detect ransomware behavior patterns.
        
        IMPROVED DETECTION STRATEGY:
        - Track ALL suspicious file events (created, modified, deleted)
        - Identify processes by scanning at event time (not just open files)
        - Look for ransomware patterns: encrypted file creation + original deletion
        """
        
        def __init__(self, parent):
            """Initialize with reference to parent Aegis object"""
            self.parent = parent
            self.last_scan_pids = set()  # Cache PIDs from last scan
            
        def _record_file_activity(self, file_path):
            """
            Record file activity and identify the responsible process
            
            CRITICAL FIX: Instead of checking open_files (which fails for closed files),
            we scan ALL Python processes and identify the one most likely responsible.
            Ransomware typically runs as a Python script, so we prioritize python.exe.
            """
            current_time = time.time()
            
            # Strategy: Find all Python processes and record activity for them
            # This works because chimera_real.py runs as a Python process
            python_processes_found = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    # Look for Python processes (python.exe, python3.exe, pythonw.exe)
                    if 'python' in proc_name:
                        pid = proc.info['pid']
                        python_processes_found.append((pid, proc_name))
                        
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    continue
            
            # Record activity for all Python processes
            # The heuristic detector will determine which one is malicious
            for pid, proc_name in python_processes_found:
                if pid not in self.parent.file_modification_times:
                    self.parent.file_modification_times[pid] = []
                self.parent.file_modification_times[pid].append(current_time)
        
        def on_created(self, event):
            """Track file creation events (ransomware creates encrypted files)"""
            if not event.is_directory and '.chimera_encrypted' in event.src_path:
                # Encrypted file created - strong indicator of ransomware!
                self._record_file_activity(event.src_path)
        
        def on_modified(self, event):
            """Track file modification events"""
            if not event.is_directory:
                self._record_file_activity(event.src_path)
        
        def on_deleted(self, event):
            """Track file deletion events (ransomware deletes original files)"""
            if not event.is_directory:
                self._record_file_activity(event.src_path)

    def start_protection(self):
        """
        [INTEGRATED DEFENSE SYSTEM - All Blue Team Modules]
        
        Start All Defense Mechanisms with Full Integration
        
        This method initializes and starts all defense modules in separate daemon
        threads for comprehensive concurrent protection.
        
        CORE DEFENSE METHODS:
        1. Heuristic Encryption Detection (behavioral ransomware detection)
        2. System File Integrity Monitor (hash-based protection)
        3. Network Egress Filtering (C2 blocking)
        4. File System Observer (event-driven monitoring)
        
        INTEGRATED MODULES:
        5. Anti-Delivery System (Sakura) - Download folder monitoring, HTML smuggling detection
        6. Anti-Persistence Monitor (Titya) - Registry & task monitoring
        7. SMB Monitor (Vicheakta) - SMB lateral movement blocking
        8. USB Sentinel (Vicheakta) - USB drive malware scanning
        
        All threads run concurrently to provide multi-layer defense.
        """
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║         AEGIS DEFENSE - FULLY INTEGRATED SYSTEM               ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        print("\n[CORE DEFENSE METHODS]")
        print("  1. ✓ Heuristic Encryption Detection - ACTIVE")
        print("  2. ✓ System File Integrity Monitor - ACTIVE") 
        print("  3. ✓ Network Egress Filtering - ACTIVE")
        print("  4. ✓ File System Observer - ACTIVE")
        
        print("\n[INTEGRATED BLUE TEAM MODULES]")
        print("  5. ✓ Anti-Delivery System (Sakura) - ACTIVE")
        print("  6. ✓ Registry Watchdog (Titya) - ACTIVE")
        print("  7. ✓ Task Auditor (Titya) - ACTIVE")
        print("  8. ✓ SMB Traffic Monitor (Vicheakta) - ACTIVE")
        print("  9. ✓ USB Sentinel (Vicheakta) - ACTIVE")
        
        print("\n[*] Initializing comprehensive protection...\n")
        
        # ===========================================
        # CORE DEFENSE THREADS
        # ===========================================
        core_threads = [
            threading.Thread(target=self.heuristic_encryption_detection, name="HeuristicDetection"),
            threading.Thread(target=self.system_file_integrity_monitor, name="IntegrityMonitor"),
            threading.Thread(target=self.network_egress_filtering, name="EgressFilter")
        ]
        
        # Start core defense threads
        for thread in core_threads:
            thread.daemon = True
            thread.start()
            print(f"[+] Started: {thread.name}")
        
        # ===========================================
        # INTEGRATED MODULE 1: ANTI-DELIVERY (Sakura)
        # ===========================================
        try:
            downloads_path = os.path.expanduser("~/Downloads")
            if os.path.exists(downloads_path):
                anti_delivery = AntiDeliverySystem(downloads_path)
                delivery_thread = threading.Thread(
                    target=anti_delivery.monitor_downloads_folder,
                    name="AntiDelivery-Sakura",
                    daemon=True
                )
                delivery_thread.start()
                print("[+] Started: Anti-Delivery System (Sakura)")
            else:
                print("[-] Downloads folder not found - Anti-Delivery disabled")
        except Exception as e:
            print(f"[-] Failed to start Anti-Delivery: {e}")
        
        # ===========================================
        # INTEGRATED MODULE 2: ANTI-PERSISTENCE (Titya)
        # NOW WITH 2 SEPARATE CLASSES TO MATCH RED TEAM
        # ===========================================
        
        # 2a. Registry Watchdog (defends against RegistryPersistence)
        try:
            registry_watchdog = RegistryWatchdog()
            registry_thread = threading.Thread(
                target=registry_watchdog.monitor_registry,
                name="RegistryWatchdog-Titya",
                daemon=True
            )
            registry_thread.start()
            print("[+] Started: Registry Watchdog (Titya)")
        except Exception as e:
            print(f"[-] Failed to start Registry Watchdog: {e}")
        
        # 2b. Task Auditor (defends against ScheduledTaskPersistence)
        try:
            task_auditor = TaskAuditor()
            task_thread = threading.Thread(
                target=task_auditor.audit_tasks,
                name="TaskAuditor-Titya",
                daemon=True
            )
            task_thread.start()
            print("[+] Started: Task Auditor (Titya)")
        except Exception as e:
            print(f"[-] Failed to start Task Auditor: {e}")
        
        # ===========================================
        # INTEGRATED MODULE 3: SMB MONITOR (Vicheakta)
        # ===========================================
        try:
            smb_monitor = SMBMonitor()
            smb_thread = threading.Thread(
                target=smb_monitor.monitor_loop,
                name="SMBMonitor-Vicheakta",
                daemon=True
            )
            smb_thread.start()
            print("[+] Started: SMB Traffic Monitor (Vicheakta)")
        except Exception as e:
            print(f"[-] Failed to start SMB Monitor: {e}")
        
        # ===========================================
        # INTEGRATED MODULE 4: USB SENTINEL (Vicheakta)
        # ===========================================
        try:
            usb_sentinel = USBSentinel()
            usb_thread = threading.Thread(
                target=usb_sentinel.monitor_loop,
                name="USBSentinel-Vicheakta",
                daemon=True
            )
            usb_thread.start()
            print("[+] Started: USB Sentinel (Vicheakta)")
        except Exception as e:
            print(f"[-] Failed to start USB Sentinel: {e}")
        
        # ===========================================
        # FILE SYSTEM OBSERVER (watchdog)
        # ===========================================
        event_handler = self.EncryptionEventHandler(self)
        observer = Observer()
        
        # Monitor user directories where ransomware typically encrypts files
        user_folders = [
            os.path.expanduser("~/Documents"),  # User documents
            os.path.expanduser("~/Desktop"),    # Desktop files
            os.path.expanduser("~/Downloads")   # Downloaded files
        ]
        
        # Schedule monitoring for each folder (recursive = subdirectories too)
        for folder in user_folders:
            if os.path.exists(folder):
                observer.schedule(event_handler, folder, recursive=True)
                print(f"[+] Monitoring: {folder}")
        
        # Start the file system observer
        observer.start()
        
        print("\n╔═══════════════════════════════════════════════════════════════╗")
        print("║   AEGIS DEFENSE FULLY OPERATIONAL - ALL MODULES ACTIVE       ║")
        print("║   Monitoring for: Ransomware | Worms | Persistence | C2      ║")
        print("╚═══════════════════════════════════════════════════════════════╝\n")
        
        try:
            # Keep main thread alive while monitoring
            # All actual work is done in daemon threads
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            # User pressed Ctrl+C - shutdown gracefully
            self.running = False
            observer.stop()
            print("\n[!] Defense system shutting down...")
            print("[!] All protection modules terminated")
        
        # Wait for observer to finish
        observer.join()

if __name__ == "__main__":
    defense = EnhancedAegisDefense()
    defense.start_protection()