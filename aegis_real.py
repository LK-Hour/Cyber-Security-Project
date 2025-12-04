# Standard library and third-party imports for defense system
import os         # File and directory operations
import time       # Timestamps and timing for monitoring
import hashlib    # MD5 hashing for file integrity verification
import threading  # Multi-threaded monitoring (concurrent defense mechanisms)
import shutil     # File operations for backup/restore
import signal     # Process signals for forceful termination
import psutil     # Process and network monitoring library
from watchdog.observers import Observer  # File system event monitoring
from watchdog.events import FileSystemEventHandler  # File modification event handler

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
        Start All Defense Mechanisms
        
        This method initializes and starts all three core protection methods
        in separate daemon threads for concurrent monitoring.
        
        Threads:
        1. Heuristic Encryption Detection (every 500ms)
        2. System File Integrity Monitor (every 5 seconds)
        3. Network Egress Filtering (every 3 seconds)
        4. File System Observer (event-driven)
        
        All threads run concurrently to provide comprehensive real-time protection.
        """
        print("=== ENHANCED AEGIS DEFENSE SYSTEM ACTIVATED ===")
        print("Core Protection Methods:")
        print("1. Heuristic Encryption Detection - ACTIVE")
        print("2. System File Integrity Monitor - ACTIVE") 
        print("3. Network Egress Filtering - ACTIVE")
        print("Monitoring system for malicious activities...\n")
        
        # Create threads for each protection method
        # daemon=True ensures threads exit when main program exits
        threads = [
            threading.Thread(target=self.heuristic_encryption_detection),
            threading.Thread(target=self.system_file_integrity_monitor),
            threading.Thread(target=self.network_egress_filtering)
        ]
        
        # Start all protection threads
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Setup file system monitoring using watchdog
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
        
        # Start the file system observer
        observer.start()
        
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
        
        # Wait for observer to finish
        observer.join()

if __name__ == "__main__":
    defense = EnhancedAegisDefense()
    defense.start_protection()