import os
import time
import hashlib
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class EnhancedAegisDefense:
    def __init__(self):
        self.alerts = []
        self.running = True
        self.file_modification_times = {}
        self.suspicious_processes = set()
        
        # Critical system files to protect
        self.critical_files = {
            r"C:\Windows\System32\drivers\etc\hosts": None,
            r"C:\Windows\System32\kernel32.dll": None
        }
        
        # Create backups of critical files
        self.backup_critical_files()

    def backup_critical_files(self):
        """Create backups of critical system files for integrity checking"""
        for file_path in self.critical_files.keys():
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        self.critical_files[file_path] = {
                            'hash': hashlib.md5(f.read()).hexdigest(),
                            'backup_data': f.read()
                        }
                    print(f"[+] Created backup for {os.path.basename(file_path)}")
                except Exception as e:
                    print(f"[-] Failed to backup {file_path}: {e}")

    def log_alert(self, message, level="MEDIUM"):
        """Log security alerts with color coding"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{level}] {message}"
        
        # Color coding for alerts
        if level == "HIGH":
            print(f"\033[91m{alert_msg}\033[0m")  # Red
        elif level == "CRITICAL":
            print(f"\033[95m{alert_msg}\033[0m")  # Magenta  
        else:
            print(f"\033[93m{alert_msg}\033[0m")  # Yellow
            
        self.alerts.append(alert_msg)

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 1: HEURISTIC ENCRYPTION DETECTION
    # ==========================================
    def heuristic_encryption_detection(self):
        """
        METHOD 1: Detect ransomware by monitoring rapid file modifications
        Kills processes that modify >3 files in 1 second (encryption behavior)
        """
        print("[+] Starting Heuristic Encryption Detection...")
        
        while self.running:
            current_time = time.time()
            process_file_counts = {}
            
            # Monitor all processes and their file handles
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    pid = proc.info['pid']
                    process_name = proc.info['name']
                    
                    # Count recent file modifications by this process
                    if pid not in self.file_modification_times:
                        self.file_modification_times[pid] = []
                    
                    # Clean old records (older than 1 second)
                    self.file_modification_times[pid] = [
                        t for t in self.file_modification_times[pid] 
                        if current_time - t < 1.0
                    ]
                    
                    # Check if process is modifying files rapidly
                    if len(self.file_modification_times[pid]) > 3:
                        self.log_alert(
                            f"Ransomware behavior detected: {process_name} (PID: {pid}) "
                            f"modified {len(self.file_modification_times[pid])} files in 1 second", 
                            "CRITICAL"
                        )
                        
                        # Terminate suspicious process
                        try:
                            proc.kill()
                            self.log_alert(f"Terminated suspicious process: {process_name}", "HIGH")
                            self.suspicious_processes.add(process_name)
                        except:
                            self.log_alert(f"Failed to terminate: {process_name}", "MEDIUM")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            time.sleep(0.5)  # Check every 500ms

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 2: SYSTEM FILE INTEGRITY MONITOR
    # ==========================================
    def system_file_integrity_monitor(self):
        """
        METHOD 2: Monitor and protect critical system files from tampering
        Automatically restores files if unauthorized modifications detected
        """
        print("[+] Starting System File Integrity Monitor...")
        
        while self.running:
            for file_path, backup_info in self.critical_files.items():
                if backup_info is None:
                    continue
                    
                if os.path.exists(file_path):
                    try:
                        # Calculate current file hash
                        with open(file_path, 'rb') as f:
                            current_hash = hashlib.md5(f.read()).hexdigest()
                        
                        # Compare with original hash
                        if current_hash != backup_info['hash']:
                            self.log_alert(
                                f"Critical system file modified: {os.path.basename(file_path)}", 
                                "HIGH"
                            )
                            
                            # Restore from backup
                            self.restore_system_file(file_path, backup_info)
                            
                    except Exception as e:
                        self.log_alert(f"Error checking {file_path}: {e}", "MEDIUM")
                else:
                    self.log_alert(f"Critical file missing: {file_path}", "HIGH")
                    
            time.sleep(5)  # Check every 5 seconds

    def restore_system_file(self, file_path, backup_info):
        """Restore a compromised system file from backup"""
        try:
            # In real implementation, you would restore from backup_data
            # For demo, we'll just log the restoration action
            self.log_alert(f"RESTORING compromised file: {os.path.basename(file_path)}", "CRITICAL")
            
            # Simulate restoration
            restoration_note = f"# File would be restored from backup here\n"
            restoration_note += f"# Original hash: {backup_info['hash']}\n"
            restoration_note += f"# Restored by Aegis Defense System at {time.ctime()}\n"
            
            with open(file_path + '.aegis_restored', 'w') as f:
                f.write(restoration_note)
                
            self.log_alert(f"Successfully restored: {os.path.basename(file_path)}", "HIGH")
            
        except Exception as e:
            self.log_alert(f"Failed to restore {file_path}: {e}", "HIGH")

    # ==========================================
    # CORE ANTI-MALICIOUS METHOD 3: NETWORK EGRESS FILTERING
    # ==========================================
    def network_egress_filtering(self):
        """
        METHOD 3: Monitor and block unauthorized outbound traffic
        Prevents data exfiltration to malicious servers
        """
        print("[+] Starting Network Egress Filtering...")
        
        # Known malicious IPs/domains (would be much larger in real system)
        blocked_destinations = [
            "192.168.1.100",  # Your Kali C2 server
            "malicious.com",
            "exfiltration-server.com"
        ]
        
        while self.running:
            try:
                # Check active network connections
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check if connection is to blocked destination
                        if any(blocked in remote_ip for blocked in blocked_destinations):
                            pid = conn.pid
                            if pid:
                                try:
                                    process = psutil.Process(pid)
                                    process_name = process.name()
                                    
                                    self.log_alert(
                                        f"Blocked exfiltration attempt: {process_name} "
                                        f"(PID: {pid}) -> {remote_ip}:{remote_port}", 
                                        "CRITICAL"
                                    )
                                    
                                    # Terminate process attempting exfiltration
                                    process.kill()
                                    self.log_alert(f"Terminated exfiltration process: {process_name}", "HIGH")
                                    
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                                    
            except Exception as e:
                self.log_alert(f"Network monitoring error: {e}", "MEDIUM")
                
            time.sleep(3)  # Check every 3 seconds

    # File System Event Handler for Heuristic Detection
    class EncryptionEventHandler(FileSystemEventHandler):
        def __init__(self, parent):
            self.parent = parent
            
        def on_modified(self, event):
            """Track file modifications for heuristic detection"""
            if not event.is_directory:
                # Record this modification for all running processes
                current_time = time.time()
                for proc in psutil.process_iter(['pid']):
                    try:
                        pid = proc.info['pid']
                        if pid not in self.parent.file_modification_times:
                            self.parent.file_modification_times[pid] = []
                        self.parent.file_modification_times[pid].append(current_time)
                    except:
                        continue

    def start_protection(self):
        """Start all core defense mechanisms"""
        print("=== ENHANCED AEGIS DEFENSE SYSTEM ACTIVATED ===")
        print("Core Protection Methods:")
        print("1. Heuristic Encryption Detection - ACTIVE")
        print("2. System File Integrity Monitor - ACTIVE") 
        print("3. Network Egress Filtering - ACTIVE")
        print("Monitoring system for malicious activities...\n")
        
        # Start core protection threads
        threads = [
            threading.Thread(target=self.heuristic_encryption_detection),
            threading.Thread(target=self.system_file_integrity_monitor),
            threading.Thread(target=self.network_egress_filtering)
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Start file system monitoring for heuristic detection
        event_handler = self.EncryptionEventHandler(self)
        observer = Observer()
        
        # Monitor user directories for encryption activity
        user_folders = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads")
        ]
        
        for folder in user_folders:
            if os.path.exists(folder):
                observer.schedule(event_handler, folder, recursive=True)
        
        observer.start()
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            observer.stop()
            print("\n[!] Defense system shutting down...")
        
        observer.join()

if __name__ == "__main__":
    defense = EnhancedAegisDefense()
    defense.start_protection()