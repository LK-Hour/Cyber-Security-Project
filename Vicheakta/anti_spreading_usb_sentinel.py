"""
Anti-Spreading Module: USB Sentinel
Developer: Penh Sovicheakta
Purpose: Monitor and scan USB drives for malware

Project Spec: "USB Auto-Scan: A service that automatically scans any 
new USB drive for hidden files and executable extensions before mounting it."
"""

import time
import threading
import os
import string
import shutil
import platform
from pathlib import Path

class USBSentinel:
    """Monitor USB drives and quarantine suspicious files"""
    
    def __init__(self):
        self.running = False
        self.known_drives = set()
        self.quarantine_path = Path.home() / "AEGIS_Quarantine"
        self.alerts = []
        self.threats_found = 0
        
        # Dangerous file extensions and names
        self.dangerous_extensions = {
            '.exe', '.lnk', '.scr', '.bat', '.ps1', '.vbs',
            '.cmd', '.com', '.pif', '.msi', '.jar', '.hta'
        }
        
        self.dangerous_files = {
            'autorun.inf', 'desktop.ini', '.lnk'
        }
        
        # Create quarantine folder
        self.quarantine_path.mkdir(exist_ok=True)
    
    def log_alert(self, message):
        """Log alert message"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] {message}"
        self.alerts.append(alert)
        print(alert)
    
    def detect_usb_drives(self):
        """Detect removable USB drives"""
        drives = set()
        
        if platform.system() == "Windows":
            try:
                import ctypes
                for letter in string.ascii_uppercase:
                    drive_path = f"{letter}:\\"
                    if os.path.exists(drive_path):
                        try:
                            # DRIVE_REMOVABLE = 2
                            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                            if drive_type == 2:
                                drives.add(drive_path)
                        except:
                            pass
            except ImportError:
                # Fallback: check all drives except C:
                for letter in string.ascii_uppercase:
                    if letter != 'C':
                        drive_path = f"{letter}:\\"
                        if os.path.exists(drive_path):
                            drives.add(drive_path)
        else:
            # Linux/Mac: Check common mount points
            mount_points = ["/media", "/mnt", "/run/media", "/Volumes"]
            for mount in mount_points:
                if os.path.exists(mount):
                    try:
                        for item in os.listdir(mount):
                            full_path = os.path.join(mount, item)
                            if os.path.ismount(full_path):
                                drives.add(full_path)
                    except:
                        pass
        
        return drives
    
    def is_file_suspicious(self, file_path):
        """Check if a file is suspicious"""
        path = Path(file_path)
        filename = path.name.lower()
        extension = path.suffix.lower()
        
        # Check dangerous extensions
        if extension in self.dangerous_extensions:
            return True, f"Dangerous extension: {extension}"
        
        # Check dangerous filenames
        if filename in self.dangerous_files:
            return True, f"Dangerous file: {filename}"
        
        # Check for hidden executables (double extension)
        if '.pdf.' in filename or '.doc.' in filename or '.jpg.' in filename:
            if extension in self.dangerous_extensions:
                return True, f"Double extension attack: {filename}"
        
        # Check for autorun.inf content
        if filename == 'autorun.inf':
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                    if 'open=' in content or 'shellexecute=' in content:
                        return True, "Autorun with execution command"
            except:
                pass
        
        return False, None
    
    def is_file_hidden(self, file_path):
        """Check if file is hidden"""
        if platform.system() == "Windows":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                # FILE_ATTRIBUTE_HIDDEN = 2, FILE_ATTRIBUTE_SYSTEM = 4
                return attrs != -1 and (attrs & 2 or attrs & 4)
            except:
                return False
        else:
            return os.path.basename(file_path).startswith('.')
    
    def quarantine_file(self, file_path, reason):
        """Move suspicious file to quarantine"""
        try:
            filename = os.path.basename(file_path)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}.QUARANTINED"
            quarantine_dest = self.quarantine_path / quarantine_name
            
            shutil.move(file_path, quarantine_dest)
            
            # Log the quarantine action
            log_file = self.quarantine_path / "quarantine_log.txt"
            with open(log_file, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {file_path} | {reason}\n")
            
            self.threats_found += 1
            return True
            
        except Exception as e:
            self.log_alert(f"[ERROR] Failed to quarantine {file_path}: {e}")
            return False
    
    def scan_drive(self, drive_path):
        """Scan a USB drive for threats"""
        self.log_alert(f"[AEGIS] 🔍 Scanning USB drive: {drive_path}")
        
        threats = []
        scanned_files = 0
        
        try:
            for root, dirs, files in os.walk(drive_path):
                # Check for hidden directories
                for dir_name in dirs[:]:
                    dir_path = os.path.join(root, dir_name)
                    if self.is_file_hidden(dir_path):
                        self.log_alert(f"[WARN] Hidden directory: {dir_path}")
                
                for filename in files:
                    file_path = os.path.join(root, filename)
                    scanned_files += 1
                    
                    # Check if suspicious
                    is_suspicious, reason = self.is_file_suspicious(file_path)
                    
                    # Also flag hidden executables
                    if self.is_file_hidden(file_path):
                        path = Path(file_path)
                        if path.suffix.lower() in self.dangerous_extensions:
                            is_suspicious = True
                            reason = f"Hidden executable: {path.suffix}"
                    
                    if is_suspicious:
                        self.log_alert(f"[THREAT] 🚨 {file_path} → {reason}")
                        threats.append((file_path, reason))
                        
                        # Quarantine the threat
                        if self.quarantine_file(file_path, reason):
                            self.log_alert(f"[AEGIS] ✓ Quarantined: {filename}")
        
        except Exception as e:
            self.log_alert(f"[ERROR] Scan error on {drive_path}: {e}")
        
        self.log_alert(f"[AEGIS] Scan complete: {scanned_files} files, {len(threats)} threats")
        return threats
    
    def monitor_loop(self):
        """Main monitoring loop for USB drives"""
        self.log_alert("[AEGIS] USB Sentinel STARTED - Monitoring for USB drives")
        
        while self.running:
            try:
                current_drives = self.detect_usb_drives()
                
                # Detect new drives
                new_drives = current_drives - self.known_drives
                
                for drive in new_drives:
                    self.log_alert(f"[AEGIS] 💾 New USB detected: {drive}")
                    self.scan_drive(drive)
                
                # Detect removed drives
                removed_drives = self.known_drives - current_drives
                if removed_drives:
                    for drive in removed_drives:
                        self.log_alert(f"[AEGIS] USB removed: {drive}")
                
                self.known_drives = current_drives
                time.sleep(2)  # Check every 2 seconds
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(2)
    
    def start(self):
        """Start USB sentinel in background thread"""
        if self.running:
            return
        
        self.running = True
        self.known_drives = self.detect_usb_drives()  # Get initial state
        
        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def stop(self):
        """Stop USB sentinel"""
        self.running = False
        self.log_alert(f"[AEGIS] USB Sentinel STOPPED - {self.threats_found} threats quarantined")


# Global instance for easy access
_usb_sentinel = None

def start_usb_sentinel():
    """Start USB sentinel - entry point for integration"""
    global _usb_sentinel
    _usb_sentinel = USBSentinel()
    _usb_sentinel.start()
    return _usb_sentinel

def stop_usb_sentinel():
    """Stop USB sentinel"""
    global _usb_sentinel
    if _usb_sentinel:
        _usb_sentinel.stop()


if __name__ == "__main__":
    print("🛡️ AEGIS USB SENTINEL - Anti-Spreading Defense")
    print("=" * 50)
    print("Monitors for USB drives and scans for malware")
    print("Quarantines: .exe, .lnk, .bat, autorun.inf, etc.")
    print("=" * 50)
    print("\nPress Ctrl+C to stop\n")
    
    sentinel = USBSentinel()
    sentinel.running = True
    
    try:
        sentinel.monitor_loop()
    except KeyboardInterrupt:
        print("\n[AEGIS] Shutting down...")
        sentinel.stop()