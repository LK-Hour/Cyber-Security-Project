#!/usr/bin/env python3
"""
LNK Verification & Testing Tool
Safely inspect and verify LNK spoofing files without executing them
"""

import win32com.client
import os
import sys
from pathlib import Path
import base64

class LNKVerifier:
    def __init__(self, lnk_path):
        self.lnk_path = lnk_path
        if not os.path.exists(lnk_path):
            print(f"[!] File not found: {lnk_path}")
            sys.exit(1)
    
    def get_lnk_properties(self):
        """Extract all properties from LNK file"""
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(self.lnk_path)
            
            return {
                'path': self.lnk_path,
                'target': shortcut.TargetPath,
                'arguments': shortcut.Arguments,
                'working_dir': shortcut.WorkingDirectory,
                'icon': shortcut.IconLocation,
                'description': shortcut.Description,
                'hotkey': shortcut.Hotkey,
                'window_style': shortcut.WindowStyle,
            }
        except Exception as e:
            print(f"[!] Error reading LNK: {e}")
            return None
    
    def decode_powershell_command(self, args_string):
        """Decode base64 PowerShell command if present"""
        try:
            if "-EncodedCommand" in args_string:
                # Extract base64 string
                start = args_string.find("-EncodedCommand") + len("-EncodedCommand")
                b64_string = args_string[start:].strip()
                
                # Decode from UTF-16
                decoded = base64.b64decode(b64_string)
                powershell_command = decoded.decode('utf-16-le', errors='ignore')
                
                return powershell_command
        except Exception as e:
            print(f"[!] Error decoding: {e}")
        
        return None
    
    def analyze(self):
        """Analyze LNK file and print results"""
        print("\n" + "="*70)
        print("LNK SPOOFING VERIFICATION TOOL")
        print("="*70)
        
        props = self.get_lnk_properties()
        
        if not props:
            print("[!] Failed to analyze LNK file")
            return False
        
        print(f"\n[*] File: {props['path']}")
        print(f"[*] File Size: {os.path.getsize(self.lnk_path)} bytes")
        
        print("\n[*] SHORTCUT PROPERTIES:")
        print(f"    Target:         {props['target']}")
        print(f"    Arguments:      {props['arguments'][:60]}..." if len(props['arguments']) > 60 else f"    Arguments:      {props['arguments']}")
        print(f"    Working Dir:    {props['working_dir']}")
        print(f"    Icon:           {props['icon']}")
        print(f"    Description:    {props['description']}")
        
        # Decode PowerShell command
        if props['arguments']:
            decoded_cmd = self.decode_powershell_command(props['arguments'])
            if decoded_cmd:
                print(f"\n[*] DECODED POWERSHELL COMMAND:")
                print(f"    {decoded_cmd}")
                
                # Analyze the command
                if "DownloadFile" in decoded_cmd:
                    print("\n[!] MALICIOUS INDICATORS:")
                    print("    ✓ Contains file download command")
                    
                    # Extract URL
                    try:
                        start = decoded_cmd.find('("http') + 2
                        end = decoded_cmd.find('"', start)
                        url = decoded_cmd[start:end-1]
                        print(f"    ✓ Download URL: {url}")
                    except:
                        pass
                    
                    # Extract output path
                    try:
                        start = decoded_cmd.find('","') + 3
                        end = decoded_cmd.find('"', start)
                        output = decoded_cmd[start:end]
                        print(f"    ✓ Save location: {output}")
                    except:
                        pass
                
                if "Start-Process" in decoded_cmd:
                    print("    ✓ Contains process execution")
        
        # Check for spoofing indicators
        print(f"\n[*] SPOOFING ANALYSIS:")
        filename = os.path.basename(self.lnk_path)
        
        if ".pdf.lnk" in filename:
            print("    ✓ Filename contains .pdf (appears as PDF to users)")
        
        if props['icon'] == "shell32.dll,3":
            print("    ✓ Using shell32.dll,3 (standard PDF icon)")
        
        if "-WindowStyle Hidden" in props['arguments']:
            print("    ✓ PowerShell runs in hidden mode (no window visible)")
        
        if "-NoProfile" in props['arguments']:
            print("    ✓ No profile loading (faster execution)")
        
        if "-ExecutionPolicy Bypass" in props['arguments']:
            print("    ✓ Execution policy bypassed")
        
        print("\n[*] SPOOFING VERDICT: " + ("✓ PROPERLY CONFIGURED" if all([
            ".pdf" in filename,
            props['icon'] == "shell32.dll,3",
            "-WindowStyle Hidden" in props['arguments']
        ]) else "✗ INCOMPLETE CONFIGURATION"))
        
        print("\n" + "="*70)
        return True


def verify_all_lnks():
    """Verify all LNK files in example_payloads directory"""
    payloads_dir = "example_payloads"
    
    if not os.path.exists(payloads_dir):
        print(f"[!] Directory not found: {payloads_dir}")
        return
    
    lnk_files = list(Path(payloads_dir).glob("*.lnk"))
    
    if not lnk_files:
        print(f"[!] No LNK files found in {payloads_dir}")
        return
    
    print(f"\n[*] Found {len(lnk_files)} LNK files")
    
    for lnk_file in lnk_files:
        verifier = LNKVerifier(str(lnk_file))
        verifier.analyze()
        print("\n")


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     LNK SPOOFING VERIFICATION TOOL v1.0                   ║
    ║   Safely inspect LNK files without executing them         ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) > 1:
        # Verify specific file
        lnk_path = sys.argv[1]
        verifier = LNKVerifier(lnk_path)
        verifier.analyze()
    else:
        # Verify all files in example_payloads
        verify_all_lnks()


if __name__ == "__main__":
    main()
