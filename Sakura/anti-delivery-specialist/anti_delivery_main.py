# anti_delivery_main.py
"""
Anti-Delivery Module: File Scanner & Script Analyzer
Developer: Te Sakura
Purpose: Detect and block malware delivery attempts

Project Spec:
- "Magic Number Analysis: A scanner that checks file headers. 
   It detects if a file claiming to be a PDF is actually an LNK or EXE."
- "Script De-obfuscation: A module that scans HTML files for large 
   Base64 encoded strings (indicative of Smuggling) and blocks them."
"""

import os
import time
from file_signature_scanner import FileSignatureScanner
from script_analyzer import ScriptAnalyzer

class AntiDeliverySystem:
    def __init__(self):
        self.file_scanner = FileSignatureScanner()
        self.script_analyzer = ScriptAnalyzer()
        self.quarantine_folder = "quarantine"
        
        # Create quarantine folder if it doesn't exist
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)
    
    def quarantine_file(self, file_path, reason):
        """Move suspicious file to quarantine"""
        try:
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_folder, 
                                         f"{int(time.time())}_{filename}")
            
            os.rename(file_path, quarantine_path)
            print(f"🚫 QUARANTINED: {filename} - Reason: {reason}")
            print(f"   Moved to: {quarantine_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to quarantine {file_path}: {e}")
            return False
    
    def monitor_downloads_folder(self, downloads_path=None):
        """Monitor downloads folder for suspicious files"""
        if downloads_path is None:
            # Common downloads folders
            downloads_path = os.path.expanduser("~/Downloads")
            if not os.path.exists(downloads_path):
                downloads_path = os.path.expanduser("~/Documents")
        
        print(f"🔍 Monitoring folder: {downloads_path}")
        
        while True:
            try:
                # Scan for new files
                files = [f for f in os.listdir(downloads_path) 
                        if os.path.isfile(os.path.join(downloads_path, f))]
                
                for file in files:
                    file_path = os.path.join(downloads_path, file)
                    
                    # Check file signature
                    sig_result = self.file_scanner.scan_file(file_path)
                    if sig_result.get('is_suspicious', False):
                        self.quarantine_file(file_path, sig_result['warning'])
                        continue
                    
                    # Check HTML/script files
                    if file.lower().endswith(('.html', '.htm', '.js')):
                        script_result = self.script_analyzer.analyze_html_file(file_path)
                        if script_result.get('suspicious', False):
                            reasons = ", ".join(script_result['warnings'])
                            self.quarantine_file(file_path, f"Script analysis: {reasons}")
                
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                print("\n⏹️ Monitoring stopped by user")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    def quick_scan(self, target_path):
        """Perform a quick scan of a file or directory"""
        if os.path.isfile(target_path):
            print(f"🔍 Scanning file: {target_path}")
            
            # File signature check
            sig_result = self.file_scanner.scan_file(target_path)
            if sig_result.get('is_suspicious', False):
                print(f"🚨 File Signature Alert: {sig_result['warning']}")
                response = input("Quarantine this file? (y/n): ")
                if response.lower() == 'y':
                    self.quarantine_file(target_path, sig_result['warning'])
            else:
                print("✅ File signature: CLEAN")
            
            # Script analysis for relevant files
            if target_path.lower().endswith(('.html', '.htm', '.js')):
                script_result = self.script_analyzer.analyze_html_file(target_path)
                if script_result.get('suspicious', False):
                    print(f"🚨 Script Analysis Alert:")
                    for warning in script_result['warnings']:
                        print(f"   ⚠️ {warning}")
                    response = input("Quarantine this file? (y/n): ")
                    if response.lower() == 'y':
                        reasons = ", ".join(script_result['warnings'])
                        self.quarantine_file(target_path, f"Script analysis: {reasons}")
                else:
                    print("✅ Script analysis: CLEAN")
        
        elif os.path.isdir(target_path):
            print(f"🔍 Scanning directory: {target_path}")
            
            # Scan for signature mismatches
            suspicious_sig = self.file_scanner.scan_directory(target_path)
            
            # Scan for malicious scripts
            suspicious_scripts = self.script_analyzer.scan_directory_for_html(target_path)
            
            total_suspicious = len(suspicious_sig) + len(suspicious_scripts)
            print(f"\n📊 Scan complete: Found {total_suspicious} suspicious items")
            
            if total_suspicious > 0:
                response = input("Quarantine all suspicious files? (y/n): ")
                if response.lower() == 'y':
                    for result in suspicious_sig:
                        file_path = os.path.join(target_path, result['filename'])
                        self.quarantine_file(file_path, result['warning'])
                    
                    for result in suspicious_scripts:
                        file_path = os.path.join(target_path, result['filename'])
                        reasons = ", ".join(result['warnings'])
                        self.quarantine_file(file_path, f"Script analysis: {reasons}")

def main():
    system = AntiDeliverySystem()
    
    print("🛡️ Anti-Delivery Defense System")
    print("=" * 40)
    print("1. Quick scan (file or directory)")
    print("2. Monitor downloads folder")
    print("3. Exit")
    
    while True:
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            target = input("Enter file or directory path: ").strip()
            if os.path.exists(target):
                system.quick_scan(target)
            else:
                print("❌ Path does not exist")
        
        elif choice == '2':
            downloads_path = input("Enter downloads folder path (Enter for default): ").strip()
            if not downloads_path:
                downloads_path = None
            system.monitor_downloads_folder(downloads_path)
        
        elif choice == '3':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")


# Global instance for integration
_anti_delivery = None

def start_anti_delivery(downloads_path=None):
    """
    Start anti-delivery monitoring - entry point for integration
    
    Args:
        downloads_path: Path to monitor (default: ~/Downloads)
    
    Returns:
        AntiDeliverySystem instance
    """
    global _anti_delivery
    _anti_delivery = AntiDeliverySystem()
    
    # Start monitoring in a separate thread
    import threading
    monitor_thread = threading.Thread(
        target=_anti_delivery.monitor_downloads_folder,
        args=(downloads_path,),
        daemon=True
    )
    monitor_thread.start()
    
    return _anti_delivery

def scan_file(file_path):
    """Quick scan a single file - entry point for integration"""
    system = AntiDeliverySystem()
    system.quick_scan(file_path)
    return system

def scan_directory(dir_path):
    """Scan a directory - entry point for integration"""
    system = AntiDeliverySystem()
    system.quick_scan(dir_path)
    return system


if __name__ == "__main__":
    main()