"""
RED TEAM USB REPLICATION TOOL
Lateral Movement Specialist Assignment - Part 2
For authorized penetration testing only
"""

import os
import sys
import time
import random
import shutil
import json
from datetime import datetime
from pathlib import Path

class RedTeamUSBReplication:
    def __init__(self):
        self.engagement_id = f"RT_USB_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.usb_operations = []
        self.replication_count = 0
        self.safe_mode = True
        
        # USB Attack Vectors
        self.usb_techniques = [
            "AUTORUN_INF",
            "LNK_FILE_EXPLOIT", 
            "DLL_SIDELOADING",
            "HID_ATTACK_SIMULATION",
            "BADUSB_EMULATION"
        ]
        
        self.disguise_names = [
            "folder_icon.exe", "photo_viewer.scr", "document_reader.exe",
            "setup_helper.exe", "media_player.exe", "driver_update.exe"
        ]
        
        print(f"""
🔴 RED TEAM USB REPLICATION TOOL
💾 Engagement ID: {self.engagement_id}
📅 Started: {datetime.now()}
⚠️  FOR AUTHORIZED SOCIAL ENGINEERING TESTING ONLY
        """)
    
    def safety_check(self):
        """Verify authorization for USB replication testing"""
        if not self.safe_mode:
            response = input("[!] SAFE MODE DISABLED. Confirm authorization (type 'AUTHORIZED'): ")
            if response != "AUTHORIZED":
                print("[-] Operation cancelled - unauthorized testing")
                sys.exit(1)
        return True
    
    def simulate_usb_drop_attack(self):
        """Simulate malicious USB drop attack campaign"""
        print("\n[PHASE 1] USB DROP ATTACK SIMULATION")
        print("=" * 45)
        
        # Simulate different USB scenarios
        drop_scenarios = [
            {
                "location": "Parking Lot",
                "target": "Employees",
                "content": "Fake Salary Information",
                "success_rate": 0.3
            },
            {
                "location": "Coffee Shop", 
                "target": "Remote Workers",
                "content": "WiFi Configuration",
                "success_rate": 0.4
            },
            {
                "location": "Conference Room",
                "target": "Executives", 
                "content": "Business Strategy",
                "success_rate": 0.25
            }
        ]
        
        for scenario in drop_scenarios:
            print(f"  [>] Simulating USB drop: {scenario['location']}")
            print(f"      Target: {scenario['target']}")
            print(f"      Bait: {scenario['content']}")
            
            # Simulate user interaction
            if random.random() <= scenario['success_rate']:
                print(f"      ✅ SUCCESS: User interacted with USB")
                self._deploy_usb_payload(scenario)
            else:
                print(f"      ❌ FAILED: User ignored USB")
            
            time.sleep(random.uniform(2, 4))
    
    def _deploy_usb_payload(self, scenario):
        """Deploy simulated payload to USB device"""
        payload_id = f"USB_{random.randint(1000, 9999)}"
        
        # Create USB simulation directory
        usb_path = f"C:\\USB_Simulation\\{scenario['location'].replace(' ', '_')}"
        os.makedirs(usb_path, exist_ok=True)
        
        # Choose attack technique
        technique = random.choice(self.usb_techniques)
        print(f"      [>] Deploying: {technique}")
        
        if technique == "AUTORUN_INF":
            self._create_autorun_attack(usb_path, payload_id)
        elif technique == "LNK_FILE_EXPLOIT":
            self._create_lnk_exploit(usb_path, payload_id)
        elif technique == "DLL_SIDELOADING":
            self._create_dll_sideloading(usb_path, payload_id)
        elif technique == "HID_ATTACK_SIMULATION":
            self._simulate_hid_attack(usb_path, payload_id)
        elif technique == "BADUSB_EMULATION":
            self._simulate_badusb(usb_path, payload_id)
        
        self.usb_operations.append({
            'technique': technique,
            'location': scenario['location'],
            'payload_id': payload_id,
            'timestamp': str(datetime.now()),
            'success': True
        })
        self.replication_count += 1
    
    def _create_autorun_attack(self, usb_path, payload_id):
        """Create autorun.inf based attack"""
        print(f"        [AUTORUN] Creating autorun.inf infection")
        
        # Create malicious autorun.inf
        autorun_content = f"""[autorun]
open={random.choice(self.disguise_names)}
icon=shell32.dll,4
label=Important Documents
action=Open folder to view files
UseAutoPlay=1
"""
        
        with open(os.path.join(usb_path, "autorun.inf"), "w") as f:
            f.write(autorun_content)
        
        # Create disguised payload
        payload_name = random.choice(self.disguise_names)
        payload_path = os.path.join(usb_path, payload_name)
        
        with open(payload_path, "w") as f:
            f.write(f"Simulated USB Worm Payload\nID: {payload_id}\n")
        
        # Create realistic folder structure
        folders = ["Documents", "Photos", "Confidential", "Reports"]
        for folder in folders:
            folder_path = os.path.join(usb_path, folder)
            os.makedirs(folder_path, exist_ok=True)
            
            # Add decoy files
            for i in range(random.randint(2, 5)):
                decoy_file = os.path.join(folder_path, f"document_{i}.txt")
                with open(decoy_file, "w") as f:
                    f.write(f"Decoy file content - looks legitimate\n")
    
    def _create_lnk_exploit(self, usb_path, payload_id):
        """Create LNK file exploit simulation"""
        print(f"        [LNK] Creating malicious shortcut exploit")
        
        # Create malicious LNK simulation
        lnk_content = f"""Windows Shortcut Exploit Simulation
Target: cmd.exe /c malicious_payload.exe
Icon: shell32.dll
Payload ID: {payload_id}
"""
        
        with open(os.path.join(usb_path, "Documents.lnk.sim"), "w") as f:
            f.write(lnk_content)
        
        # Create folder that LNK points to
        target_folder = os.path.join(usb_path, "Financial_Reports")
        os.makedirs(target_folder, exist_ok=True)
        
        # Add decoy content
        decoy_files = ["Q1_Report.pdf.txt", "Budget_2024.xlsx.txt", "Salary_Info.doc.txt"]
        for file in decoy_files:
            with open(os.path.join(target_folder, file), "w") as f:
                f.write("Important looking decoy content\n")
    
    def _create_dll_sideloading(self, usb_path, payload_id):
        """Create DLL sideloading attack simulation"""
        print(f"        [DLL] Creating DLL sideloading attack")
        
        # Create fake legitimate application structure
        app_folder = os.path.join(usb_path, "PhotoViewer")
        os.makedirs(app_folder, exist_ok=True)
        
        # Create legitimate-looking executable
        with open(os.path.join(app_folder, "PhotoViewer.exe.sim"), "w") as f:
            f.write("Legitimate application simulation\n")
        
        # Create malicious DLL
        with open(os.path.join(app_folder, "malicious.dll.sim"), "w") as f:
            f.write(f"Malicious DLL - Sideloading attack\nPayload: {payload_id}\n")
        
        # Create configuration files
        with open(os.path.join(app_folder, "config.ini"), "w") as f:
            f.write("[Settings]\nLoadDLL=malicious.dll\n")
    
    def _simulate_hid_attack(self, usb_path, payload_id):
        """Simulate HID (Human Interface Device) attack"""
        print(f"        [HID] Simulating USB HID attack")
        
        hid_script = f"""# Rubber Ducky / HID Attack Simulation
DELAY 2000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "malicious_script.ps1"
ENTER
DELAY 1000
STRING exit
ENTER
Payload ID: {payload_id}
"""
        
        with open(os.path.join(usb_path, "hid_attack_script.txt"), "w") as f:
            f.write(hid_script)
    
    def _simulate_badusb(self, usb_path, payload_id):
        """Simulate BadUSB attack"""
        print(f"        [BADUSB] Simulating BadUSB attack")
        
        badusb_script = f"""# BadUSB Attack Simulation
# Device presents as keyboard and executes commands
STRINGS "Hello, I'm a trusted keyboard"
DELAY 1000
ENTER
STRINGS "Actually, I'm running malicious commands..."
DELAY 1000
ENTER
# Simulated payload execution
Payload ID: {payload_id}
"""
        
        with open(os.path.join(usb_path, "badusb_script.txt"), "w") as f:
            f.write(badusb_script)
    
    def simulate_physical_access(self):
        """Simulate physical access attacks"""
        print("\n[PHASE 2] PHYSICAL ACCESS ATTACKS")
        print("=" * 40)
        
        physical_attacks = [
            "USB_DEVICE_PLANTING",
            "CHARGE_CABLE_EXPLOIT", 
            "PERIPHERAL_COMPROMISE",
            "LOCK_SCREEN_BYPASS"
        ]
        
        for attack in physical_attacks:
            print(f"  [>] Testing: {attack}")
            time.sleep(1)
            
            if random.random() > 0.5:  # 50% success rate
                print(f"      ✅ SUCCESS: {attack} would be effective")
                self.usb_operations.append({
                    'technique': attack,
                    'type': 'PHYSICAL_ACCESS',
                    'success': True,
                    'timestamp': str(datetime.now())
                })
            else:
                print(f"      ❌ FAILED: {attack} would be detected/blocked")
    
    def generate_usb_report(self):
        """Generate comprehensive USB replication report"""
        print("\n[PHASE 3] USB REPLICATION REPORT")
        print("=" * 45)
        
        report = {
            "engagement_id": self.engagement_id,
            "timestamp": str(datetime.now()),
            "safe_mode": self.safe_mode,
            
            "findings": {
                "total_usb_operations": len(self.usb_operations),
                "successful_replications": self.replication_count,
                "techniques_tested": list(set([op['technique'] for op in self.usb_operations])),
                "physical_access_risk": len([op for op in self.usb_operations if op.get('type') == 'PHYSICAL_ACCESS']) > 0
            },
            
            "usb_operations": self.usb_operations,
            
            "risk_assessment": self._assess_usb_risk(),
            
            "recommendations": [
                "Implement USB device control policies",
                "Disable AutoRun/AutoPlay for removable media",
                "Use application whitelisting",
                "Educate users about USB drop attacks",
                "Monitor for unusual USB device activity",
                "Implement device control software",
                "Restrict removable media usage in sensitive areas",
                "Conduct regular social engineering tests"
            ],
            
            "detection_indicators": [
                "Unknown USB devices connecting to systems",
                "Autorun.inf files on removable media",
                "Suspicious LNK files from USB devices",
                "Unusual processes launching from removable drives",
                "Multiple USB connection attempts in short time"
            ]
        }
        
        # Print executive summary
        print("\n📊 USB ATTACK SUMMARY")
        print("-" * 25)
        print(f"Operations Simulated: {report['findings']['total_usb_operations']}")
        print(f"Successful Replications: {report['findings']['successful_replications']}")
        print(f"Physical Access Risk: {report['findings']['physical_access_risk']}")
        print(f"Risk Level: {report['risk_assessment']['level']}")
        
        print("\n🔧 TECHNIQUES TESTED")
        print("-" * 20)
        for technique in report['findings']['techniques_tested']:
            print(f"  • {technique}")
        
        print("\n🚨 CRITICAL RECOMMENDATIONS")
        print("-" * 28)
        for i, recommendation in enumerate(report['recommendations'][:3], 1):
            print(f"  {i}. {recommendation}")
        
        # Save detailed report
        self._save_usb_report(report)
        return report
    
    def _assess_usb_risk(self):
        """Assess USB-based attack risk"""
        risk_score = 0
        
        if self.replication_count > 2:
            risk_score += 3
        if any('PHYSICAL_ACCESS' in str(op) for op in self.usb_operations):
            risk_score += 2
        if len(self.usb_operations) > 5:
            risk_score += 2
        
        if risk_score >= 5:
            return {"level": "CRITICAL", "score": risk_score}
        elif risk_score >= 3:
            return {"level": "HIGH", "score": risk_score}
        elif risk_score >= 2:
            return {"level": "MEDIUM", "score": risk_score}
        else:
            return {"level": "LOW", "score": risk_score}
    
    def _save_usb_report(self, report):
        """Save USB replication report"""
        report_dir = "C:\\RedTeam_Reports"
        os.makedirs(report_dir, exist_ok=True)
        
        report_file = f"{report_dir}\\{self.engagement_id}_usb_report.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 USB report saved: {report_file}")

def main():
    """Main execution for USB replication testing"""
    print("🔴 RED TEAM USB REPLICATION TOOL")
    print("FOR AUTHORIZED SOCIAL ENGINEERING TESTING ONLY")
    print("Ensure proper authorization before proceeding.\n")
    
    # Configuration
    safe_mode = True
    
    if not safe_mode:
        confirm = input("⚠️  SAFE MODE DISABLED. Type 'CONFIRM' to proceed: ")
        if confirm != "CONFIRM":
            print("Operation cancelled.")
            return
    
    # Execute USB replication testing
    usb_tool = RedTeamUSBReplication()
    usb_tool.safe_mode = safe_mode
    
    if usb_tool.safety_check():
        usb_tool.simulate_usb_drop_attack()
        usb_tool.simulate_physical_access()
        report = usb_tool.generate_usb_report()
        
        print(f"\n🎯 USB REPLICATION TESTING COMPLETE: {usb_tool.engagement_id}")
        print("Use findings to improve physical security and user awareness")

if __name__ == "__main__":
    main()