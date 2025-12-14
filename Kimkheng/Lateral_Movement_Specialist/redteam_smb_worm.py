"""
RED TEAM SMB WORM - Advanced Lateral Movement
For authorized penetration testing and security assessments only
"""

import os
import sys
import time
import random
import subprocess
import platform
from datetime import datetime
from pathlib import Path

class RedTeamSMBWorm:
    def __init__(self):
        self.engagement_id = f"RT_SMB_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.discovered_hosts = []
        self.compromised_shares = []
        self.lateral_movements = []
        self.techniques_used = []
        
        # Red Team Tradecraft
        self.operational_security = True
        self.safe_mode = True  # Set to False for actual payload deployment
        
        print(f"""
🚩 RED TEAM SMB LATERAL MOVEMENT TOOL
🔴 Engagement ID: {self.engagement_id}
📅 Started: {datetime.now()}
⚠️  FOR AUTHORIZED TESTING ONLY
        """)
    
    def safety_check(self):
        """Verify this is authorized testing"""
        if not self.safe_mode:
            response = input("[!] SAFE MODE DISABLED. Confirm authorization (type 'AUTHORIZED'): ")
            if response != "AUTHORIZED":
                print("[-] Operation cancelled - unauthorized testing")
                sys.exit(1)
        return True
    
    def network_discovery(self):
        """Advanced network reconnaissance"""
        print("\n[PHASE 1] NETWORK DISCOVERY")
        print("=" * 40)
        
        discovery_methods = [
            self._net_view_discovery,
            self._arp_table_discovery,
            self._ping_sweep_discovery
        ]
        
        for method in discovery_methods:
            try:
                method()
                time.sleep(random.uniform(2, 5))  # OpSec delay
            except Exception as e:
                print(f"  [-] {method.__name__} failed: {e}")
        
        print(f"  [+] Total hosts discovered: {len(self.discovered_hosts)}")
        return self.discovered_hosts
    
    def _net_view_discovery(self):
        """Use net view for host discovery"""
        print("  [>] Executing: net view")
        try:
            result = subprocess.run(['net', 'view'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '\\\\' in line and 'The command completed' not in line:
                        host = line.split('\\\\')[1].split(' ')[0].strip()
                        if host and host not in self.discovered_hosts:
                            self.discovered_hosts.append(host)
                            print(f"    [+] NetView: {host}")
        except subprocess.TimeoutExpired:
            print("    [!] Net view timed out")
        except Exception as e:
            print(f"    [-] Net view error: {e}")
    
    def _arp_table_discovery(self):
        """Check ARP table for recent hosts"""
        print("  [>] Checking ARP table")
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'dynamic' in line.lower() and '.' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if ip not in [h for h in self.discovered_hosts if '.' in h]:
                            self.discovered_hosts.append(ip)
                            print(f"    [+] ARP: {ip}")
        except Exception as e:
            print(f"    [-] ARP check failed: {e}")
    
    def _ping_sweep_discovery(self):
        """Limited ping sweep on common subnets"""
        print("  [>] Limited ping sweep")
        subnets = ['192.168.1.', '10.0.0.', '172.16.1.']
        
        for subnet in subnets:
            for i in random.sample(range(1, 254), 5):  # Sample 5 hosts per subnet
                ip = f"{subnet}{i}"
                try:
                    result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                          capture_output=True, timeout=2)
                    if result.returncode == 0 and ip not in self.discovered_hosts:
                        self.discovered_hosts.append(ip)
                        print(f"    [+] Ping: {ip} - Active")
                except:
                    pass
    
    def share_enumeration(self):
        """Advanced SMB share enumeration"""
        print("\n[PHASE 2] SHARE ENUMERATION")
        print("=" * 40)
        
        if not self.discovered_hosts:
            print("  [!] No hosts discovered - skipping share enumeration")
            return []
        
        for host in self.discovered_hosts[:10]:  # Limit to first 10 hosts
            print(f"  [>] Enumerating: {host}")
            
            techniques = [
                self._net_view_shares,
                self._smbclient_shares,
                self._powerShell_shares
            ]
            
            for technique in techniques:
                try:
                    technique(host)
                    time.sleep(random.uniform(1, 3))
                except Exception as e:
                    print(f"    [-] {technique.__name__} failed: {e}")
        
        print(f"  [+] Total shares found: {len(self.compromised_shares)}")
        return self.compromised_shares
    
    def _net_view_shares(self, host):
        """Use net view for share enumeration"""
        try:
            result = subprocess.run(['net', 'view', f'\\\\{host}'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and 'shared resources' in result.stdout.lower():
                for line in result.stdout.split('\n'):
                    if 'Disk' in line and '\\\\' in line:
                        share_name = line.split(' ')[0]
                        full_path = f"\\\\{host}\\{share_name}"
                        if full_path not in self.compromised_shares:
                            self.compromised_shares.append(full_path)
                            print(f"    [+] Share: {full_path}")
                            self.techniques_used.append("NetView_Share_Enum")
        except subprocess.TimeoutExpired:
            print(f"    [!] Net view timeout for {host}")
    
    def _smbclient_shares(self, host):
        """Alternative share enumeration"""
        try:
            # Try different methods for share discovery
            commands = [
                f"net use \\\\{host}\\IPC$ /user:guest \"\"",
                f"net view \\\\{host} /all"
            ]
            
            for cmd in commands:
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                if result.returncode == 0:
                    self.techniques_used.append("SMBClient_Enum")
                    break
        except Exception as e:
            pass  # Silent fail for alternative methods
    
    def _powerShell_shares(self, host):
        """PowerShell-based enumeration"""
        try:
            ps_command = f"Get-SmbShare -CimSession {host} 2>$null"
            result = subprocess.run(['powershell', '-Command', ps_command],
                                  capture_output=True, text=True, timeout=10)
            
            if 'Name' in result.stdout and 'ScopeName' in result.stdout:
                self.techniques_used.append("PowerShell_SMB_Enum")
                print(f"    [!] PowerShell access to {host}")
        except:
            pass
    
    def lateral_movement_execution(self):
        """Execute lateral movement techniques"""
        print("\n[PHASE 3] LATERAL MOVEMENT EXECUTION")
        print("=" * 40)
        
        if not self.compromised_shares:
            print("  [!] No accessible shares found")
            return []
        
        movement_techniques = [
            self._smb_copy_execution,
            self._wmi_lateral_movement,
            self._schtask_lateral_movement
        ]
        
        successful_movements = 0
        for share in self.compromised_shares[:5]:  # Limit attempts
            print(f"  [>] Targeting: {share}")
            
            for technique in movement_techniques:
                if successful_movements >= 3:  # Limit success count
                    break
                    
                try:
                    if technique(share):
                        successful_movements += 1
                        self.lateral_movements.append({
                            'target': share,
                            'technique': technique.__name__,
                            'timestamp': str(datetime.now()),
                            'success': True
                        })
                        break  # Move to next share after success
                    time.sleep(random.uniform(3, 7))
                except Exception as e:
                    print(f"    [-] {technique.__name__} failed: {e}")
        
        print(f"  [+] Successful lateral movements: {successful_movements}")
        return self.lateral_movements
    
    def _smb_copy_execution(self, share):
        """SMB copy-based lateral movement"""
        print(f"    [>] Attempting SMB copy to {share}")
        
        if self.safe_mode:
            # Simulation only
            print(f"      [SIM] Would copy payload to {share}\\Windows\\Temp\\")
            self.techniques_used.append("SMB_Copy_Simulation")
            return True
        
        # Actual implementation would go here
        # This is intentionally omitted for safety
        return False
    
    def _wmi_lateral_movement(self, share):
        """WMI-based lateral movement simulation"""
        host = share.split('\\')[2]
        print(f"    [>] Attempting WMI execution on {host}")
        
        if self.safe_mode:
            print(f"      [SIM] Would execute via WMI on {host}")
            self.techniques_used.append("WMI_Lateral_Simulation")
            return True
        
        return False
    
    def _schtask_lateral_movement(self, share):
        """Scheduled task lateral movement simulation"""
        host = share.split('\\')[2]
        print(f"    [>] Attempting scheduled task on {host}")
        
        if self.safe_mode:
            print(f"      [SIM] Would create scheduled task on {host}")
            self.techniques_used.append("ScheduledTask_Lateral_Simulation")
            return True
        
        return False
    
    def generate_engagement_report(self):
        """Comprehensive red team engagement report"""
        print("\n[PHASE 4] ENGAGEMENT REPORT")
        print("=" * 50)
        
        report = {
            "engagement_id": self.engagement_id,
            "timestamp": str(datetime.now()),
            "execution_platform": platform.platform(),
            "safe_mode": self.safe_mode,
            
            "findings": {
                "hosts_discovered": len(self.discovered_hosts),
                "shares_accessible": len(self.compromised_shares),
                "lateral_movements_successful": len([m for m in self.lateral_movements if m['success']]),
                "techniques_demonstrated": list(set(self.techniques_used)),
                "lateral_movement_possible": len(self.compromised_shares) > 0
            },
            
            "hosts_discovered": self.discovered_hosts[:10],  # Limit for report
            "shares_compromised": self.compromised_shares[:10],
            "successful_movements": self.lateral_movements,
            
            "risk_assessment": self._assess_risk_level(),
            
            "recommendations": [
                "Implement network segmentation",
                "Restrict SMB share permissions using least privilege",
                "Enable SMB signing and encryption",
                "Monitor for unusual SMB activity patterns",
                "Regularly review and remove unnecessary shares",
                "Implement host-based firewalls",
                "Use network access control (NAC)",
                "Conduct regular penetration testing"
            ],
            
            "detection_indicators": [
                "Multiple net view commands in short time",
                "Unusual SMB share access patterns",
                "WMI or scheduled task creation from unusual sources",
                "Lateral movement between segments"
            ]
        }
        
        # Print executive summary
        print("\n📊 EXECUTIVE SUMMARY")
        print("-" * 30)
        print(f"Hosts Discovered: {report['findings']['hosts_discovered']}")
        print(f"Accessible Shares: {report['findings']['shares_accessible']}")
        print(f"Lateral Movement Possible: {report['findings']['lateral_movement_possible']}")
        print(f"Risk Level: {report['risk_assessment']['level']}")
        
        print("\n🔧 TECHNIQUES DEMONSTRATED")
        print("-" * 30)
        for technique in report['findings']['techniques_demonstrated']:
            print(f"  • {technique}")
        
        print("\n🚨 CRITICAL RECOMMENDATIONS")
        print("-" * 30)
        for i, recommendation in enumerate(report['recommendations'][:3], 1):
            print(f"  {i}. {recommendation}")
        
        # Save detailed report
        self._save_detailed_report(report)
        return report
    
    def _assess_risk_level(self):
        """Assess the risk level based on findings"""
        risk_score = 0
        
        if len(self.discovered_hosts) > 5:
            risk_score += 2
        if len(self.compromised_shares) > 3:
            risk_score += 3
        if len(self.lateral_movements) > 0:
            risk_score += 4
        
        if risk_score >= 7:
            return {"level": "CRITICAL", "score": risk_score}
        elif risk_score >= 4:
            return {"level": "HIGH", "score": risk_score}
        elif risk_score >= 2:
            return {"level": "MEDIUM", "score": risk_score}
        else:
            return {"level": "LOW", "score": risk_score}
    
    def _save_detailed_report(self, report):
        """Save detailed report to file"""
        import json
        
        report_dir = "C:\\RedTeam_Reports"
        os.makedirs(report_dir, exist_ok=True)
        
        report_file = f"{report_dir}\\{self.engagement_id}_report.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Detailed report saved: {report_file}")

def main():
    """Main execution with safety controls"""
    # Safety warning
    print("🚩 RED TEAM TOOL - AUTHORIZED USE ONLY")
    print("This tool simulates attacker techniques for security testing.")
    print("Ensure you have proper authorization before proceeding.\n")
    
    # Configuration
    safe_mode = True  # Set to False only for authorized engagements
    
    if not safe_mode:
        confirm = input("⚠️  SAFE MODE DISABLED. Type 'CONFIRM' to proceed: ")
        if confirm != "CONFIRM":
            print("Operation cancelled.")
            return
    
    # Execute engagement
    worm = RedTeamSMBWorm()
    worm.safe_mode = safe_mode
    
    if worm.safety_check():
        worm.network_discovery()
        worm.share_enumeration()
        worm.lateral_movement_execution()
        worm.generate_engagement_report()
        
        print(f"\n🎯 ENGAGEMENT COMPLETE: {worm.engagement_id}")
        print("Use findings to improve defensive security controls")


# Entry point function for integration
def spread_smb(safe_mode=True):
    """
    Execute SMB lateral movement - entry point for integration
    
    Args:
        safe_mode: If True, simulates without actual payload deployment
    
    Returns:
        dict: Engagement results
    """
    worm = RedTeamSMBWorm()
    worm.safe_mode = safe_mode
    
    worm.network_discovery()
    worm.share_enumeration()
    worm.lateral_movement_execution()
    
    return {
        'hosts_discovered': len(worm.discovered_hosts),
        'shares_found': len(worm.compromised_shares),
        'lateral_movements': len(worm.lateral_movements),
        'engagement_id': worm.engagement_id
    }


if __name__ == "__main__":
    main()