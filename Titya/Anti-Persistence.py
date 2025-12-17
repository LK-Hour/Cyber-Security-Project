"""
Anti-Persistence Module: Registry Watchdog & Task Auditor
Developer: Panha Virakitiya (Titya)
Purpose: Monitor and remediate persistence mechanisms used by malware

Project Spec:
- "Registry Watchdog: A background service that locks the Run key. 
   If a new value is added, it alerts the user and deletes it."
- "Task Scheduler Audit: A script that lists all tasks and highlights 
   any task pointing to a file in the Temp or Downloads folder."
"""

import winreg
import time
import threading
import subprocess
import platform
from datetime import datetime


class AntiPersistence:
    """Monitor and remove malware persistence mechanisms"""
    
    def __init__(self, defense_log=None):
        # Use provided logger or default to print
        self.defense_log = defense_log or self._default_log
        self.running = False
        self.alerts = []
        self.remediated_count = 0
        
        # Registry keys commonly used for persistence
        self.monitored_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        # Suspicious keywords for task detection
        self.suspicious_keywords = [
            "chimera", "temp", "downloads", "appdata", "malware",
            "windowsupdate", "microsoftupdate", "systemhealth",
            "securityscan", "updateassistant"
        ]
        
        # Whitelist of known legitimate task names
        self.task_whitelist = [
            "GoogleUpdateTask", "MicrosoftEdgeUpdate", "OneDrive",
            "Adobe", "Dropbox", "Slack", "Discord",
            # Windows Defender legitimate tasks
            "Windows Defender Scheduled Scan",
            "Windows Defender Cache Maintenance", 
            "Windows Defender Cleanup",
            "Windows Defender Verification"
        ]
        
        # Get baseline of current registry entries
        self.known_entries = self._get_current_entries()
    
    def _default_log(self, message):
        """Default logging function"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        self.alerts.append(log_msg)
        print(log_msg)

    def _get_current_entries(self):
        """Gets a baseline of all existing Run and RunOnce entries."""
        entries = {}
        
        if platform.system() != "Windows":
            return entries
        
        for hive, key_path in self.monitored_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                entries[(hive, key_path)] = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries[(hive, key_path)][name] = value
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                # Key doesn't exist, which is fine
                entries[(hive, key_path)] = {}
            except Exception:
                pass
        
        return entries

    def _delete_registry_entry(self, hive, key_path, value_name):
        """Deletes a specific value from the Windows Registry."""
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            self.remediated_count += 1
            return True
        except Exception as e:
            raise e

    def _monitor_registry(self):
        """The core monitoring loop for the Registry Watchdog."""
        self.defense_log("[AEGIS] Registry Watchdog STARTED")
        
        while self.running:
            try:
                current_entries = self._get_current_entries()
                
                # Check for new entries in all monitored keys
                for key_identifier, current_dict in current_entries.items():
                    baseline_dict = self.known_entries.get(key_identifier, {})
                    
                    for name, value in current_dict.items():
                        if name not in baseline_dict:
                            # NEW PERSISTENCE ENTRY DETECTED!
                            hive, key_path = key_identifier
                            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                            
                            self.defense_log(
                                f"[ALERT] 🚨 New persistence entry: {hive_name}\\{key_path}\\{name}"
                            )
                            self.defense_log(f"        Value: {value}")
                            
                            # Check if it looks suspicious
                            is_suspicious = any(
                                kw in name.lower() or kw in value.lower() 
                                for kw in self.suspicious_keywords
                            )
                            
                            if is_suspicious:
                                self.defense_log("[AEGIS] ⚠️ Entry matches suspicious patterns - AUTO-DELETING")
                                
                                # AUTOMATIC REMEDIATION
                                try:
                                    self._delete_registry_entry(hive, key_path, name)
                                    self.defense_log(f"[AEGIS] ✓ Deleted malicious entry: {name}")
                                except Exception as e:
                                    self.defense_log(f"[AEGIS] ✗ Failed to delete {name}: {e}")
                            else:
                                self.defense_log("[AEGIS] Entry added to watchlist (manual review recommended)")
                
                # Update baseline
                self.known_entries = current_entries
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.defense_log(f"[ERROR] Registry monitoring error: {e}")
                time.sleep(5)

    def _delete_scheduled_task(self, task_name):
        """Delete a scheduled task by name"""
        try:
            cmd = f'schtasks /delete /tn "{task_name}" /f'
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                self.remediated_count += 1
                return True
            else:
                return False
        except Exception as e:
            self.defense_log(f"[ERROR] Failed to delete task {task_name}: {e}")
            return False

    def audit_scheduled_tasks(self, auto_delete=True):
        """
        Scan Task Scheduler for suspicious tasks
        
        Args:
            auto_delete: If True, automatically delete suspicious tasks
        
        Returns:
            list: Suspicious tasks found
        """
        self.defense_log("[AEGIS] Starting Task Scheduler audit...")
        suspicious_tasks = []
        
        if platform.system() != "Windows":
            self.defense_log("[AEGIS] Task auditing only supported on Windows")
            return suspicious_tasks
        
        try:
            # Get detailed task information using PowerShell
            ps_command = '''
            Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ForEach-Object {
                $task = $_
                $action = ($task.Actions | Select-Object -First 1)
                [PSCustomObject]@{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    Execute = $action.Execute
                    Arguments = $action.Arguments
                    State = $task.State
                }
            } | ConvertTo-Json
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                self.defense_log(f"[ERROR] PowerShell failed: {result.stderr}")
                return suspicious_tasks
            
            # Parse JSON output
            import json
            try:
                tasks = json.loads(result.stdout)
                if isinstance(tasks, dict):
                    tasks = [tasks]  # Single task returned
            except json.JSONDecodeError:
                # Fallback to line-by-line parsing
                self._audit_tasks_fallback()
                return suspicious_tasks
            
            for task in tasks:
                task_name = task.get('TaskName', '')
                task_path = task.get('TaskPath', '')
                execute = task.get('Execute', '') or ''
                arguments = task.get('Arguments', '') or ''
                
                full_info = f"{task_name} {task_path} {execute} {arguments}".lower()
                
                # Skip whitelisted tasks
                if any(wl.lower() in task_name.lower() for wl in self.task_whitelist):
                    continue
                
                # Check for suspicious patterns
                is_suspicious = False
                reason = ""
                
                # Check suspicious keywords (exclude if it's just "programdata" with MpCmdRun.exe)
                for keyword in self.suspicious_keywords:
                    if keyword in full_info:
                        # Skip if this is a Windows Defender system task
                        if "mpcmdrun.exe" in execute.lower() and "windows defender" in task_path.lower():
                            continue
                        is_suspicious = True
                        reason = f"Matches keyword: {keyword}"
                        break
                
                # Check for executables in suspicious locations (but NOT Windows Defender system paths)
                suspicious_paths = ["temp", "downloads", "appdata\\local\\temp", "users\\public"]
                for path in suspicious_paths:
                    if path in execute.lower():
                        is_suspicious = True
                        reason = f"Suspicious location: {path}"
                        break
                
                if is_suspicious:
                    self.defense_log(f"[ALERT] 🚨 Suspicious task: {task_name}")
                    self.defense_log(f"        Path: {task_path}")
                    self.defense_log(f"        Execute: {execute}")
                    self.defense_log(f"        Reason: {reason}")
                    
                    suspicious_tasks.append({
                        'name': task_name,
                        'path': task_path,
                        'execute': execute,
                        'reason': reason
                    })
                    
                    # Auto-delete if enabled
                    if auto_delete:
                        full_task_name = task_path + task_name if task_path else task_name
                        self.defense_log(f"[AEGIS] Attempting to delete task: {task_name}")
                        
                        if self._delete_scheduled_task(full_task_name.strip('\\')):
                            self.defense_log(f"[AEGIS] ✓ Deleted malicious task: {task_name}")
                        else:
                            self.defense_log(f"[AEGIS] ✗ Failed to delete task: {task_name}")
            
            self.defense_log(f"[AEGIS] Audit complete: {len(suspicious_tasks)} suspicious tasks found")
            
        except subprocess.TimeoutExpired:
            self.defense_log("[ERROR] Task Scheduler audit timed out")
        except Exception as e:
            self.defense_log(f"[ERROR] Task audit error: {e}")
        
        return suspicious_tasks

    def _audit_tasks_fallback(self):
        """Fallback task audit using schtasks command"""
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                for keyword in self.suspicious_keywords:
                    if keyword in line_lower:
                        self.defense_log(f"[ALERT] Suspicious task entry: {line.strip()}")
                        break
        except Exception as e:
            self.defense_log(f"[ERROR] Fallback audit failed: {e}")

    def start_registry_watchdog(self):
        """Starts the Registry Watchdog in a separate thread."""
        if self.running:
            return
        
        self.running = True
        watchdog_thread = threading.Thread(target=self._monitor_registry, daemon=True)
        watchdog_thread.start()
        return watchdog_thread

    def start_task_auditor(self, interval=30):
        """
        Start periodic task auditing
        
        Args:
            interval: Seconds between audits (default 30)
        """
        def audit_loop():
            while self.running:
                self.audit_scheduled_tasks(auto_delete=True)
                time.sleep(interval)
        
        if not self.running:
            self.running = True
        
        auditor_thread = threading.Thread(target=audit_loop, daemon=True)
        auditor_thread.start()
        return auditor_thread
    
    def start(self):
        """Start both Registry Watchdog and Task Auditor"""
        self.running = True
        self.start_registry_watchdog()
        self.start_task_auditor()
        self.defense_log("[AEGIS] Anti-Persistence module STARTED")
    
    def stop(self):
        """Stop all monitoring"""
        self.running = False
        self.defense_log(f"[AEGIS] Anti-Persistence STOPPED - {self.remediated_count} threats remediated")


# Global instance
_anti_persistence = None

def start_anti_persistence(defense_log=None):
    """Start anti-persistence module - entry point for integration"""
    global _anti_persistence
    _anti_persistence = AntiPersistence(defense_log)
    _anti_persistence.start()
    return _anti_persistence

def stop_anti_persistence():
    """Stop anti-persistence module"""
    global _anti_persistence
    if _anti_persistence:
        _anti_persistence.stop()


if __name__ == "__main__":
    print("🛡️ AEGIS ANTI-PERSISTENCE - Defense Module")
    print("=" * 50)
    print("Monitors Registry Run keys and Scheduled Tasks")
    print("Automatically removes suspicious persistence")
    print("=" * 50)
    print("\nPress Ctrl+C to stop\n")
    
    anti_persist = AntiPersistence()
    
    print("Select mode:")
    print("1. Full monitoring (Registry + Tasks)")
    print("2. One-time task audit only")
    print("3. Registry watchdog only")
    
    choice = input("\nChoice (1-3) [default: 1]: ").strip() or "1"
    
    try:
        if choice == "1":
            anti_persist.start()
            while True:
                time.sleep(1)
        elif choice == "2":
            suspicious = anti_persist.audit_scheduled_tasks(auto_delete=False)
            print(f"\n📊 Found {len(suspicious)} suspicious tasks")
            if suspicious:
                delete = input("Delete suspicious tasks? (y/n): ").strip().lower()
                if delete == 'y':
                    for task in suspicious:
                        anti_persist._delete_scheduled_task(task['name'])
        elif choice == "3":
            anti_persist.running = True
            anti_persist._monitor_registry()
    except KeyboardInterrupt:
        print("\n[AEGIS] Shutting down...")
        anti_persist.stop()
        auditor_thread.start()