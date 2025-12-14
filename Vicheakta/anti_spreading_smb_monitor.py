
"""
Anti-Spreading Module: SMB Traffic Monitor
Developer: Penh Sovicheakta
Purpose: Monitor and block suspicious SMB (Port 445) activity

Project Spec: "SMB Traffic Blocker: A firewall rule that temporarily 
blocks Port 445 if it detects more than 5 connection attempts in 1 second."
"""

import time
import threading
import subprocess
import platform

class SMBMonitor:
    """Monitor SMB traffic and block suspicious activity"""
    
    def __init__(self):
        self.rule_name = "AEGIS_BLOCK_SMB_445"
        self.running = False
        self.blocked = False
        self.connection_threshold = 5  # Max connections per second
        self.block_duration = 60  # Seconds to block
        self.alerts = []
    
    def log_alert(self, message):
        """Log alert message"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] {message}"
        self.alerts.append(alert)
        print(alert)
    
    def block_smb(self):
        """Block SMB port 445 using Windows Firewall"""
        if platform.system() != "Windows":
            self.log_alert("[AEGIS] SMB blocking only supported on Windows")
            return False
        
        try:
            # Remove existing rule first
            subprocess.call(
                f'netsh advfirewall firewall delete rule name="{self.rule_name}"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Add inbound block rule
            subprocess.call(
                f'netsh advfirewall firewall add rule name="{self.rule_name}" '
                f'dir=in action=block protocol=TCP localport=445',
                shell=True, stdout=subprocess.DEVNULL
            )
            
            # Add outbound block rule
            subprocess.call(
                f'netsh advfirewall firewall add rule name="{self.rule_name}" '
                f'dir=out action=block protocol=TCP remoteport=445',
                shell=True, stdout=subprocess.DEVNULL
            )
            
            self.blocked = True
            self.log_alert("[AEGIS] 🛡️ Blocked port 445 - SMB worm stopped!")
            return True
            
        except Exception as e:
            self.log_alert(f"[AEGIS] Failed to block SMB: {e}")
            return False
    
    def unblock_smb(self):
        """Remove SMB blocking rule"""
        if platform.system() != "Windows":
            return False
        
        try:
            subprocess.call(
                f'netsh advfirewall firewall delete rule name="{self.rule_name}"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.blocked = False
            self.log_alert("[AEGIS] ✓ Unblocked port 445 - SMB traffic restored")
            return True
        except Exception as e:
            self.log_alert(f"[AEGIS] Failed to unblock SMB: {e}")
            return False
    
    def get_smb_connections(self):
        """Count current SMB connections on port 445"""
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    'netstat -an | findstr :445',
                    shell=True, text=True, stderr=subprocess.DEVNULL
                )
            else:
                # Linux alternative
                result = subprocess.check_output(
                    'netstat -an | grep :445',
                    shell=True, text=True, stderr=subprocess.DEVNULL
                )
            
            # Count active connections
            connections = 0
            for line in result.splitlines():
                if "ESTABLISHED" in line or "SYN" in line or "TIME_WAIT" in line:
                    connections += 1
            
            return connections
            
        except subprocess.CalledProcessError:
            # No connections found (grep returns non-zero)
            return 0
        except Exception:
            return 0
    
    def monitor_loop(self):
        """Main monitoring loop - detects SMB worm activity"""
        self.log_alert("[AEGIS] SMB Monitor STARTED - Watching port 445")
        
        connection_count = 0
        last_check_time = time.time()
        
        while self.running:
            try:
                current_connections = self.get_smb_connections()
                current_time = time.time()
                
                # Reset counter every second (sliding window)
                if current_time - last_check_time > 1.0:
                    connection_count = 0
                    last_check_time = current_time
                
                connection_count += current_connections
                
                # Check threshold - more than 5 connections in 1 second = suspicious
                if connection_count > self.connection_threshold and not self.blocked:
                    self.log_alert(
                        f"[ALERT] 🚨 SMB WORM DETECTED! {connection_count} connections in 1 second"
                    )
                    
                    # Block SMB traffic
                    self.block_smb()
                    
                    # Schedule unblock after duration
                    unblock_timer = threading.Timer(self.block_duration, self.unblock_smb)
                    unblock_timer.daemon = True
                    unblock_timer.start()
                    
                    connection_count = 0
                
                time.sleep(0.3)  # Check every 300ms for responsiveness
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(1)
    
    def start(self):
        """Start SMB monitor in background thread"""
        if self.running:
            return
        
        self.running = True
        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def stop(self):
        """Stop SMB monitor"""
        self.running = False
        if self.blocked:
            self.unblock_smb()
        self.log_alert("[AEGIS] SMB Monitor STOPPED")


# Global instance for easy access
_smb_monitor = None

def start_smb_monitor():
    """Start SMB monitor - entry point for integration"""
    global _smb_monitor
    _smb_monitor = SMBMonitor()
    _smb_monitor.start()
    return _smb_monitor

def stop_smb_monitor():
    """Stop SMB monitor"""
    global _smb_monitor
    if _smb_monitor:
        _smb_monitor.stop()

def block_smb():
    """Manually block SMB - legacy function"""
    monitor = SMBMonitor()
    return monitor.block_smb()

def unblock_smb():
    """Manually unblock SMB - legacy function"""
    monitor = SMBMonitor()
    return monitor.unblock_smb()


if __name__ == "__main__":
    print("🛡️ AEGIS SMB MONITOR - Anti-Spreading Defense")
    print("=" * 50)
    print("Monitors Port 445 for SMB worm propagation attempts")
    print("Automatically blocks if >5 connections detected in 1 second")
    print("=" * 50)
    print("\nPress Ctrl+C to stop\n")
    
    monitor = SMBMonitor()
    monitor.running = True
    
    try:
        monitor.monitor_loop()
    except KeyboardInterrupt:
        print("\n[AEGIS] Shutting down...")
        monitor.stop()