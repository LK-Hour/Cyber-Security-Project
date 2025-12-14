**Penh Sovicheakta**  
Role: Blue Team – Anti-Spreading Specialist  
Task: Developing Network Port Monitor & USB Sentinel  

## Working anti-spreading techniques (fully blocks Red Team stage 3)

1. **SMB Traffic Blocker**  
   Real-time detection + automatic Windows Firewall rule  
   Blocks port 445 (inbound + outbound) when >5 connection attempts in 1 second  

2. **USB Sentinel – Instant Auto-Scan & Quarantine**  
   Detects any new removable drive the second it appears  
   Full recursive scan + instant quarantine of:  
   `.exe .lnk .scr .bat .ps1 .vbs autorun.inf` + hidden executables