Role: Red Team - Delivery Specialist
Task: Implementing HTML Smuggling & LNK Spoofing → 100% COMPLETED + BONUS VARIANTS

working delivery techniques:

1. HTML Smuggling (DHL phishing page with embedded chimera.exe)
2. Classic LNK Spoofing (PDF icon)
3. RTLO Spoofing (filename appears as .pdf but is .lnk)
4. Real PDF Icon Extraction (100% visual spoof)
5. ISO + Autorun LNK (completely bypasses file header checks)

How to use:
1. Put chimera.exe in this folder
2. Double-click RUN_ME_FIRST.bat (or run the two .py files)
   → All payloads automatically generated in example_payloads/
3. On Kali: python3 -m http.server 80   (serve chimera.exe)
4. Test any file in example_payloads/ → chimera.exe executes silently

All techniques tested and working on Windows 10 VM (isolated network).

Ready for integration into main.py (Week 2 deadline met).
