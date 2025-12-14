# script_analyzer.py
import re
import base64
import os
import math
import struct

class ScriptAnalyzer:
    def __init__(self):
        # Patterns for detecting suspicious content
        self.patterns = {
            'large_base64': r'[A-Za-z0-9+/]{100,}={0,2}',
            'obfuscated_js': [
                r'eval\(.*\)',
                r'unescape\(.*\)',
                r'fromCharCode\(.*\)',
                r'document\.write\(.*\)',
                r'window\.location\s*=',
                r'String\.fromCharCode'
            ],
            'suspicious_functions': [
                'ActiveXObject',
                'WScript.Shell',
                'Shell.Application',
                'ADODB.Stream',
                'MSXML2.XMLHTTP'
            ]
        }
        
        # Minimum size for Base64 blob to be considered suspicious (in bytes when decoded)
        self.min_suspicious_size = 50000  # 50KB
        
    def analyze_html_file(self, file_path):
        """Analyze an HTML file for suspicious content"""
        if not os.path.exists(file_path):
            return {"status": "ERROR", "message": "File not found"}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {"status": "ERROR", "message": f"Could not read file: {e}"}
        
        return self.analyze_html_content(content, file_path)
    
    def analyze_html_content(self, content, filename="unknown"):
        """Analyze HTML content for smuggling techniques"""
        results = {
            "filename": filename,
            "suspicious": False,
            "warnings": [],
            "base64_blobs": [],
            "obfuscation_detected": False,
            "risk_level": "LOW"
        }
        
        # Check for large Base64 blobs
        base64_matches = re.findall(self.patterns['large_base64'], content)
        
        for match in base64_matches:
            try:
                # Try to decode the Base64
                decoded = base64.b64decode(match)
                decoded_size = len(decoded)
                
                if decoded_size > self.min_suspicious_size:
                    blob_info = {
                        'size_encoded': len(match),
                        'size_decoded': decoded_size,
                        'preview': decoded[:100] if decoded_size > 100 else decoded,
                        'is_likely_executable': self.is_likely_executable(decoded)
                    }
                    results['base64_blobs'].append(blob_info)
                    results['suspicious'] = True
                    results['warnings'].append(
                        f"Large Base64 blob detected ({decoded_size} bytes decoded)"
                    )
                    
            except Exception:
                # Not valid Base64, continue
                continue
        
        # Check for JavaScript obfuscation
        for pattern in self.patterns['obfuscated_js']:
            if re.search(pattern, content, re.IGNORECASE):
                results['obfuscation_detected'] = True
                results['suspicious'] = True
                results['warnings'].append(f"Obfuscated JavaScript detected: {pattern}")
        
        # Check for suspicious ActiveX/COM objects
        for func in self.patterns['suspicious_functions']:
            if func in content:
                results['suspicious'] = True
                results['warnings'].append(f"Suspicious function call: {func}")
        
        # Determine risk level
        if results['suspicious']:
            if len(results['base64_blobs']) > 0 and any(b['is_likely_executable'] for b in results['base64_blobs']):
                results['risk_level'] = "HIGH"
            elif results['obfuscation_detected']:
                results['risk_level'] = "MEDIUM"
            else:
                results['risk_level'] = "LOW"
        
        return results
    
    def is_likely_executable(self, data):
        """Check if decoded data looks like an executable"""
        if len(data) < 2:
            return False
        
        # Check for MZ header (Windows EXE)
        if data.startswith(b'MZ'):
            return True
        
        # Check for PE header (typically at offset 0x3C)
        if len(data) > 0x40:
            try:
                pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                if pe_offset + 2 < len(data) and data[pe_offset:pe_offset+2] == b'PE':
                    return True
            except:
                pass
        
        return False
    
    def scan_directory_for_html(self, directory_path):
        """Scan directory for HTML files and analyze them"""
        suspicious_files = []
        
        html_extensions = ['.html', '.htm', '.xhtml']
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in html_extensions):
                    file_path = os.path.join(root, file)
                    result = self.analyze_html_file(file_path)
                    
                    if result['suspicious']:
                        suspicious_files.append(result)
                        print(f"🚨 SUSPICIOUS HTML: {file} - Risk: {result['risk_level']}")
                        for warning in result['warnings']:
                            print(f"   ⚠️  {warning}")
                    else:
                        print(f"✅ Clean HTML: {file}")
        
        return suspicious_files

def analyze_script_file(file_path):
    analyzer = ScriptAnalyzer()
    
    if file_path.lower().endswith(('.html', '.htm')):
        return analyzer.analyze_html_file(file_path)
    else:
        # For other file types, read and check for Base64/obfuscation
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return analyzer.analyze_html_content(content, file_path)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

if __name__ == "__main__":
    analyzer = ScriptAnalyzer()
    test_file = input("Enter HTML file path to analyze: ")
    result = analyzer.analyze_html_file(test_file)
    print(f"Analysis Result: {result}")