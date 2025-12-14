# file_signature_scanner.py
import os
import struct

class FileSignatureScanner:
    def __init__(self):
        # Known file signatures (magic numbers)
        self.signatures = {
            b'%PDF': 'PDF',
            b'\x4D\x5A': 'EXE',  # MZ header
            b'\x50\x4B\x03\x04': 'ZIP',  # Also DOCX, XLSX
            b'\x4C\x00\x00\x00': 'LNK',  # Windows Shortcut
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG': 'PNG',
            b'GIF8': 'GIF',
            b'\x25\x50\x44\x46': 'PDF_alternative'  # %PDF in different encoding
        }
        
        # Suspicious extensions that are often spoofed
        self.suspicious_extensions = ['.pdf', '.doc', '.docx', '.xls', '.jpg', '.png']
        
    def get_file_signature(self, file_path):
        """Read the first 20 bytes of a file to determine its signature"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)
                return header
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None
    
    def detect_file_type(self, header):
        """Detect file type based on magic number"""
        for signature, file_type in self.signatures.items():
            if header.startswith(signature):
                return file_type
        return 'UNKNOWN'
    
    def scan_file(self, file_path):
        """Scan a single file for signature mismatch"""
        if not os.path.exists(file_path):
            return {"status": "ERROR", "message": "File not found"}
        
        filename = os.path.basename(file_path)
        file_extension = os.path.splitext(filename)[1].lower()
        
        # Read file signature
        header = self.get_file_signature(file_path)
        if not header:
            return {"status": "ERROR", "message": "Could not read file"}
        
        # Detect actual file type
        actual_type = self.detect_file_type(header)
        
        # Check for mismatch
        result = {
            "filename": filename,
            "extension": file_extension,
            "actual_type": actual_type,
            "header_preview": header[:8].hex(),
            "is_suspicious": False,
            "warning": ""
        }
        
        # Check for suspicious patterns
        if actual_type == 'LNK' and file_extension in ['.pdf', '.doc', '.jpg']:
            result["is_suspicious"] = True
            result["warning"] = f"LNK file masquerading as {file_extension.upper()}"
        
        elif actual_type == 'EXE' and file_extension in ['.pdf', '.doc', '.jpg', '.png']:
            result["is_suspicious"] = True
            result["warning"] = f"EXE file masquerading as {file_extension.upper()}"
        
        elif actual_type == 'UNKNOWN' and file_extension in self.suspicious_extensions:
            result["is_suspicious"] = True
            result["warning"] = "Unknown file type with common document extension"
        
        return result
    
    def scan_directory(self, directory_path):
        """Scan all files in a directory"""
        suspicious_files = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                result = self.scan_file(file_path)
                
                if result["is_suspicious"]:
                    suspicious_files.append(result)
                    print(f"🚨 SUSPICIOUS: {file} - {result['warning']}")
                else:
                    print(f"✅ Clean: {file} - Actual: {result['actual_type']}")
        
        return suspicious_files

# Standalone function for quick scanning
def quick_scan(file_path):
    scanner = FileSignatureScanner()
    return scanner.scan_file(file_path)

if __name__ == "__main__":
    # Test the scanner
    scanner = FileSignatureScanner()
    test_file = input("Enter file path to scan: ")
    result = scanner.scan_file(test_file)
    print(f"Scan Result: {result}")