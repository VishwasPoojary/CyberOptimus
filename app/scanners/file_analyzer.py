import magic
from app.scanners.base_scanner import BaseScanner
from app.utils.crypto import get_file_hashes

class FileAnalyzer(BaseScanner):
    
    def scan(self, target: str) -> dict:
        # target here is expected to be raw bytes of the file, or a file path.
        # Since it's web upload, we will receive bytes.
        
        # In this implementation, target is a tuple/dict of (filename, bytes)
        # However, to conform with BaseScanner which expects a string,
        # we'll alter the signature slightly or assume target is the file content as bytes.
        pass
        
    def scan_file(self, file_content: bytes, filename: str) -> dict:
        hashes = get_file_hashes(file_content)
        md5_hash = hashes['md5']
        sha1_hash = hashes['sha1']
        sha256_hash = hashes['sha256']
        
        try:
            mime_type = magic.from_buffer(file_content, mime=True)
            file_desc = magic.from_buffer(file_content)
        except Exception:
            mime_type = "Unknown"
            file_desc = "Unknown"
            
        size_bytes = len(file_content)
        
        # Check against some very basic suspicious extensions or mime types
        suspicious = False
        reasons = []
        
        executables = ['application/x-dosexec', 'application/x-executable', 'application/x-mach-binary']
        if mime_type in executables:
            suspicious = True
            reasons.append("Executable file detected. These can be dangerous.")
            
        if filename.lower().endswith(('.exe', '.bat', '.cmd', '.sh', '.vbs', '.js', '.jar')):
            suspicious = True
            reasons.append("Suspicious file extension.")
            
        return {
            "filename": filename,
            "size_bytes": size_bytes,
            "mime_type": mime_type,
            "description": file_desc,
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "is_suspicious": suspicious,
            "reasons": reasons,
            "status": "success"
        }
