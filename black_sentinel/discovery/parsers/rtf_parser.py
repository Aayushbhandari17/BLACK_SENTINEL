from striprtf.striprtf import rtf_to_text
import os

class RTFParser:
    def parse(self, file_path: str) -> str:
        try:
            if not os.path.exists(file_path):
                return ""
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                rtf_content = f.read()
            return rtf_to_text(rtf_content)
        except Exception as e:
            print(f"[-] RTF Parsing failed for {file_path}: {str(e)}")
            return ""
