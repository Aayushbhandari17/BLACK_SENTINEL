import json
import re
import os

def extract_config_secrets(file_path):
    """
    Parses structured configuration files (JSON, .env, INI/properties) 
    and flattens them into an optimized text string for the scanner.
    """
    text_content = []
    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        if not os.path.exists(file_path):
            return ""

        # 1. Handle JSON Configurations
        if ext == '.json':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                # Flatten nested JSON dictionaries into readable key=value strings
                def flatten(obj, prefix=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            flatten(v, f"{prefix}{k}.")
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            flatten(item, f"{prefix}{i}.")
                    else:
                        text_content.append(f"{prefix[:-1]} = {obj}")
                flatten(data)

        # 2. Handle .env, .ini, and .properties structures
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Skip blank lines and pure comments
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    # Match key=value or key:value patterns
                    match = re.match(r'^([^=: \t]+)\s*[=:]\s*(.*)$', line)
                    if match:
                        key, val = match.groups()
                        # Clean quotes around values
                        val = val.strip("'\"")
                        text_content.append(f"{key} = {val}")

        return "\n".join(text_content)

    except Exception as e:
        print(f"[-] Config Parsing failed for {file_path}: {str(e)}")
        return ""