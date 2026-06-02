import os
import json
import uuid
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from black_sentinel.honeycomb import generator

# Default manifest location
MANIFEST_PATH = os.path.join(os.path.expanduser("~"), ".black_sentinel", "manifest.enc")
KEY_PATH = os.path.join(os.path.expanduser("~"), ".black_sentinel", "fernet.key")

def _ensure_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def get_or_create_key() -> bytes:
    _ensure_dir(KEY_PATH)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

def deploy():
    home = os.path.expanduser("~")
    
    # Define deployments
    deployments_config = [
        (os.path.join(home, "Documents", "credentials.txt"), generator.generate_generic_api_key(), "GENERIC_API_KEY"),
        (os.path.join(home, "Desktop", ".env"), generator.generate_env_file(), "ENV_FILE"),
        (os.path.join(home, ".ssh", "backup_key"), generator.generate_ssh_private_key(), "SSH_PRIVATE_KEY"),
        (os.path.join(home, ".app_config.json"), generator.generate_credentials_json(), "JSON_CREDENTIALS"),
        (os.path.join(home, "Downloads", "api_keys.txt"), f"AWS: {generator.generate_aws_access_key()}\nGH: {generator.generate_github_pat()}", "MIXED_API_KEYS"),
        (os.path.join(home, "Documents", "dev", "secrets.env"), generator.generate_env_file(), "ENV_FILE")
    ]
    
    manifest = {"deployed_tokens": []}
    
    for path, content, token_type in deployments_config:
        try:
            _ensure_dir(path)
            with open(path, "w", encoding='utf-8') as f:
                f.write(content)
                
            content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            manifest["deployed_tokens"].append({
                "path": path,
                "token_id": str(uuid.uuid4()),
                "token_type": token_type,
                "deployed_at": datetime.utcnow().isoformat(),
                "content_hash": content_hash
            })
        except Exception as e:
            print(f"Failed to deploy honeytoken at {path}: {e}")
            
    # Encrypt manifest
    key = get_or_create_key()
    f = Fernet(key)
    manifest_bytes = json.dumps(manifest).encode()
    encrypted_manifest = f.encrypt(manifest_bytes)
    
    _ensure_dir(MANIFEST_PATH)
    with open(MANIFEST_PATH, "wb") as mf:
        mf.write(encrypted_manifest)

def get_manifest() -> dict:
    if not os.path.exists(MANIFEST_PATH):
        return {"deployed_tokens": []}
        
    key = get_or_create_key()
    f = Fernet(key)
    with open(MANIFEST_PATH, "rb") as mf:
        encrypted_manifest = mf.read()
        
    try:
        manifest_bytes = f.decrypt(encrypted_manifest)
        return json.loads(manifest_bytes)
    except Exception:
        return {"deployed_tokens": []}
