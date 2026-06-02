import secrets
import string
import json
import base64

def generate_random_string(length: int, chars: str = string.ascii_letters + string.digits) -> str:
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_aws_access_key() -> str:
    return "AKIA" + generate_random_string(16, string.ascii_uppercase + string.digits)

def generate_aws_secret_key() -> str:
    return generate_random_string(40)

def generate_github_pat() -> str:
    return "ghp_" + generate_random_string(36)

def generate_generic_api_key() -> str:
    return generate_random_string(32)

def generate_env_file() -> str:
    return f"""AWS_ACCESS_KEY_ID={generate_aws_access_key()}
AWS_SECRET_ACCESS_KEY={generate_aws_secret_key()}
DATABASE_URL=postgresql://admin:{generate_random_string(12)}@localhost:5432/proddb
STRIPE_SECRET_KEY=sk_live_{generate_random_string(24)}
GITHUB_TOKEN={generate_github_pat()}
"""

def generate_ssh_private_key() -> str:
    body = base64.b64encode(generate_random_string(120).encode()).decode()
    lines = [body[i:i+64] for i in range(0, len(body), 64)]
    key_body = "\n".join(lines)
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{key_body}\n-----END OPENSSH PRIVATE KEY-----\n"

def generate_credentials_json() -> str:
    creds = {
        "api_key": generate_generic_api_key(),
        "client_secret": generate_random_string(32),
        "database_password": generate_random_string(16)
    }
    return json.dumps(creds, indent=4)

def generate_config_ini() -> str:
    return f"""[credentials]
username = admin_{generate_random_string(4)}
password = {generate_random_string(16)}
"""
