import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from black_sentinel.core import event_store
from black_sentinel.detection import regex_engine

ph = PasswordHasher()

def get_supported_entity_types() -> set:
    """Returns a set of all entity types supported by current detectors."""
    types = {p["entity_type"] for p in regex_engine.PATTERNS}
    for _, entity_type in getattr(regex_engine, "CREDENTIAL_STORES", []):
        types.add(entity_type)
    types.add("HIGH_ENTROPY_SECRET")
    return types

def add_secret(secret_type: str, secret: str, confirm_secret: str) -> str:
    """
    Validates and hashes a secret using Argon2id, adding it to the vault DB.
    Enforces strict matching, length limits, and prevents duplicates.
    """
    if not secret or not secret.strip():
        raise ValueError("Secret cannot be empty or whitespace only.")
        
    if len(secret) > 1000:
        raise ValueError("Secret exceeds maximum allowed length.")
        
    if secret != confirm_secret:
        raise ValueError("Secret and Confirmation do not match.")
        
    if secret_type not in get_supported_entity_types():
        raise ValueError(f"Unsupported secret type: {secret_type}")
        
    # Duplicate prevention
    existing_entries = event_store.get_vault_entries_by_type(secret_type)
    for entry in existing_entries:
        try:
            if ph.verify(entry["argon2_hash"], secret):
                raise ValueError("Secret already protected.")
        except VerifyMismatchError:
            continue
            
    vault_id = str(uuid.uuid4())
    hashed = ph.hash(secret)
    
    event_store.insert_vault_entry(vault_id, secret_type, hashed)
    return vault_id

def delete_secret(vault_id: str, entered_secret: str) -> bool:
    """
    Verified delete workflow. Performs argon2.verify against the stored hash.
    If it matches, the entry is deleted.
    """
    stored_hash = event_store.get_vault_entry_hash(vault_id)
    if not stored_hash:
        raise ValueError("Vault entry not found.")
        
    try:
        if ph.verify(stored_hash, entered_secret):
            event_store.delete_vault_entry(vault_id)
            return True
    except VerifyMismatchError:
        raise ValueError("Verification failed. Secret does not match.")
        
    return False

def verify_detection(entity_type: str, detected_secret: str) -> str:
    """
    Checks if a detected secret is stored in the vault.
    Returns the vault_id if matched, otherwise None.
    Strictly case-sensitive per requirements.
    """
    if not detected_secret:
        return None
        
    entries = event_store.get_vault_entries_by_type(entity_type)
    
    for entry in entries:
        try:
            if ph.verify(entry["argon2_hash"], detected_secret):
                return entry["vault_id"]
        except VerifyMismatchError:
            continue
            
    return None

def increment_detection_counter(vault_id: str):
    """Increments the times_detected counter for a vault entry."""
    event_store.increment_vault_detection(vault_id)

def list_vault_entries() -> list:
    """Returns all vault entries (metadata only, no hashes/secrets)."""
    return event_store.get_all_vault_entries()

def get_protected_findings() -> list:
    """Returns all findings where vault_match is true."""
    return event_store.get_protected_findings()

def get_regular_findings() -> list:
    """Returns all findings where vault_match is false."""
    return event_store.get_regular_findings()
