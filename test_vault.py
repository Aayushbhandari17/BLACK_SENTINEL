from black_sentinel.vault import registry as v
from black_sentinel.core import event_store
event_store.init_db()

# 1. Test supported types
types = v.get_supported_entity_types()
print("Supported types:", types)
assert "GOOGLE_API_KEY" in types
assert "HIGH_ENTROPY_SECRET" in types

# 2. Test Add Secret
vid = v.add_secret("GOOGLE_API_KEY", "AIzaSyTestSecret123", "AIzaSyTestSecret123")
print("Added vault id:", vid)

# 3. Test Invalid Add
try:
    v.add_secret("GOOGLE_API_KEY", "", "")
    assert False, "Should reject empty secret"
except ValueError as e:
    print("Caught empty:", e)

try:
    v.add_secret("GOOGLE_API_KEY", "A", "B")
    assert False, "Should reject mismatch"
except ValueError as e:
    print("Caught mismatch:", e)

try:
    v.add_secret("UNKNOWN", "A", "A")
    assert False, "Should reject unknown type"
except ValueError as e:
    print("Caught unknown type:", e)

# 4. Test Duplicate
try:
    v.add_secret("GOOGLE_API_KEY", "AIzaSyTestSecret123", "AIzaSyTestSecret123")
    assert False, "Should reject duplicate"
except ValueError as e:
    print("Caught duplicate:", e)

# 5. Test Verification
assert v.verify_detection("GOOGLE_API_KEY", "AIzaSyTestSecret123") == vid
assert v.verify_detection("GOOGLE_API_KEY", "aizasytestsecret123") is None

# 6. Test Increment
v.increment_detection_counter(vid)
entries = v.list_vault_entries()
print("Entries:", entries)
assert entries[0]["times_detected"] == 1

# 7. Test Delete
try:
    v.delete_secret(vid, "wrongsecret")
    assert False, "Should reject bad delete"
except ValueError as e:
    print("Caught bad delete:", e)

v.delete_secret(vid, "AIzaSyTestSecret123")
print("Deleted successfully. Remaining:", len(v.list_vault_entries()))

print("ALL TESTS PASSED.")
