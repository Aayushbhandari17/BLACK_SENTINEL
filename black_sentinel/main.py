import time
import sys
from black_sentinel.core import event_store
from black_sentinel.core.event_system import bus
from black_sentinel.honeycomb import deployer, watcher
from black_sentinel.discovery import engine

def main():
    print("=========================================")
    print("   BLACK SENTINEL - PHASE 1 STARTUP      ")
    print("=========================================\n")
    
    print("[1] Initializing EventStore (SQLite)...")
    event_store.init_db()
    
    print("[2] Subscribing to EventBus topics...")
    # Link storage handlers
    bus.subscribe("HONEYTOKEN_TRIGGERED", event_store.handle_honeycomb_event)
    bus.subscribe("FINDING_DISCOVERED", event_store.handle_finding_event)
    
    # Link CLI visual loggers
    def log_finding(f):
        if getattr(f, "vault_match", False):
            print("    [!] PROTECTED SECRET EXPOSURE DETECTED: CRITICAL")
            print("        Details Hidden")
            print("        Review via Dashboard")
        else:
            print(f"    [!] EXPOSURE DETECTED: {f.severity} | {f.entity_type}")
            print(f"        Path: {f.file_path}")
            print(f"        Masked Value: {f.masked_value}")
        
    def log_alert(a):
        print(f"    [!] HONEYCOMB ALERT: {a.incident_type} on {a.honeytoken_path}")
        
    bus.subscribe("FINDING_DISCOVERED", log_finding)
    bus.subscribe("HONEYTOKEN_TRIGGERED", log_alert)
    
    print("[3] Deploying Honeycomb Protection Layer...")
    deployer.deploy()
    
    print("[4] Starting Honeycomb Watcher daemon...")
    observer = watcher.start_watcher()
    if not observer:
        print("[!] Failed to start watcher daemon. Exiting.")
        sys.exit(1)
        
    print("[5] Launching Tracking Engine Scanner...")
    # The tracking engine runs synchronously in this single-threaded Phase 1 runner,
    # while the watchdog observer handles filesystem events in its background thread.
    engine.start_tracking_engine()
    
    print("\n=========================================")
    print("   SYSTEM LIVE - PROTECTION ACTIVE       ")
    print("=========================================")
    print("Tracking Engine scan complete.")
    print("Honeycomb background daemon is monitoring for breaches.")
    print("Press Ctrl+C to terminate the system.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Black Sentinel...")
        from black_sentinel.detection import regex_engine
        regex_engine.print_summary()
        observer.stop()
    observer.join()
    print("[*] Shutdown complete.")

if __name__ == "__main__":
    main()
