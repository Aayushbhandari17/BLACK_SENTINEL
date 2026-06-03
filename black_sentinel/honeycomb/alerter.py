import psutil
from datetime import datetime
from black_sentinel.schemas.models import HoneycombAlert
from black_sentinel.core.event_system import bus
from black_sentinel.honeycomb import sysmon_enricher

def trigger_alert(path: str, event_type: str, token_id: str, token_type: str, incident_type: str):
    current_time = datetime.utcnow()
    
    # 1. Sysmon Enrichment
    enrichment = sysmon_enricher.get_enrichment(path, event_type, current_time)
    
    # 2. Attempt Fallback Attribution (Best Effort) if Sysmon failed
    if enrichment["attribution_source"] == "UNKNOWN":
        inspected = 0
        candidate_found = False
        print("[DEBUG] Fallback attribution attempted using psutil.")
        try:
            for proc in psutil.process_iter(['name', 'pid', 'exe', 'username']):
                inspected += 1
                try:
                    open_files = proc.open_files()
                    if open_files:
                        for f in open_files:
                            if f.path == path:
                                enrichment["user"] = proc.info.get('username') or "UNKNOWN"
                                enrichment["process_name"] = proc.info.get('name') or "UNKNOWN"
                                enrichment["process_id"] = proc.info.get('pid')
                                enrichment["process_path"] = proc.info.get('exe') or "UNKNOWN"
                                enrichment["attribution_source"] = "FALLBACK"
                                candidate_found = True
                                break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if candidate_found:
                    break
        except Exception:
            pass
        print(f"[DEBUG] Processes inspected: {inspected}")
        print(f"[DEBUG] Candidate selected: {candidate_found}")
            
    # 3. Immediate Alert Generation
    alert = HoneycombAlert(
        event_type=event_type,
        severity="CRITICAL",
        source="honeycomb",
        honeytoken_path=path,
        token_id=token_id,
        token_type=token_type,
        incident_type=incident_type,
        confidence=1.0,
        timestamp=current_time,
        username=enrichment.get("user"),
        process_name=enrichment.get("process_name"),
        process_path=enrichment.get("process_path"),
        process_id=enrichment.get("process_id"),
        attribution_source=enrichment.get("attribution_source")
    )
    
    # 4. Console Output
    print("\nHONEYCOMB ALERT")
    print(f"\nFile:\n{alert.honeytoken_path}")
    print(f"\nEvent:\n{alert.incident_type}")
    print(f"\nUser:\n{alert.username or 'UNKNOWN'}")
    print(f"\nProcess:\n{alert.process_name or 'UNKNOWN'}")
    print(f"\nProcess Path:\n{alert.process_path or 'UNKNOWN'}")
    print(f"\nPID:\n{alert.process_id or 'UNKNOWN'}")
    print(f"\nTime:\n{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\nRisk:\n{alert.severity}")
    print(f"\nSource:\n{alert.attribution_source}\n")
    
    # 5. Event Dispatch
    bus.publish("HONEYTOKEN_TRIGGERED", alert)
