import psutil
from datetime import datetime
from black_sentinel.schemas.models import HoneycombAlert
from black_sentinel.core.event_system import bus

def trigger_alert(path: str, event_type: str, token_id: str, token_type: str, incident_type: str):
    # 1. Immediate Alert Generation
    alert = HoneycombAlert(
        event_type=event_type,
        severity="CRITICAL",
        source="honeycomb",
        honeytoken_path=path,
        token_id=token_id,
        token_type=token_type,
        incident_type=incident_type,
        confidence=1.0,
        timestamp=datetime.utcnow()
    )
    
    # 2. Attempt Process Attribution (Best Effort)
    try:
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                # open_files() requires elevated privileges for other users' processes,
                # but we try best-effort.
                open_files = proc.open_files()
                if open_files:
                    for f in open_files:
                        if f.path == path:
                            alert.process_name = proc.info.get('name')
                            alert.process_id = proc.info.get('pid')
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if alert.process_name:
                break
    except Exception:
        pass
        
    # 3. Event Dispatch
    bus.publish("HONEYTOKEN_TRIGGERED", alert)
