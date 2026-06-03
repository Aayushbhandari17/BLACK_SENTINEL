import sys
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, Any

CORRELATION_WINDOW_SECONDS = 5

def get_enrichment(file_path: str, event_type: str, event_timestamp: datetime) -> Dict[str, Any]:
    """
    Queries Sysmon for process attribution based on a time window around the honeytoken event.
    """
    res = {
        "user": "UNKNOWN",
        "process_name": "UNKNOWN",
        "process_path": "UNKNOWN",
        "process_id": None,
        "attribution_source": "UNKNOWN"
    }

    if sys.platform != "win32":
        return res
        
    try:
        # Wevtutil query to find any event targeting the file
        query = f"*[EventData[Data[@Name='TargetFilename']='{file_path}']]"
        
        cmd = [
            "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
            f"/q:{query}",
            "/rd:true", # reverse direction (newest first)
            "/f:text"   # actually, XML is easier to parse. /f:xml is default for qe
        ]
        
        # wevtutil qe outputs a series of XML Event elements. We don't use /c:1 to allow window search.
        # But to be safe on performance, limit to recent events.
        cmd_xml = [
            "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
            f"/q:{query}",
            "/c:10", "/rd:true"
        ]
        
        out = subprocess.check_output(cmd_xml, stderr=subprocess.STDOUT, text=True)
        if not out.strip():
            return res
            
        # wevtutil outputs multiple <Event> elements without a single root.
        xml_string = f"<Events>{out.strip()}</Events>"
        root = ET.fromstring(xml_string)
        
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        
        window_start = event_timestamp - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        window_end = event_timestamp + timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        
        best_event = None
        
        for event in root.findall("ns:Event", ns):
            system = event.find("ns:System", ns)
            if system is None:
                continue
                
            time_created = system.find("ns:TimeCreated", ns)
            if time_created is None:
                continue
                
            sys_time_str = time_created.get("SystemTime")
            if not sys_time_str:
                continue
                
            try:
                # Format: 2026-06-03T11:21:43.123456Z
                sys_time = datetime.strptime(sys_time_str[:26] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                try:
                    sys_time = datetime.strptime(sys_time_str, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    continue
                    
            if window_start <= sys_time <= window_end:
                best_event = event
                break # Since /rd:true gives newest first, we might want the closest one, but first in window is fine.
                
        if best_event is not None:
            event_data = best_event.find("ns:EventData", ns)
            if event_data is not None:
                for data in event_data.findall("ns:Data", ns):
                    name = data.get("Name")
                    if name == "Image":
                        res["process_path"] = data.text
                        if data.text:
                            res["process_name"] = os.path.basename(data.text)
                    elif name == "ProcessId":
                        res["process_id"] = int(data.text)
                    elif name == "User":
                        res["user"] = data.text
                        
                res["attribution_source"] = "SYSMON"
                
    except Exception:
        pass
        
    return res
