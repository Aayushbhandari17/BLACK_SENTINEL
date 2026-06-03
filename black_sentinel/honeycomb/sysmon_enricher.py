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
        
    debug_reason = "No Sysmon match found in window."
    events_returned = 0
    candidate_selected = False
    
    try:
        # Fetch last 100 Sysmon events to manually filter in Python
        query = "*"
        cmd_xml = [
            "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
            f"/q:{query}",
            "/c:100", "/rd:true"
        ]
        
        print(f"[DEBUG-SYSMON] Executing: {' '.join(cmd_xml)}")
        out = subprocess.check_output(cmd_xml, stderr=subprocess.STDOUT, text=True)
        if not out.strip():
            debug_reason = "wevtutil returned empty output."
            print(f"[DEBUG-SYSMON] {debug_reason}")
            return res
            
        xml_string = f"<Events>{out.strip()}</Events>"
        root = ET.fromstring(xml_string)
        
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        
        window_start = event_timestamp - timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        window_end = event_timestamp + timedelta(seconds=CORRELATION_WINDOW_SECONDS)
        
        best_event = None
        best_match_type = None # 'target' or 'cmdline'
        
        norm_search_path = file_path.lower().replace('/', '\\')
        print(f"[DEBUG-SYSMON] Searching for normalized path: {norm_search_path}")
        
        events = root.findall("ns:Event", ns)
        events_returned = len(events)
        print(f"[DEBUG-SYSMON] Sysmon events returned: {events_returned}")
        
        examined_ids = []
        path_match_occurred = False
        
        for event in events:
            system = event.find("ns:System", ns)
            if system is None:
                continue
                
            event_id_elem = system.find("ns:EventID", ns)
            if event_id_elem is not None:
                examined_ids.append(event_id_elem.text)
                
            time_created = system.find("ns:TimeCreated", ns)
            if time_created is None:
                continue
                
            sys_time_str = time_created.get("SystemTime")
            if not sys_time_str:
                continue
                
            try:
                sys_time = datetime.strptime(sys_time_str[:26] + "Z", "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                try:
                    sys_time = datetime.strptime(sys_time_str, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    continue
                    
            if window_start <= sys_time <= window_end:
                event_data = event.find("ns:EventData", ns)
                if event_data is not None:
                    target_file = ""
                    cmd_line = ""
                    
                    for data in event_data.findall("ns:Data", ns):
                        name = data.get("Name")
                        if name == "TargetFilename" and data.text:
                            target_file = data.text.lower().replace('/', '\\')
                        elif name == "CommandLine" and data.text:
                            cmd_line = data.text.lower().replace('/', '\\')
                            
                    is_target_match = (norm_search_path == target_file or norm_search_path in target_file)
                    is_cmd_match = (norm_search_path in cmd_line)
                    
                    if is_target_match or is_cmd_match:
                        path_match_occurred = True
                        if is_target_match:
                            # TargetFilename is the strongest match, prefer it
                            best_event = event
                            best_match_type = 'target'
                            break
                        elif is_cmd_match and best_match_type != 'target':
                            # Keep cmdline match but continue searching in case a Target match exists
                            best_event = event
                            best_match_type = 'cmdline'
                            
        print(f"[DEBUG-SYSMON] Event IDs examined in window: {list(set(examined_ids))}")
        print(f"[DEBUG-SYSMON] Path match occurred: {path_match_occurred}")
        
        if best_event is not None:
            candidate_selected = True
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
        else:
            if not path_match_occurred:
                debug_reason = "No events in time window contained the target path in TargetFilename or CommandLine."
            else:
                debug_reason = "Path matched, but event structure was invalid."
            print(f"[DEBUG-SYSMON] Fallback to UNKNOWN reason: {debug_reason}")
                
    except Exception as e:
        debug_reason = f"Exception occurred: {str(e)}"
        print(f"[DEBUG-SYSMON] Fallback to UNKNOWN reason: {debug_reason}")
        
    print(f"[DEBUG-SYSMON] Candidate selected: {candidate_selected}")
    return res
