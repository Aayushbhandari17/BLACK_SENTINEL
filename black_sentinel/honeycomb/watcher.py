import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from black_sentinel.honeycomb import deployer, alerter

class HoneytokenHandler(FileSystemEventHandler):
    def __init__(self, tokens):
        super().__init__()
        self.monitored_paths = {os.path.normcase(os.path.abspath(t["path"])): t for t in tokens}

    def _check_and_alert(self, event_path, event_type, incident_type):
        norm_path = os.path.normcase(os.path.abspath(event_path))
        if norm_path in self.monitored_paths:
            token = self.monitored_paths[norm_path]
            alerter.trigger_alert(norm_path, event_type, token.get("token_id", ""), token.get("token_type", ""), incident_type)

    def on_modified(self, event):
        if not event.is_directory:
            self._check_and_alert(event.src_path, "modified", "FILE_MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            self._check_and_alert(event.src_path, "deleted", "TOKEN_ACCESSED")

    def on_moved(self, event):
        if not event.is_directory:
            self._check_and_alert(event.src_path, "moved", "TOKEN_ACCESSED")
            self._check_and_alert(event.dest_path, "moved_to", "TOKEN_ACCESSED")
            
    def on_opened(self, event):
        if not event.is_directory:
            self._check_and_alert(event.src_path, "opened", "FILE_OPEN")

def start_watcher() -> Observer:
    manifest = deployer.get_manifest()
    tokens = manifest.get("deployed_tokens", [])
    if not tokens:
        return None
        
    monitored_paths = [t["path"] for t in tokens]
    directories_to_watch = set(os.path.dirname(p) for p in monitored_paths)
    
    event_handler = HoneytokenHandler(tokens)
    observer = Observer()
    
    for d in directories_to_watch:
        if os.path.exists(d):
            observer.schedule(event_handler, d, recursive=False)
            
    observer.daemon = True
    observer.start()
    return observer
