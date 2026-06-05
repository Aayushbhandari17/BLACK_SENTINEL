import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, Any

@dataclass
class BaseEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: Optional[str] = None
    event_type: str = ""
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_extract: Optional[str] = None
    vault_ref: Optional[str] = None

@dataclass
class Finding(BaseEvent):
    file_path: str = ""
    detector: str = ""
    entity_type: str = ""
    raw_value: str = ""  # kept in RAM only
    masked_value: str = ""
    context: Optional[str] = None
    confidence: float = 0.0
    line_number: Optional[int] = None
    validated: bool = False
    vault_match: bool = False

@dataclass
class HoneycombAlert(BaseEvent):
    honeytoken_path: str = ""
    token_id: str = ""
    token_type: str = ""
    incident_type: str = ""
    confidence: float = 1.0
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    username: Optional[str] = None
    process_path: Optional[str] = None
    attribution_source: str = "UNKNOWN"

@dataclass
class TextChunk:
    file_path: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeployedToken:
    path: str
    token_id: str
    deployed_at: datetime
    content_hash: str
