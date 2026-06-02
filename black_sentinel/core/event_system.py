from typing import Callable, Dict, List, Any

class EventBus:
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, topic: str, callback: Callable):
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)

    def publish(self, topic: str, event: Any):
        if topic in self.subscribers:
            for callback in self.subscribers[topic]:
                try:
                    callback(event)
                except Exception as e:
                    print(f"Error in subscriber for topic {topic}: {e}")

# Global singleton
bus = EventBus()
