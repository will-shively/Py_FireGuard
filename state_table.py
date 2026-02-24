import time

class StateTable:
    def __init__(self, timeout=60):
        self.connections = {}
        self.timeout = timeout

    def make_key(self, src, dst, sport, dport, proto):
        return (src, dst, sport, dport, proto)

    def add(self, key, state):
        self.connections[key] = {
            "state": state,
            "last_seen": time.time()
        }

    def update(self, key, state):
        if key in self.connections:
            self.connections[key]["state"] = state
            self.connections[key]["last_seen"] = time.time()

    def get(self, key):
        return self.connections.get(key)

    def remove(self, key):
        if key in self.connections:
            del self.connections[key]

    def cleanup(self):
        now = time.time()
        for key in list(self.connections.keys()):
            if now - self.connections[key]["last_seen"] > self.timeout:
                del self.connections[key]
