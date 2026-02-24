import yaml

class RuleEngine:
    def __init__(self, rule_file):
        with open(rule_file, "r") as f:
            self.rules = yaml.safe_load(f)["rules"]

    def evaluate(self, packet_info, state):
        for rule in self.rules:

            
            if "state" in rule and state:
                if state["state"] == rule["state"]:
                    return rule["action"]

            
            if "protocol" in rule:
                if packet_info["protocol"] == rule["protocol"]:
                    if "dst_port" in rule:
                        if packet_info["dst_port"] == rule["dst_port"]:
                            return rule["action"]

        return "ALLOW"