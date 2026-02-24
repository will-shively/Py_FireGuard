from scapy.all import IP
from netfilterqueue import NetfilterQueue
from firewall.state_table import StateTable
from firewall.rules import RuleEngine
from firewall.utils import extract_packet_info

class FirewallEngine:
    def __init__(self, rule_file):
        self.state_table = StateTable()
        self.rule_engine = RuleEngine(rule_file)

    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        info = extract_packet_info(scapy_packet)

        if not info or info["protocol"] != "TCP":
            packet.accept()
            return

        key = (
            info["src_ip"],
            info["dst_ip"],
            info["src_port"],
            info["dst_port"],
            info["protocol"]
        )

        state = self.state_table.get(key)

        flags = info["flags"]

        
        if flags == 0x02:  
            self.state_table.add(key, "SYN_SENT")

        elif flags == 0x10 and state:  
            self.state_table.update(key, "ESTABLISHED")

        elif flags in (0x01, 0x04):  
            self.state_table.remove(key)

        state = self.state_table.get(key)

        action = self.rule_engine.evaluate(info, state)

        if action == "DROP":
            print("Dropped:", info)
            packet.drop()
        else:
            packet.accept()

        self.state_table.cleanup()

    def run(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.process_packet)

        try:
            print("Firewall running...")
            nfqueue.run()
        except KeyboardInterrupt:
            nfqueue.unbind()
            print("Firewall stopped.")