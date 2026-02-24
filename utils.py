from scapy.layers.inet import IP, TCP

def extract_packet_info(packet):
    if not packet.haslayer(IP):
        return None

    info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "flags": None
    }

    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["flags"] = packet[TCP].flags

    return info