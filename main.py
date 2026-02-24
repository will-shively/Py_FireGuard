from firewall.engine import FirewallEngine

if __name__ == "__main__":
    firewall = FirewallEngine("config/rules.yaml")
    firewall.run()