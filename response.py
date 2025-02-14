class ThreatResponse:
    def __init__(self):
        self.firewall = FirewallAPI()
        
    def handle_threat(self, alert):
        if alert['severity'] == "HIGH":
            self.firewall.block_ip(alert['ip'])
            self.notify_admin(alert) 