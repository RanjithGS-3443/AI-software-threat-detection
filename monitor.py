from data_collector import DataCollector
from model import ThreatDetectionModel
from alert_system import AlertSystem
import numpy as np
import torch

class ThreatMonitor:
    def __init__(self, model_path=None):
        self.collector = DataCollector()
        self.model = ThreatDetectionModel()
        self.alert_system = AlertSystem()
        if model_path and torch.cuda.is_available():
            self.model.load_state_dict(torch.load(model_path))
        self.model.eval()

        # Known malicious IPs and their threat scores
        self.known_malicious_ips = {
            "45.227.253.214": 0.95,  # Known malicious IP
            "31.192.45.78": 0.85,    # Known scanner
            "185.143.223.45": 0.90,  # Known botnet
            "103.91.206.72": 0.80,   # Suspicious traffic source
        }

        # Known malicious domains and their threat scores
        self.known_malicious_domains = {
            "malware-site.com": 0.95,
            "phishing-attempt.net": 0.90,
            "suspicious-domain.org": 0.85,
            "spam-source.com": 0.80,
            "botnet-cc.net": 0.90,
        }

    def process_event(self, event):
        """Process an event using AI model"""
        if event['type'] == 'ip_check':
            threat_score = self.model.predict_threat(event['ip_address'])
        else:
            threat_score = self.model.predict_threat(event['domain'])

        alert = self._generate_alert(threat_score)
        
        # Add event details to alert
        alert.update(event)
        
        # Show popup for medium and high threats
        if alert['severity'] in ['MEDIUM', 'HIGH']:
            self.alert_system.show_alert(alert)
            
        return alert

    def _generate_alert(self, threat_score):
        """Generate alert based on AI prediction"""
        if threat_score >= 0.8:
            severity = "HIGH"
            action = "Block and investigate immediately"
        elif threat_score >= 0.5:
            severity = "MEDIUM"
            action = "Monitor closely and investigate"
        else:
            severity = "LOW"
            action = "Log for future reference"

        return {
            "severity": severity,
            "threat_score": threat_score,
            "recommended_action": action
        } 