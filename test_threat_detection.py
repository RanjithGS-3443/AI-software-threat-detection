import unittest
from monitor import ThreatMonitor
from data_collector import DataCollector
from model import ThreatDetector
import torch
import numpy as np

class TestThreatDetection(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.monitor = ThreatMonitor()
        self.collector = DataCollector()

    def test_network_event_processing(self):
        """Test processing of network events"""
        network_event = {
            'type': 'network',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'packet_size': 1500,
            'protocol': 'TCP'
        }
        
        alert = self.monitor.process_event(network_event)
        
        # Test alert structure
        self.assertIn('severity', alert)
        self.assertIn('threat_score', alert)
        self.assertIn('recommended_action', alert)
        self.assertIn('timestamp', alert)
        
        # Test threat score is in valid range
        self.assertTrue(0 <= alert['threat_score'] <= 1)

    def test_log_event_processing(self):
        """Test processing of log events"""
        log_event = {
            'type': 'log',
            'user': 'admin',
            'action': 'login',
            'resource': '/admin/dashboard'
        }
        
        alert = self.monitor.process_event(log_event)
        
        # Test alert structure
        self.assertIn('severity', alert)
        self.assertIn('threat_score', alert)
        self.assertIn('recommended_action', alert)

    def test_data_collector(self):
        """Test data collection functionality"""
        # Test network data collection
        network_data = self.collector.collect_network_data(
            source_ip='192.168.1.1',
            dest_ip='192.168.1.2',
            packet_size=1000,
            protocol='UDP'
        )
        
        self.assertEqual(network_data['type'], 'network')
        self.assertEqual(network_data['source_ip'], '192.168.1.1')
        
        # Test log data collection
        log_data = self.collector.collect_log_data(
            user='user1',
            action='delete',
            resource='file.txt'
        )
        
        self.assertEqual(log_data['type'], 'log')
        self.assertEqual(log_data['user'], 'user1')

    def test_threat_levels(self):
        """Test different threat levels and corresponding actions"""
        # Mock the predict method to return known threat scores
        original_predict = self.monitor.model.predict
        
        # Create a complete network event
        network_event = {
            'type': 'network',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'packet_size': 1500,
            'protocol': 'TCP'
        }
        
        try:
            # Test HIGH severity
            self.monitor.model.predict = lambda x: 0.9
            alert_high = self.monitor.process_event(network_event)
            self.assertEqual(alert_high['severity'], 'HIGH')
            
            # Test MEDIUM severity
            self.monitor.model.predict = lambda x: 0.6
            alert_medium = self.monitor.process_event(network_event)
            self.assertEqual(alert_medium['severity'], 'MEDIUM')
            
            # Test LOW severity
            self.monitor.model.predict = lambda x: 0.3
            alert_low = self.monitor.process_event(network_event)
            self.assertEqual(alert_low['severity'], 'LOW')
        
        finally:
            # Restore original predict method
            self.monitor.model.predict = original_predict

    def test_model_structure(self):
        """Test the neural network model structure"""
        model = ThreatDetector(input_size=10)
        
        # Test input layer
        self.assertEqual(
            model.network[0].in_features, 
            10,
            "Input layer size should match specified input_size"
        )
        
        # Test output layer
        final_layer = model.network[-2]  # -2 because -1 is Sigmoid
        self.assertEqual(
            final_layer.out_features,
            1,
            "Output layer should have 1 output"
        )

    def test_recommended_actions(self):
        """Test recommended actions for different severity levels"""
        network_event = {
            'type': 'network',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.5',
            'packet_size': 1500,
            'protocol': 'TCP'
        }
        
        original_predict = self.monitor.model.predict
        try:
            # Test HIGH severity action
            self.monitor.model.predict = lambda x: 0.9
            alert_high = self.monitor.process_event(network_event)
            self.assertEqual(
                alert_high['recommended_action'],
                "Block IP and investigate immediately"
            )
            
            # Test MEDIUM severity action
            self.monitor.model.predict = lambda x: 0.6
            alert_medium = self.monitor.process_event(network_event)
            self.assertEqual(
                alert_medium['recommended_action'],
                "Monitor closely and investigate"
            )
            
            # Test LOW severity action
            self.monitor.model.predict = lambda x: 0.3
            alert_low = self.monitor.process_event(network_event)
            self.assertEqual(
                alert_low['recommended_action'],
                "Log for future reference"
            )
        finally:
            self.monitor.model.predict = original_predict

if __name__ == '__main__':
    unittest.main() 