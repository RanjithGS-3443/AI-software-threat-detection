import pandas as pd
from datetime import datetime

class DataCollector:
    def __init__(self):
        self.data_buffer = []

    def collect_network_data(self, source_ip, dest_ip, packet_size, protocol):
        """Collect network traffic data point"""
        data_point = {
            'timestamp': datetime.now(),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'packet_size': packet_size,
            'protocol': protocol,
            'type': 'network'
        }
        self.data_buffer.append(data_point)
        return data_point

    def collect_log_data(self, user, action, resource):
        """Collect system log data point"""
        data_point = {
            'timestamp': datetime.now(),
            'user': user,
            'action': action,
            'resource': resource,
            'type': 'log'
        }
        self.data_buffer.append(data_point)
        return data_point

    def get_recent_data(self, n_samples=100):
        """Return the n most recent data points"""
        return pd.DataFrame(self.data_buffer[-n_samples:]) 