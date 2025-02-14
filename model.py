import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.preprocessing import StandardScaler

class ThreatDetectionModel(nn.Module):
    def __init__(self, input_size=10):
        super(ThreatDetectionModel, self).__init__()
        
        # Deep neural network for threat detection
        self.network = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )
        
        self.scaler = StandardScaler()
        
    def forward(self, x):
        return self.network(x)
    
    def extract_features(self, ip_or_domain):
        """Extract AI features from IP or domain"""
        features = []
        
        if self._is_ip(ip_or_domain):
            # IP-based features
            octets = [int(x) for x in ip_or_domain.split('.')]
            features.extend([
                np.mean(octets),                    # Mean of octets
                np.std(octets),                     # Standard deviation
                max(octets),                        # Maximum value
                min(octets),                        # Minimum value
                len(set(octets)),                   # Unique octets
                self._entropy(ip_or_domain),        # String entropy
                1 if ip_or_domain.startswith('192.168') else 0,  # Internal IP
                1 if ip_or_domain.startswith('10.') else 0,      # Internal IP
                octets[0] / 255.0,                 # First octet normalized
                sum(octets) / 1020.0               # Sum of octets normalized
            ])
        else:
            # Domain-based features
            features.extend([
                len(ip_or_domain),                 # Length
                ip_or_domain.count('.'),           # Number of dots
                self._entropy(ip_or_domain),       # String entropy
                sum(c.isdigit() for c in ip_or_domain) / len(ip_or_domain),  # Digit ratio
                len(set(ip_or_domain)) / len(ip_or_domain),                  # Unique char ratio
                self._contains_suspicious_words(ip_or_domain),               # Suspicious words
                self._longest_consonant_sequence(ip_or_domain),             # Consonant sequence
                self._domain_length_score(ip_or_domain),                    # Length score
                self._special_char_ratio(ip_or_domain),                     # Special chars
                self._vowel_consonant_ratio(ip_or_domain)                   # Vowel ratio
            ])
            
        return torch.FloatTensor(features)
    
    def _is_ip(self, string):
        """Check if string is an IP address"""
        parts = string.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def _entropy(self, string):
        """Calculate Shannon entropy of string"""
        prob = [string.count(c) / len(string) for c in set(string)]
        return -sum(p * np.log2(p) for p in prob)
    
    def _contains_suspicious_words(self, domain):
        """Check for suspicious words in domain"""
        suspicious = ['free', 'win', 'prize', 'crypto', 'bank', 'secure', 'login']
        return any(word in domain.lower() for word in suspicious)
    
    def _longest_consonant_sequence(self, string):
        """Get length of longest consonant sequence"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        current = max_len = 0
        for c in string.lower():
            if c in consonants:
                current += 1
                max_len = max(max_len, current)
            else:
                current = 0
        return max_len
    
    def _domain_length_score(self, domain):
        """Score domain length (longer domains more suspicious)"""
        return min(len(domain) / 50.0, 1.0)
    
    def _special_char_ratio(self, string):
        """Calculate ratio of special characters"""
        special = '-_'
        return sum(c in special for c in string) / len(string)
    
    def _vowel_consonant_ratio(self, string):
        """Calculate vowel to consonant ratio"""
        vowels = 'aeiou'
        v_count = sum(c in vowels for c in string.lower())
        return v_count / len(string) if len(string) > 0 else 0

    def predict_threat(self, ip_or_domain):
        """Predict threat level for IP or domain"""
        features = self.extract_features(ip_or_domain)
        with torch.no_grad():
            prediction = self(features)
            return prediction.item() 