from monitor import ThreatMonitor
from datetime import datetime
import json
import os
import tkinter as tk
import threading
import time
from system_tray import SystemTray

def load_threat_feeds():
    """Load threat feeds from various sources"""
    try:
        # Load from local threat intel file
        if os.path.exists('threat_intel.json'):
            with open('threat_intel.json', 'r') as f:
                data = json.load(f)
                return data.get('malicious_ips', []), data.get('malicious_domains', [])
    except Exception as e:
        print(f"Error loading threat feeds: {str(e)}")
    
    # Return default data if loading fails
    return [
        "45.227.253.214",
        "192.168.1.100",
        "31.192.45.78"
    ], [
        "malware-site.com",
        "phishing-attempt.net",
        "suspicious-domain.org"
    ]

def check_threats_periodically(monitor, root):
    """Run threat checks in a separate thread"""
    check_count = 0
    while True:
        try:
            check_count += 1
            print(f"\n=== Threat Check #{check_count} ===")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Get IPs and domains to check
            suspicious_ips, suspicious_domains = load_threat_feeds()
            
            # Check IP addresses
            print(f"\nChecking {len(suspicious_ips)} IP addresses...")
            for ip in suspicious_ips:
                event = {
                    'type': 'ip_check',
                    'timestamp': datetime.now(),
                    'ip_address': ip
                }
                alert = monitor.process_event(event)
                print(f"IP: {ip} - {alert['severity']} ({alert['threat_score']:.3f})")
            
            # Check domains
            print(f"\nChecking {len(suspicious_domains)} domains...")
            for domain in suspicious_domains:
                event = {
                    'type': 'domain_check',
                    'timestamp': datetime.now(),
                    'domain': domain
                }
                alert = monitor.process_event(event)
                print(f"Domain: {domain} - {alert['severity']} ({alert['threat_score']:.3f})")
            
            print("\nWaiting 60 seconds until next check...")
            time.sleep(60)  # Check every minute
            
        except Exception as e:
            print(f"Error during threat check: {str(e)}")
            time.sleep(5)

def main():
    try:
        print("\n=== AI-Powered Threat Detection System ===")
        print("Initializing...")
        
        # Create the main window
        root = tk.Tk()
        root.withdraw()
        
        # Initialize the monitor
        monitor = ThreatMonitor()
        print("Monitor initialized successfully")
        
        # Create system tray icon
        tray = SystemTray(root)
        print("System tray icon created")
        
        # Start alert processing
        monitor.alert_system.process_alerts()
        print("Alert system initialized")
        
        # Start threat checking in a separate thread
        thread = threading.Thread(
            target=check_threats_periodically,
            args=(monitor, root),
            daemon=True
        )
        thread.start()
        print("Threat checking thread started")
        
        print("\nSystem is now running!")
        print("- Checking threats every 60 seconds")
        print("- Popup alerts will appear for medium/high threats")
        print("- Right-click system tray icon (red square) to exit")
        print("\nMonitoring in progress...\n")
        
        # Run the system tray icon
        root.mainloop()
        
    except Exception as e:
        print(f"\nFatal Error: {str(e)}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 