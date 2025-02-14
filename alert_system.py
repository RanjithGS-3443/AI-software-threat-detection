import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import queue
import os

# Try to import Windows-specific modules
try:
    import win32gui
    import win32con
    import winsound
    WINDOWS = True
except ImportError:
    WINDOWS = False

class AlertSystem:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main window
        self.alert_queue = queue.Queue()
        
    def process_alerts(self):
        """Process any pending alerts"""
        try:
            while True:
                alert = self.alert_queue.get_nowait()
                self.show_popup(alert)
        except queue.Empty:
            pass
        finally:
            # Schedule next check
            self.root.after(100, self.process_alerts)
        
    def show_popup(self, alert):
        """Show a popup notification for a threat"""
        severity = alert['severity']
        
        # Set icon and color based on severity
        if severity == "HIGH":
            icon = "❌"  # Red X
            bg_color = "#ff4444"  # Red
            sound = True
        elif severity == "MEDIUM":
            icon = "⚠️"  # Warning
            bg_color = "#ffbb33"  # Orange
            sound = True
        else:
            icon = "ℹ️"  # Info
            bg_color = "#33b5e5"  # Blue
            sound = False
            
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title("Threat Detection Alert")
        
        # Make window appear on top
        popup.lift()
        popup.attributes('-topmost', True)
        
        # Position in bottom right corner
        screen_width = popup.winfo_screenwidth()
        screen_height = popup.winfo_screenheight()
        popup.geometry(f"400x200+{screen_width-420}+{screen_height-250}")
        
        # Style
        popup.configure(bg=bg_color)
        
        # Header
        header = tk.Label(
            popup,
            text=f"{icon} {severity} THREAT DETECTED",
            font=("Arial", 12, "bold"),
            bg=bg_color,
            fg="white"
        )
        header.pack(pady=10)
        
        # Details
        if 'ip_address' in alert:
            target = alert['ip_address']
            target_type = "IP"
        else:
            target = alert['domain']
            target_type = "Domain"
            
        details = tk.Label(
            popup,
            text=f"Target {target_type}: {target}\n" +
                 f"Threat Score: {alert['threat_score']:.3f}\n" +
                 f"Action: {alert['recommended_action']}\n" +
                 f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            font=("Arial", 10),
            bg=bg_color,
            fg="white",
            justify=tk.LEFT,
            wraplength=380
        )
        details.pack(pady=10)
        
        # Close button
        close_btn = tk.Button(
            popup,
            text="Acknowledge",
            command=popup.destroy,
            bg="white",
            fg="black"
        )
        close_btn.pack(pady=10)
        
        # Play sound for high/medium threats
        if sound and WINDOWS:
            try:
                winsound.MessageBeep(winsound.MB_ICONWARNING)
            except:
                pass  # Ignore sound errors
        
        # Auto-close after 10 seconds
        popup.after(10000, popup.destroy)
        
    def show_alert(self, alert):
        """Queue an alert to be shown"""
        self.alert_queue.put(alert) 