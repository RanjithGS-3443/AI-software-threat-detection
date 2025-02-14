import pystray
from PIL import Image
import tkinter as tk

class SystemTray:
    def __init__(self, root):
        self.root = root
        self.create_icon()
        
    def create_icon(self):
        # Create a simple icon (you can replace with your own .ico file)
        image = Image.new('RGB', (64, 64), color='red')
        
        # Create system tray icon
        self.icon = pystray.Icon(
            "Threat Detection",
            image,
            "Threat Detection System",
            menu=self.create_menu()
        )
        
    def create_menu(self):
        return pystray.Menu(
            pystray.MenuItem(
                "Exit",
                self.stop_application
            )
        )
        
    def stop_application(self):
        self.icon.stop()
        self.root.quit()
        
    def run(self):
        self.icon.run() 