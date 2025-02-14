import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import time
import sys
from main import check_threats

class ThreatDetectionService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ThreatDetectionService"
    _svc_display_name_ = "Threat Detection Service"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_alive = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_alive = False

    def SvcDoRun(self):
        try:
            while self.is_alive:
                check_threats()
                time.sleep(3600)  # Run every hour
        except Exception as e:
            servicemanager.LogErrorMsg(str(e))

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ThreatDetectionService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(ThreatDetectionService) 