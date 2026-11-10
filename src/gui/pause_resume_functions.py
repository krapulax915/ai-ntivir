"""
Pause/Resume functionality for scan operations
"""
import time
import threading
from PyQt5.QtCore import QMetaObject, Qt, Q_ARG

def toggle_scan_pause(self):
    """Toggle scan pause/resume state"""
    print(f"🔄 toggle_scan_pause called - scan_running: {getattr(self, 'scan_running', False)}, scan_paused: {getattr(self, 'scan_paused', False)}")
    
    if not getattr(self, 'scan_running', False):
        print("❌ No scan running, returning")
        return
    
    if getattr(self, 'scan_paused', False):
        # Resume scan
        self.scan_paused = False
        if hasattr(self, 'dashboard_pause_resume_btn'):
            self.dashboard_pause_resume_btn.setText("⏸️ Pause")
        QMetaObject.invokeMethod(self, "_update_scan_status_safe", 
                               Qt.QueuedConnection, Q_ARG(str, "Scan resumed"))
        self.show_notification("Scan Resumed", "Scan operation resumed")
        print("🔄 Scan resumed")
    else:
        # Pause scan
        self.scan_paused = True
        if hasattr(self, 'dashboard_pause_resume_btn'):
            self.dashboard_pause_resume_btn.setText("▶️ Resume")
        QMetaObject.invokeMethod(self, "_update_scan_status_safe", 
                               Qt.QueuedConnection, Q_ARG(str, "Scan paused"))
        self.show_notification("Scan Paused", "Scan operation paused")
        print("⏸️ Scan paused")

def check_pause_state(self):
    """Check if scan is paused and wait if needed"""
    while self.scan_paused and self.scan_running:
        time.sleep(0.1)  # Small delay while paused
    return self.scan_running  # Return False if scan was stopped while paused
