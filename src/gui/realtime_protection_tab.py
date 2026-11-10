import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class RealTimeProtectionTab(QWidget):
    """Real-time protection configuration tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        
        # Protection status
        status_group = QGroupBox("Protection Status")
        status_layout = QGridLayout(status_group)
        
        self.protection_status = QLabel("🛡️ Status: Active")
        self.protection_status.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(self.protection_status, 0, 0)
        
        self.monitored_dirs = QLabel("📁 Monitored Directories: 3")
        status_layout.addWidget(self.monitored_dirs, 0, 1)
        
        self.threats_blocked = QLabel("🚨 Threats Blocked: 0")
        status_layout.addWidget(self.threats_blocked, 1, 0)
        
        self.last_scan = QLabel("🔍 Last Activity: Just now")
        status_layout.addWidget(self.last_scan, 1, 1)
        
        layout.addWidget(status_group)
        
        # Controls
        controls_group = QGroupBox("Protection Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.enable_btn = QPushButton("Enable Protection")
        self.enable_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 10px; }")
        controls_layout.addWidget(self.enable_btn)
        
        self.disable_btn = QPushButton("Disable Protection")
        self.disable_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 10px; }")
        controls_layout.addWidget(self.disable_btn)
        
        layout.addWidget(controls_group)
        
        # Settings
        settings_group = QGroupBox("Protection Settings")
        settings_layout = QFormLayout(settings_group)
        
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setRange(1, 10)
        self.sensitivity_slider.setValue(7)
        settings_layout.addRow("Detection Sensitivity:", self.sensitivity_slider)
        
        self.auto_quarantine = QCheckBox("Automatically quarantine threats")
        self.auto_quarantine.setChecked(True)
        settings_layout.addRow(self.auto_quarantine)
        
        self.scan_downloads = QCheckBox("Scan Downloads folder")
        self.scan_downloads.setChecked(True)
        settings_layout.addRow(self.scan_downloads)
        
        layout.addWidget(settings_group)
        
        layout.addStretch()
