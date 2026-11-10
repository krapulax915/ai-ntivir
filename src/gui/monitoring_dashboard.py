#!/usr/bin/env python3
"""
Minimal Monitoring Dashboard - optimized for performance
"""

from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout

class MonitoringDashboard(QWidget):
    def __init__(self, parent=None, monitoring_system=None):
        super().__init__(parent)
        self.monitoring_system = monitoring_system
        self.setLayout(QVBoxLayout())
        self.layout().addWidget(QLabel("Monitoring Dashboard - Optimized for performance"))
        
    def update_display(self):
        pass
        
    def refresh_data(self):
        pass
