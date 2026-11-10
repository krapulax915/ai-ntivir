#!/usr/bin/env python3
"""
Minimal stub for EnterpriseConsole - optimized for performance
"""

from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout

class EnterpriseConsole(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().addWidget(QLabel("Component disabled for performance optimization"))
        
    def update_display(self):
        pass
        
    def refresh_data(self):
        pass

class EnterpriseConsoleWidget(QWidget):
    """Alias for EnterpriseConsole"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().addWidget(QLabel("Enterprise Console disabled for performance optimization"))
        
    def update_display(self):
        pass
        
    def refresh_data(self):
        pass
