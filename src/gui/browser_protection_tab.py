#!/usr/bin/env python3
"""
Browser Protection Tab for AI Antivirus GUI
==========================================

Provides browser protection management interface including:
- Real-time protection status
- Blocked sites management
- Phishing protection settings
- Download scanning configuration
"""

import sys
import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QTableWidget, QTableWidgetItem,
                           QCheckBox, QGroupBox, QTextEdit, QLineEdit,
                           QMessageBox, QProgressBar, QTabWidget,
                           QHeaderView, QFrame, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor
import logging

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from protection.browser_protection import BrowserProtection
    from ..config.config_manager import ConfigManager
except ImportError as e:
    print(f"Import error in browser protection tab: {e}")
    BrowserProtection = None
    ConfigManager = None

class BrowserProtectionTab(QWidget):
    """Browser Protection management tab"""
    
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.browser_protection_tab')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.browser_protection = None
        self.config_manager = None
        self.update_timer = QTimer()
        
        self.init_ui()
        self.init_browser_protection()
        self.setup_timer()
        # Initial status update
        self.update_display()
        # Initial status update
        self.update_display()
        
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Browser Protection")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Main splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Controls
        left_panel = self.create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Statistics and logs
        right_panel = self.create_info_panel()
        splitter.addWidget(right_panel)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        self.setLayout(layout)
        
    def create_control_panel(self):
        """Create the control panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Protection Status
        status_group = QGroupBox("Protection Status")
        status_layout = QVBoxLayout()
        
        self.protection_status = QLabel("🔴 Disabled")
        self.protection_status.setFont(QFont("Arial", 12, QFont.Bold))
        status_layout.addWidget(self.protection_status)
        
        self.toggle_protection_btn = QPushButton("Enable Protection")
        self.toggle_protection_btn.clicked.connect(self.toggle_protection)
        status_layout.addWidget(self.toggle_protection_btn)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Protection Settings
        settings_group = QGroupBox("Protection Settings")
        settings_layout = QVBoxLayout()
        
        self.malicious_blocking_cb = QCheckBox("Block Malicious Sites")
        self.malicious_blocking_cb.setChecked(True)
        self.malicious_blocking_cb.stateChanged.connect(self.update_settings)
        settings_layout.addWidget(self.malicious_blocking_cb)
        
        self.phishing_protection_cb = QCheckBox("Phishing Protection")
        self.phishing_protection_cb.setChecked(True)
        self.phishing_protection_cb.stateChanged.connect(self.update_settings)
        settings_layout.addWidget(self.phishing_protection_cb)
        
        self.download_scanning_cb = QCheckBox("Scan Downloads")
        self.download_scanning_cb.setChecked(True)
        self.download_scanning_cb.stateChanged.connect(self.update_settings)
        settings_layout.addWidget(self.download_scanning_cb)
        
        self.real_time_monitoring_cb = QCheckBox("Real-time Monitoring")
        self.real_time_monitoring_cb.setChecked(True)
        self.real_time_monitoring_cb.stateChanged.connect(self.update_settings)
        settings_layout.addWidget(self.real_time_monitoring_cb)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Blocked Sites Management
        blocked_group = QGroupBox("Blocked Sites Management")
        blocked_layout = QVBoxLayout()
        
        # Add site input
        add_layout = QHBoxLayout()
        self.add_site_input = QLineEdit()
        self.add_site_input.setPlaceholderText("Enter URL to block...")
        add_layout.addWidget(self.add_site_input)
        
        self.add_site_btn = QPushButton("Block Site")
        self.add_site_btn.clicked.connect(self.add_blocked_site)
        add_layout.addWidget(self.add_site_btn)
        
        blocked_layout.addLayout(add_layout)
        
        # Blocked sites table
        self.blocked_sites_table = QTableWidget()
        self.blocked_sites_table.setColumnCount(3)
        self.blocked_sites_table.setHorizontalHeaderLabels(["URL", "Reason", "Actions"])
        self.blocked_sites_table.horizontalHeader().setStretchLastSection(True)
        blocked_layout.addWidget(self.blocked_sites_table)
        
        blocked_group.setLayout(blocked_layout)
        layout.addWidget(blocked_group)
        
        widget.setLayout(layout)
        return widget
        
    def create_info_panel(self):
        """Create the information panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Statistics
        stats_group = QGroupBox("Protection Statistics")
        stats_layout = QVBoxLayout()
        
        self.stats_label = QLabel("Loading statistics...")
        stats_layout.addWidget(self.stats_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Activity Log
        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout()
        
        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(200)
        log_layout.addWidget(self.activity_log)
        
        # Clear log button
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_activity_log)
        log_layout.addWidget(clear_log_btn)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        widget.setLayout(layout)
        return widget
        
    def init_browser_protection(self):
        """Initialize browser protection engine"""
        try:
            if BrowserProtection:
                print("🔄 Initializing browser protection...")
                self.browser_protection = BrowserProtection()
                self.config_manager = ConfigManager()
                print("✅ Browser protection initialized")
                self.logger.info("Browser protection initialized")
            else:
                print("❌ Browser protection module not available")
                self.logger.warning("Browser protection module not available")
        except Exception as e:
            print(f"❌ Failed to initialize browser protection: {e}")
            self.logger.error(f"Failed to initialize browser protection: {e}")
            self.log_activity(f"❌ Initialization failed: {e}")
            
    def setup_timer(self):
        """Setup update timer"""
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def toggle_protection(self):
        """Toggle browser protection on/off"""
        if not self.browser_protection:
            print("❌ Browser protection not available")
            QMessageBox.warning(self, "Error", "Browser protection not available")
            return
            
        try:
            print(f"🔄 Toggling browser protection...")
            if self.browser_protection.is_monitoring():
                print("🔴 Stopping browser protection...")
                self.browser_protection.stop_monitoring()
                self.protection_status.setText("🔴 Disabled")
                self.toggle_protection_btn.setText("Enable Protection")
                self.log_activity("🔴 Browser protection disabled")
                print("✅ Browser protection disabled")
            else:
                print("🟢 Starting browser protection...")
                self.browser_protection.start_monitoring()
                self.protection_status.setText("🟢 Enabled")
                self.toggle_protection_btn.setText("Disable Protection")
                self.log_activity("🟢 Browser protection enabled")
                print("✅ Browser protection enabled")
                
        except Exception as e:
            self.logger.error(f"Failed to toggle protection: {e}")
            print(f"❌ Browser Protection Error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to toggle protection: {e}")
            
    def update_settings(self):
        """Update protection settings"""
        if not self.browser_protection:
            return
            
        try:
            settings = {
                'malicious_blocking': self.malicious_blocking_cb.isChecked(),
                'phishing_protection': self.phishing_protection_cb.isChecked(),
                'download_scanning': self.download_scanning_cb.isChecked(),
                'real_time_monitoring': self.real_time_monitoring_cb.isChecked()
            }
            
            # Update browser protection settings
            self.browser_protection.update_settings(settings)
            self.log_activity("⚙️ Protection settings updated")
            
        except Exception as e:
            self.logger.error(f"Failed to update settings: {e}")
            self.log_activity(f"❌ Settings update failed: {e}")
            
    def add_blocked_site(self):
        """Add a site to the blocked list"""
        url = self.add_site_input.text().strip()
        if not url:
            return
            
        if not self.browser_protection:
            QMessageBox.warning(self, "Error", "Browser protection not available")
            return
            
        try:
            self.browser_protection.add_blocked_domain(url, "User blocked")
            self.add_site_input.clear()
            self.update_blocked_sites_table()
            self.log_activity(f"🚫 Blocked site added: {url}")
            
        except Exception as e:
            self.logger.error(f"Failed to add blocked site: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add blocked site: {e}")
            
    def update_blocked_sites_table(self):
        """Update the blocked sites table"""
        if not self.browser_protection:
            return
            
        try:
            blocked_domains = self.browser_protection.get_blocked_domains()
            
            # Handle both list and dict formats
            if isinstance(blocked_domains, list):
                self.blocked_sites_table.setRowCount(len(blocked_domains))
                for row, domain in enumerate(blocked_domains):
                    self.blocked_sites_table.setItem(row, 0, QTableWidgetItem(str(domain)))
                    self.blocked_sites_table.setItem(row, 1, QTableWidgetItem("Blocked"))
                    
                    # Add remove button
                    remove_btn = QPushButton("Remove")
                    remove_btn.clicked.connect(lambda checked, d=domain: self.remove_blocked_site(d))
                    self.blocked_sites_table.setCellWidget(row, 2, remove_btn)
            else:
                # Handle dict format
                self.blocked_sites_table.setRowCount(len(blocked_domains))
                for row, (domain, reason) in enumerate(blocked_domains.items()):
                    self.blocked_sites_table.setItem(row, 0, QTableWidgetItem(domain))
                    self.blocked_sites_table.setItem(row, 1, QTableWidgetItem(reason))
                    
                    # Add remove button
                    remove_btn = QPushButton("Remove")
                    remove_btn.clicked.connect(lambda checked, d=domain: self.remove_blocked_site(d))
                    self.blocked_sites_table.setCellWidget(row, 2, remove_btn)
                
        except Exception as e:
            self.logger.error(f"Failed to update blocked sites table: {e}")
            
    def remove_blocked_site(self, domain):
        """Remove a site from the blocked list"""
        if not self.browser_protection:
            return
            
        try:
            self.browser_protection.remove_blocked_domain(domain)
            self.update_blocked_sites_table()
            self.log_activity(f"✅ Blocked site removed: {domain}")
            
        except Exception as e:
            self.logger.error(f"Failed to remove blocked site: {e}")
            QMessageBox.critical(self, "Error", f"Failed to remove blocked site: {e}")
            
    def update_display(self):
        """Update the display with current information"""
        if not self.browser_protection:
            return
            
        try:
            # Update protection status based on actual monitoring state
            if self.browser_protection.is_monitoring():
                self.protection_status.setText("🟢 Enabled")
                self.toggle_protection_btn.setText("Disable Protection")
            else:
                self.protection_status.setText("🔴 Disabled")
                self.toggle_protection_btn.setText("Enable Protection")
            
            # Update statistics
            stats = self.browser_protection.get_statistics()
            stats_text = f"""
Blocked Requests: {stats.get('blocked_requests', 0)}
Phishing Attempts: {stats.get('phishing_blocked', 0)}
Safe Requests: {stats.get('safe_requests', 0)}
Total Scanned: {stats.get('total_scanned', 0)}
"""
            self.stats_label.setText(stats_text)
            
            # Update blocked sites table
            self.update_blocked_sites_table()
            
        except Exception as e:
            self.logger.error(f"Failed to update display: {e}")
            
    def load_settings(self):
        """Load settings from configuration"""
        if not self.config_manager:
            return
            
        try:
            config = self.config_manager.get_config()
            browser_config = config.get('core', {}).get('browser_protection', {})
            
            self.malicious_blocking_cb.setChecked(browser_config.get('block_malicious', True))
            self.phishing_protection_cb.setChecked(browser_config.get('block_phishing', True))
            self.download_scanning_cb.setChecked(browser_config.get('scan_downloads', True))
            self.real_time_monitoring_cb.setChecked(browser_config.get('real_time_monitoring', True))
            
        except Exception as e:
            self.logger.error(f"Failed to load settings: {e}")
            
    def log_activity(self, message):
        """Add message to activity log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(f"[{timestamp}] {message}")
        
    def clear_activity_log(self):
        """Clear the activity log"""
        self.activity_log.clear()
        
    def closeEvent(self, event):
        """Handle close event"""
        if self.browser_protection and self.browser_protection.is_monitoring():
            self.browser_protection.stop_monitoring()
        event.accept()
