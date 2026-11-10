#!/usr/bin/env python3
"""
Real-Time Protection Tab for AI Antivirus GUI
Provides controls and monitoring for real-time protection
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QPushButton, QLabel, QTextEdit, QCheckBox, 
                            QSlider, QSpinBox, QProgressBar, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap, QIcon
import logging

class ProtectionTab(QWidget):
    """Real-time protection control and monitoring tab"""
    
    protection_toggled = pyqtSignal(bool)
    settings_changed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.protection_tab')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.protection_active = False
        
        self.init_ui()
        self.init_timer()
    
    def init_ui(self):
        """Initialize the protection tab UI"""
        layout = QVBoxLayout(self)
        
        # Protection status section
        status_group = self.create_status_section()
        layout.addWidget(status_group)
        
        # Protection controls section
        controls_group = self.create_controls_section()
        layout.addWidget(controls_group)
        
        # Settings section
        settings_group = self.create_settings_section()
        layout.addWidget(settings_group)
        
        # Activity monitoring section
        activity_group = self.create_activity_section()
        layout.addWidget(activity_group)
        
        layout.addStretch()
    
    def create_status_section(self):
        """Create protection status section"""
        group = QGroupBox("🛡️ Real-Time Protection Status")
        layout = QVBoxLayout(group)
        
        # Main status display
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("🛑 Protection: STOPPED")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        # Protection toggle button
        self.toggle_btn = QPushButton("Start Protection")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        self.toggle_btn.clicked.connect(self.toggle_protection)
        status_layout.addWidget(self.toggle_btn)
        
        layout.addLayout(status_layout)
        
        # Statistics display
        stats_layout = QHBoxLayout()
        
        self.files_scanned_label = QLabel("📁 Files Scanned: 0")
        self.threats_detected_label = QLabel("⚠️ Threats Detected: 0")
        self.threats_blocked_label = QLabel("🛡️ Threats Blocked: 0")
        self.uptime_label = QLabel("⏱️ Uptime: 00:00:00")
        
        for label in [self.files_scanned_label, self.threats_detected_label, 
                     self.threats_blocked_label, self.uptime_label]:
            label.setStyleSheet("font-size: 12px; margin: 5px;")
            stats_layout.addWidget(label)
        
        layout.addLayout(stats_layout)
        
        return group
    
    def create_controls_section(self):
        """Create protection controls section"""
        group = QGroupBox("🎛️ Protection Controls")
        layout = QHBoxLayout(group)
        
        # Pause/Resume button
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_protection)
        layout.addWidget(self.pause_btn)
        
        # Scan queue status
        self.queue_label = QLabel("Queue: 0 files")
        layout.addWidget(self.queue_label)
        
        layout.addStretch()
        
        # Quick actions
        self.quarantine_btn = QPushButton("📦 View Quarantine")
        self.quarantine_btn.clicked.connect(self.view_quarantine)
        layout.addWidget(self.quarantine_btn)
        
        self.logs_btn = QPushButton("📋 View Logs")
        self.logs_btn.clicked.connect(self.view_logs)
        layout.addWidget(self.logs_btn)
        
        return group
    
    def create_settings_section(self):
        """Create protection settings section"""
        group = QGroupBox("⚙️ Protection Settings")
        layout = QVBoxLayout(group)
        
        # Auto-quarantine setting
        self.auto_quarantine_cb = QCheckBox("Automatically quarantine detected threats")
        self.auto_quarantine_cb.setChecked(True)
        self.auto_quarantine_cb.stateChanged.connect(self.on_settings_changed)
        layout.addWidget(self.auto_quarantine_cb)
        
        # Scan archives setting
        self.scan_archives_cb = QCheckBox("Scan archive files (ZIP, RAR, etc.)")
        self.scan_archives_cb.setChecked(True)
        self.scan_archives_cb.stateChanged.connect(self.on_settings_changed)
        layout.addWidget(self.scan_archives_cb)
        
        # Threat threshold setting
        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("Threat Detection Threshold:"))
        
        self.threshold_slider = QSlider(Qt.Horizontal)
        self.threshold_slider.setRange(30, 95)
        self.threshold_slider.setValue(70)
        self.threshold_slider.valueChanged.connect(self.on_threshold_changed)
        threshold_layout.addWidget(self.threshold_slider)
        
        self.threshold_label = QLabel("0.70")
        threshold_layout.addWidget(self.threshold_label)
        
        layout.addLayout(threshold_layout)
        
        return group
    
    def create_activity_section(self):
        """Create activity monitoring section"""
        group = QGroupBox("📊 Recent Activity")
        layout = QVBoxLayout(group)
        
        # Activity table
        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(4)
        self.activity_table.setHorizontalHeaderLabels(["Time", "File", "Action", "Score"])
        
        # Set column widths
        header = self.activity_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        self.activity_table.setMaximumHeight(200)
        layout.addWidget(self.activity_table)
        
        # Clear activity button
        clear_btn = QPushButton("🗑️ Clear Activity")
        clear_btn.clicked.connect(self.clear_activity)
        layout.addWidget(clear_btn)
        
        return group
    
    def init_timer(self):
        """Initialize update timer"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
    
    def toggle_protection(self):
        """Toggle real-time protection on/off"""
        try:
            if not self.protection_active:
                # Start protection
                if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
                    success = self.parent.real_time_protection.start_protection()
                    if success:
                        self.protection_active = True
                        self.update_ui_for_active_protection()
                        self.logger.info("Real-time protection started")
                    else:
                        self.logger.error("Failed to start real-time protection")
                else:
                    self.logger.error("Real-time protection engine not available")
            else:
                # Stop protection
                if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
                    success = self.parent.real_time_protection.stop_protection()
                    if success:
                        self.protection_active = False
                        self.update_ui_for_stopped_protection()
                        self.logger.info("Real-time protection stopped")
                    else:
                        self.logger.error("Failed to stop real-time protection")
        
        except Exception as e:
            self.logger.error(f"Error toggling protection: {e}")
    
    def pause_protection(self):
        """Pause/resume real-time protection"""
        try:
            if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
                if self.parent.real_time_protection.is_paused:
                    self.parent.real_time_protection.resume_protection()
                    self.pause_btn.setText("⏸️ Pause")
                    self.logger.info("Real-time protection resumed")
                else:
                    self.parent.real_time_protection.pause_protection()
                    self.pause_btn.setText("▶️ Resume")
                    self.logger.info("Real-time protection paused")
        
        except Exception as e:
            self.logger.error(f"Error pausing/resuming protection: {e}")
    
    def update_ui_for_active_protection(self):
        """Update UI when protection is active"""
        self.status_label.setText("🛡️ Protection: ACTIVE")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: green;")
        
        self.toggle_btn.setText("Stop Protection")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
            QPushButton:pressed {
                background-color: #c1160a;
            }
        """)
        
        self.pause_btn.setEnabled(True)
    
    def update_ui_for_stopped_protection(self):
        """Update UI when protection is stopped"""
        self.status_label.setText("🛑 Protection: STOPPED")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        
        self.toggle_btn.setText("Start Protection")
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        
        self.pause_btn.setEnabled(False)
        self.pause_btn.setText("⏸️ Pause")
    
    def update_status(self):
        """Update protection status display"""
        try:
            if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
                status = self.parent.real_time_protection.get_protection_status()
                
                # Update statistics
                stats = status.get('stats', {})
                self.files_scanned_label.setText(f"📁 Files Scanned: {stats.get('files_scanned', 0)}")
                self.threats_detected_label.setText(f"⚠️ Threats Detected: {stats.get('threats_detected', 0)}")
                self.threats_blocked_label.setText(f"🛡️ Threats Blocked: {stats.get('threats_blocked', 0)}")
                
                # Update queue size
                queue_size = status.get('queue_size', 0)
                self.queue_label.setText(f"Queue: {queue_size} files")
                
                # Update uptime
                if status.get('is_active') and stats.get('start_time'):
                    from datetime import datetime
                    start_time = datetime.fromisoformat(stats['start_time'].replace('Z', '+00:00'))
                    uptime = datetime.now() - start_time.replace(tzinfo=None)
                    uptime_str = str(uptime).split('.')[0]  # Remove microseconds
                    self.uptime_label.setText(f"⏱️ Uptime: {uptime_str}")
                else:
                    self.uptime_label.setText("⏱️ Uptime: 00:00:00")
        
        except Exception as e:
            self.logger.error(f"Error updating status: {e}")
    
    def on_settings_changed(self):
        """Handle settings changes"""
        settings = {
            'auto_quarantine': self.auto_quarantine_cb.isChecked(),
            'scan_archives': self.scan_archives_cb.isChecked(),
            'threat_threshold': self.threshold_slider.value() / 100.0
        }
        
        # Update protection engine settings
        if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
            self.parent.real_time_protection.update_settings(settings)
        
        self.settings_changed.emit(settings)
    
    def on_threshold_changed(self, value):
        """Handle threshold slider changes"""
        threshold = value / 100.0
        self.threshold_label.setText(f"{threshold:.2f}")
        self.on_settings_changed()
    
    def add_activity(self, timestamp, file_path, action, score):
        """Add activity to the monitoring table"""
        try:
            row = self.activity_table.rowCount()
            self.activity_table.insertRow(row)
            
            # Add items to table
            self.activity_table.setItem(row, 0, QTableWidgetItem(timestamp))
            self.activity_table.setItem(row, 1, QTableWidgetItem(os.path.basename(file_path)))
            self.activity_table.setItem(row, 2, QTableWidgetItem(action))
            self.activity_table.setItem(row, 3, QTableWidgetItem(f"{score:.2f}"))
            
            # Limit table size
            if self.activity_table.rowCount() > 100:
                self.activity_table.removeRow(0)
            
            # Scroll to bottom
            self.activity_table.scrollToBottom()
        
        except Exception as e:
            self.logger.error(f"Error adding activity: {e}")
    
    def clear_activity(self):
        """Clear activity table"""
        self.activity_table.setRowCount(0)
    
    def view_quarantine(self):
        """Open quarantine management"""
        # Switch to quarantine tab if available
        if hasattr(self.parent, 'tab_widget'):
            for i in range(self.parent.tab_widget.count()):
                if 'quarantine' in self.parent.tab_widget.tabText(i).lower():
                    self.parent.tab_widget.setCurrentIndex(i)
                    break
    
    def view_logs(self):
        """Open protection logs"""
        # Switch to logs tab if available
        if hasattr(self.parent, 'tab_widget'):
            for i in range(self.parent.tab_widget.count()):
                if 'log' in self.parent.tab_widget.tabText(i).lower():
                    self.parent.tab_widget.setCurrentIndex(i)
                    break
    
    def handle_threat_detection(self, threat_data):
        """Handle threat detection for activity display"""
        try:
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            file_path = threat_data.get('file_path', 'Unknown')
            threat_type = threat_data.get('type', 'unknown')
            score = threat_data.get('threat_score', 0.0)
            
            if threat_type == 'threat_detected':
                action = "🚨 Threat Detected"
            elif threat_type == 'threat_quarantined':
                action = "🛡️ Quarantined"
            elif threat_type == 'suspicious_file':
                action = "⚠️ Suspicious"
            else:
                action = "ℹ️ Scanned"
            
            self.add_activity(timestamp, file_path, action, score)
        
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
