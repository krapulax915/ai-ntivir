#!/usr/bin/env python3
"""
Updates Management Tab for AI Antivirus GUI
Provides controls and monitoring for automatic updates
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QPushButton, QLabel, QTextEdit, QCheckBox, 
                            QSlider, QSpinBox, QProgressBar, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSplitter,
                            QComboBox, QDateTimeEdit, QMessageBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QDateTime, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QPixmap, QIcon
import logging
from datetime import datetime, timedelta

class UpdateWorker(QThread):
    """Worker thread for performing updates"""
    
    update_progress = pyqtSignal(str, int)  # message, progress
    update_completed = pyqtSignal(dict)     # result
    
    def __init__(self, updater, update_type):
        super().__init__()
        self.updater = updater
        self.update_type = update_type
    
    def run(self):
        """Run the update process"""
        try:
            if self.update_type == 'virus_definitions':
                self.update_progress.emit("Updating virus definitions...", 25)
                result = self.updater.update_virus_definitions()
            elif self.update_type == 'ai_models':
                self.update_progress.emit("Updating AI models...", 25)
                result = self.updater.update_ai_models()
            elif self.update_type == 'application':
                self.update_progress.emit("Checking application updates...", 25)
                result = self.updater.check_application_updates()
            elif self.update_type == 'all':
                self.update_progress.emit("Checking all updates...", 10)
                self.updater.check_all_updates()
                result = {'success': True, 'message': 'All updates checked'}
            else:
                result = {'success': False, 'error': 'Unknown update type'}
            
            self.update_progress.emit("Update completed", 100)
            self.update_completed.emit(result)
            
        except Exception as e:
            self.update_completed.emit({'success': False, 'error': str(e)})

class UpdatesTab(QWidget):
    """Updates management and monitoring tab"""
    
    update_requested = pyqtSignal(str)  # update_type
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.updates_tab')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.updater = None
        self.update_worker = None
        
        self.init_ui()
        self.init_timer()
    
    def init_ui(self):
        """Initialize the updates tab UI"""
        layout = QVBoxLayout(self)
        
        # Update status section
        status_group = self.create_status_section()
        layout.addWidget(status_group)
        
        # Update controls section
        controls_group = self.create_controls_section()
        layout.addWidget(controls_group)
        
        # Update settings section
        settings_group = self.create_settings_section()
        layout.addWidget(settings_group)
        
        # Update history section
        history_group = self.create_history_section()
        layout.addWidget(history_group)
        
        layout.addStretch()
    
    def create_status_section(self):
        """Create update status section"""
        group = QGroupBox("🔄 Update Status")
        layout = QVBoxLayout(group)
        
        # Current status display
        status_layout = QHBoxLayout()
        
        self.auto_update_status = QLabel("🔄 Auto-updates: ENABLED")
        self.auto_update_status.setStyleSheet("font-size: 14px; font-weight: bold; color: green;")
        status_layout.addWidget(self.auto_update_status)
        
        status_layout.addStretch()
        
        # Last update times
        times_layout = QVBoxLayout()
        
        self.virus_update_label = QLabel("🦠 Virus Definitions: Never updated")
        self.ai_update_label = QLabel("🤖 AI Models: Never updated")
        self.app_update_label = QLabel("📱 Application: Never updated")
        
        for label in [self.virus_update_label, self.ai_update_label, self.app_update_label]:
            label.setStyleSheet("font-size: 12px; margin: 2px;")
            times_layout.addWidget(label)
        
        status_layout.addLayout(times_layout)
        layout.addLayout(status_layout)
        
        # Progress bar for updates
        self.update_progress = QProgressBar()
        self.update_progress.setVisible(False)
        layout.addWidget(self.update_progress)
        
        self.progress_label = QLabel("")
        self.progress_label.setVisible(False)
        layout.addWidget(self.progress_label)
        
        return group
    
    def create_controls_section(self):
        """Create update controls section"""
        group = QGroupBox("🎛️ Update Controls")
        layout = QVBoxLayout(group)
        
        # Manual update buttons
        buttons_layout = QHBoxLayout()
        
        self.virus_update_btn = QPushButton("🦠 Update Virus Definitions")
        self.virus_update_btn.clicked.connect(lambda: self.start_update('virus_definitions'))
        buttons_layout.addWidget(self.virus_update_btn)
        
        self.ai_update_btn = QPushButton("🤖 Update AI Models")
        self.ai_update_btn.clicked.connect(lambda: self.start_update('ai_models'))
        buttons_layout.addWidget(self.ai_update_btn)
        
        self.app_update_btn = QPushButton("📱 Check App Updates")
        self.app_update_btn.clicked.connect(lambda: self.start_update('application'))
        buttons_layout.addWidget(self.app_update_btn)
        
        layout.addLayout(buttons_layout)
        
        # Check all updates button
        check_all_layout = QHBoxLayout()
        
        self.check_all_btn = QPushButton("🔄 Check All Updates")
        self.check_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #1565C0;
            }
        """)
        self.check_all_btn.clicked.connect(lambda: self.start_update('all'))
        check_all_layout.addWidget(self.check_all_btn)
        
        check_all_layout.addStretch()
        
        # Auto-update toggle
        self.auto_update_cb = QCheckBox("Enable automatic updates")
        self.auto_update_cb.setChecked(True)
        self.auto_update_cb.stateChanged.connect(self.toggle_auto_updates)
        check_all_layout.addWidget(self.auto_update_cb)
        
        layout.addLayout(check_all_layout)
        
        return group
    
    def create_settings_section(self):
        """Create update settings section"""
        group = QGroupBox("⚙️ Update Settings")
        layout = QVBoxLayout(group)
        
        # Update intervals
        intervals_layout = QHBoxLayout()
        
        # Virus definition interval
        virus_layout = QVBoxLayout()
        virus_layout.addWidget(QLabel("Virus Definitions Interval:"))
        self.virus_interval_combo = QComboBox()
        self.virus_interval_combo.addItems(["30 minutes", "1 hour", "2 hours", "6 hours", "12 hours"])
        self.virus_interval_combo.setCurrentText("1 hour")
        self.virus_interval_combo.currentTextChanged.connect(self.on_settings_changed)
        virus_layout.addWidget(self.virus_interval_combo)
        intervals_layout.addLayout(virus_layout)
        
        # AI model interval
        ai_layout = QVBoxLayout()
        ai_layout.addWidget(QLabel("AI Models Interval:"))
        self.ai_interval_combo = QComboBox()
        self.ai_interval_combo.addItems(["6 hours", "12 hours", "24 hours", "48 hours", "Weekly"])
        self.ai_interval_combo.setCurrentText("24 hours")
        self.ai_interval_combo.currentTextChanged.connect(self.on_settings_changed)
        ai_layout.addWidget(self.ai_interval_combo)
        intervals_layout.addLayout(ai_layout)
        
        # Application interval
        app_layout = QVBoxLayout()
        app_layout.addWidget(QLabel("Application Interval:"))
        self.app_interval_combo = QComboBox()
        self.app_interval_combo.addItems(["12 hours", "24 hours", "48 hours", "Weekly", "Monthly"])
        self.app_interval_combo.setCurrentText("24 hours")
        self.app_interval_combo.currentTextChanged.connect(self.on_settings_changed)
        app_layout.addWidget(self.app_interval_combo)
        intervals_layout.addLayout(app_layout)
        
        layout.addLayout(intervals_layout)
        
        # Additional settings
        additional_layout = QHBoxLayout()
        
        self.backup_before_update_cb = QCheckBox("Create backup before updates")
        self.backup_before_update_cb.setChecked(True)
        self.backup_before_update_cb.stateChanged.connect(self.on_settings_changed)
        additional_layout.addWidget(self.backup_before_update_cb)
        
        self.update_on_startup_cb = QCheckBox("Check updates on startup")
        self.update_on_startup_cb.setChecked(True)
        self.update_on_startup_cb.stateChanged.connect(self.on_settings_changed)
        additional_layout.addWidget(self.update_on_startup_cb)
        
        layout.addLayout(additional_layout)
        
        return group
    
    def create_history_section(self):
        """Create update history section"""
        group = QGroupBox("📊 Update History")
        layout = QVBoxLayout(group)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["Time", "Type", "Status", "Details", "Version"])
        
        # Set column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        self.history_table.setMaximumHeight(200)
        layout.addWidget(self.history_table)
        
        # History controls
        history_controls = QHBoxLayout()
        
        self.refresh_history_btn = QPushButton("🔄 Refresh")
        self.refresh_history_btn.clicked.connect(self.refresh_update_history)
        history_controls.addWidget(self.refresh_history_btn)
        
        self.clear_history_btn = QPushButton("🗑️ Clear History")
        self.clear_history_btn.clicked.connect(self.clear_update_history)
        history_controls.addWidget(self.clear_history_btn)
        
        history_controls.addStretch()
        
        layout.addLayout(history_controls)
        
        return group
    
    def init_timer(self):
        """Initialize update timer"""
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status_display)
        self.status_timer.start(5000)  # Update every 5 seconds
    
    def set_updater(self, updater):
        """Set the auto updater instance"""
        self.updater = updater
        
        # Connect updater callbacks
        if self.updater:
            self.updater.add_virus_update_callback(self.on_virus_update)
            self.updater.add_ai_update_callback(self.on_ai_update)
            self.updater.add_app_update_callback(self.on_app_update)
            
            # Load initial status
            self.update_status_display()
            self.refresh_update_history()
    
    def start_update(self, update_type):
        """Start manual update process"""
        try:
            if not self.updater:
                QMessageBox.warning(self, "Error", "Update system not available")
                return
            
            if self.update_worker and self.update_worker.isRunning():
                QMessageBox.information(self, "Update in Progress", "An update is already running")
                return
            
            # Disable buttons during update
            self.set_update_buttons_enabled(False)
            
            # Show progress
            self.update_progress.setVisible(True)
            self.progress_label.setVisible(True)
            self.update_progress.setValue(0)
            
            # Start update worker
            self.update_worker = UpdateWorker(self.updater, update_type)
            self.update_worker.update_progress.connect(self.on_update_progress)
            self.update_worker.update_completed.connect(self.on_update_completed)
            self.update_worker.start()
            
            self.logger.info(f"Started manual update: {update_type}")
            
        except Exception as e:
            self.logger.error(f"Error starting update: {e}")
            QMessageBox.critical(self, "Update Error", f"Failed to start update: {e}")
            self.set_update_buttons_enabled(True)
    
    def set_update_buttons_enabled(self, enabled):
        """Enable/disable update buttons"""
        self.virus_update_btn.setEnabled(enabled)
        self.ai_update_btn.setEnabled(enabled)
        self.app_update_btn.setEnabled(enabled)
        self.check_all_btn.setEnabled(enabled)
    
    @pyqtSlot(str, int)
    def on_update_progress(self, message, progress):
        """Handle update progress"""
        self.progress_label.setText(message)
        self.update_progress.setValue(progress)
    
    @pyqtSlot(dict)
    def on_update_completed(self, result):
        """Handle update completion"""
        try:
            # Hide progress
            self.update_progress.setVisible(False)
            self.progress_label.setVisible(False)
            
            # Re-enable buttons
            self.set_update_buttons_enabled(True)
            
            # Show result
            if result.get('success', False):
                message = result.get('message', 'Update completed successfully')
                QMessageBox.information(self, "Update Successful", message)
            else:
                error = result.get('error', 'Unknown error')
                QMessageBox.warning(self, "Update Failed", f"Update failed: {error}")
            
            # Refresh displays
            self.update_status_display()
            self.refresh_update_history()
            
        except Exception as e:
            self.logger.error(f"Error handling update completion: {e}")
    
    def toggle_auto_updates(self, state):
        """Toggle automatic updates"""
        try:
            enabled = state == Qt.Checked
            
            if self.updater:
                self.updater.auto_update_enabled = enabled
            
            if enabled:
                self.auto_update_status.setText("🔄 Auto-updates: ENABLED")
                self.auto_update_status.setStyleSheet("font-size: 14px; font-weight: bold; color: green;")
            else:
                self.auto_update_status.setText("⏸️ Auto-updates: DISABLED")
                self.auto_update_status.setStyleSheet("font-size: 14px; font-weight: bold; color: red;")
            
            self.logger.info(f"Auto-updates {'enabled' if enabled else 'disabled'}")
            
        except Exception as e:
            self.logger.error(f"Error toggling auto-updates: {e}")
    
    def on_settings_changed(self):
        """Handle settings changes"""
        try:
            if not self.updater:
                return
            
            # Update intervals
            virus_interval = self.parse_interval(self.virus_interval_combo.currentText())
            ai_interval = self.parse_interval(self.ai_interval_combo.currentText())
            app_interval = self.parse_interval(self.app_interval_combo.currentText())
            
            self.updater.virus_definition_interval = virus_interval
            self.updater.ai_model_interval = ai_interval
            self.updater.application_interval = app_interval
            
            # Update other settings
            self.updater.backup_before_update = self.backup_before_update_cb.isChecked()
            self.updater.update_on_startup = self.update_on_startup_cb.isChecked()
            
            self.logger.info("Update settings changed")
            
        except Exception as e:
            self.logger.error(f"Error updating settings: {e}")
    
    def parse_interval(self, interval_text):
        """Parse interval text to seconds"""
        interval_map = {
            "30 minutes": 1800,
            "1 hour": 3600,
            "2 hours": 7200,
            "6 hours": 21600,
            "12 hours": 43200,
            "24 hours": 86400,
            "48 hours": 172800,
            "Weekly": 604800,
            "Monthly": 2592000
        }
        return interval_map.get(interval_text, 3600)
    
    def update_status_display(self):
        """Update status display"""
        try:
            if not self.updater:
                return
            
            status = self.updater.get_update_status()
            
            # Update last update times
            if status.get('last_virus_update'):
                virus_time = datetime.fromisoformat(status['last_virus_update'])
                self.virus_update_label.setText(f"🦠 Virus Definitions: {virus_time.strftime('%Y-%m-%d %H:%M')}")
            else:
                self.virus_update_label.setText("🦠 Virus Definitions: Never updated")
            
            if status.get('last_ai_update'):
                ai_time = datetime.fromisoformat(status['last_ai_update'])
                self.ai_update_label.setText(f"🤖 AI Models: {ai_time.strftime('%Y-%m-%d %H:%M')}")
            else:
                self.ai_update_label.setText("🤖 AI Models: Never updated")
            
            if status.get('last_app_update'):
                app_time = datetime.fromisoformat(status['last_app_update'])
                self.app_update_label.setText(f"📱 Application: {app_time.strftime('%Y-%m-%d %H:%M')}")
            else:
                self.app_update_label.setText("📱 Application: Never updated")
            
        except Exception as e:
            self.logger.error(f"Error updating status display: {e}")
    
    def refresh_update_history(self):
        """Refresh update history table"""
        try:
            if not self.updater:
                return
            
            history = self.updater.get_update_history(50)
            
            self.history_table.setRowCount(len(history))
            
            for row, entry in enumerate(history):
                # Format timestamp
                timestamp = entry.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        timestamp = dt.strftime('%m-%d %H:%M')
                    except:
                        pass
                
                # Set table items
                self.history_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.history_table.setItem(row, 1, QTableWidgetItem(entry.get('update_type', '')))
                
                # Color-code status
                status_item = QTableWidgetItem(entry.get('status', ''))
                if entry.get('status') == 'success':
                    status_item.setBackground(Qt.green)
                elif entry.get('status') == 'failed':
                    status_item.setBackground(Qt.red)
                elif entry.get('status') == 'attempting':
                    status_item.setBackground(Qt.yellow)
                
                self.history_table.setItem(row, 2, status_item)
                self.history_table.setItem(row, 3, QTableWidgetItem(entry.get('details', '')))
                self.history_table.setItem(row, 4, QTableWidgetItem(entry.get('version', '')))
            
        except Exception as e:
            self.logger.error(f"Error refreshing update history: {e}")
    
    def clear_update_history(self):
        """Clear update history"""
        try:
            reply = QMessageBox.question(
                self, 'Clear History', 
                'Are you sure you want to clear the update history?',
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if self.updater and hasattr(self.updater, 'conn'):
                    cursor = self.updater.conn.cursor()
                    cursor.execute("DELETE FROM update_history")
                    self.updater.conn.commit()
                
                self.refresh_update_history()
                self.logger.info("Update history cleared")
            
        except Exception as e:
            self.logger.error(f"Error clearing update history: {e}")
            QMessageBox.critical(self, "Error", f"Failed to clear history: {e}")
    
    def on_virus_update(self, update_data):
        """Handle virus definition update callback"""
        try:
            if update_data.get('status') == 'success':
                signatures = update_data.get('signatures_added', 0)
                if hasattr(self.parent, 'system_tray') and self.parent.system_tray:
                    self.parent.system_tray.show_custom_notification(
                        "Virus Definitions Updated",
                        f"Added {signatures} new virus signatures",
                        "success"
                    )
            
        except Exception as e:
            self.logger.error(f"Error handling virus update callback: {e}")
    
    def on_ai_update(self, update_data):
        """Handle AI model update callback"""
        try:
            if update_data.get('status') == 'success':
                models = update_data.get('models_updated', 0)
                if hasattr(self.parent, 'system_tray') and self.parent.system_tray:
                    self.parent.system_tray.show_custom_notification(
                        "AI Models Updated",
                        f"Updated {models} AI models",
                        "success"
                    )
            
        except Exception as e:
            self.logger.error(f"Error handling AI update callback: {e}")
    
    def on_app_update(self, update_data):
        """Handle application update callback"""
        try:
            if update_data.get('status') == 'available':
                version = update_data.get('latest_version', 'Unknown')
                if hasattr(self.parent, 'system_tray') and self.parent.system_tray:
                    self.parent.system_tray.show_custom_notification(
                        "Application Update Available",
                        f"Version {version} is available for download",
                        "info"
                    )
            
        except Exception as e:
            self.logger.error(f"Error handling app update callback: {e}")
