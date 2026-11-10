#!/usr/bin/env python3
"""
Threat Intelligence Management Tab for AI Antivirus GUI
Provides monitoring and control for threat intelligence system
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QPushButton, QLabel, QTextEdit, QCheckBox, 
                            QSlider, QSpinBox, QProgressBar, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSplitter,
                            QComboBox, QGridLayout, QFrame, QTabWidget,
                            QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
import logging
from datetime import datetime, timedelta
import json

class ThreatIntelligenceTab(QWidget):
    """Threat intelligence management and monitoring tab"""
    
    intelligence_updated = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.threat_intelligence_tab')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.intelligence_engine = None
        self.threat_classifier = None
        self.test_file_path = None
        
        self.init_ui()
        self.init_timer()
    
    def init_ui(self):
        """Initialize the threat intelligence tab UI"""
        layout = QVBoxLayout(self)
        
        # Create tab widget for different sections
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Overview tab
        overview_tab = self.create_overview_tab()
        self.tab_widget.addTab(overview_tab, "📊 Overview")
        
        # Threat feeds tab
        feeds_tab = self.create_feeds_tab()
        self.tab_widget.addTab(feeds_tab, "🌐 Threat Feeds")
        
        # Recent threats tab
        threats_tab = self.create_threats_tab()
        self.tab_widget.addTab(threats_tab, "⚠️ Recent Threats")
    
    def create_overview_tab(self):
        """Create threat intelligence overview tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Statistics section
        stats_group = QGroupBox("📈 Threat Intelligence Statistics")
        stats_layout = QGridLayout(stats_group)
        
        # Total threats
        stats_layout.addWidget(QLabel("Total Threats:"), 0, 0)
        self.total_threats_label = QLabel("0")
        self.total_threats_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #2196F3;")
        stats_layout.addWidget(self.total_threats_label, 0, 1)
        
        # Threats today
        stats_layout.addWidget(QLabel("New Today:"), 0, 2)
        self.threats_today_label = QLabel("0")
        self.threats_today_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #4CAF50;")
        stats_layout.addWidget(self.threats_today_label, 0, 3)
        
        # High severity threats
        stats_layout.addWidget(QLabel("High/Critical:"), 1, 0)
        self.high_threats_label = QLabel("0")
        self.high_threats_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #FF5722;")
        stats_layout.addWidget(self.high_threats_label, 1, 1)
        
        # Cache performance
        stats_layout.addWidget(QLabel("Cache Hit Rate:"), 1, 2)
        self.cache_hit_rate_label = QLabel("0%")
        self.cache_hit_rate_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #9C27B0;")
        stats_layout.addWidget(self.cache_hit_rate_label, 1, 3)
        
        layout.addWidget(stats_group)
        
        # Feed status section
        feeds_group = QGroupBox("🔄 Feed Status")
        feeds_layout = QVBoxLayout(feeds_group)
        
        # Feed status table
        self.feed_status_table = QTableWidget()
        self.feed_status_table.setColumnCount(4)
        self.feed_status_table.setHorizontalHeaderLabels(["Feed", "Status", "Last Update", "Records"])
        self.feed_status_table.horizontalHeader().setStretchLastSection(True)
        self.feed_status_table.setMaximumHeight(150)
        feeds_layout.addWidget(self.feed_status_table)
        
        # Manual update controls
        update_controls = QHBoxLayout()
        
        self.update_all_btn = QPushButton("🔄 Update All Feeds")
        self.update_all_btn.clicked.connect(self.update_all_feeds)
        self.update_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        update_controls.addWidget(self.update_all_btn)
        
        self.auto_update_cb = QCheckBox("Auto-update feeds")
        self.auto_update_cb.setChecked(True)
        self.auto_update_cb.stateChanged.connect(self.toggle_auto_update)
        update_controls.addWidget(self.auto_update_cb)
        
        update_controls.addStretch()
        
        # Last update info
        self.last_update_label = QLabel("Last update: Never")
        self.last_update_label.setStyleSheet("color: #666; font-size: 11px;")
        update_controls.addWidget(self.last_update_label)
        
        feeds_layout.addLayout(update_controls)
        layout.addWidget(feeds_group)
        
        # Recent activity section
        activity_group = QGroupBox("📋 Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_log = QTextEdit()
        self.activity_log.setMaximumHeight(150)
        self.activity_log.setReadOnly(True)
        self.activity_log.setFont(QFont("Consolas", 9))
        activity_layout.addWidget(self.activity_log)
        
        layout.addWidget(activity_group)
        
        return widget
    
    def create_feeds_tab(self):
        """Create threat feeds configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Feed configuration section
        config_group = QGroupBox("⚙️ Feed Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Feed list with enable/disable checkboxes
        self.feeds_table = QTableWidget()
        self.feeds_table.setColumnCount(5)
        self.feeds_table.setHorizontalHeaderLabels(["Feed", "Enabled", "URL", "Last Update", "Status"])
        self.feeds_table.horizontalHeader().setStretchLastSection(True)
        config_layout.addWidget(self.feeds_table)
        
        # Feed controls
        feed_controls = QHBoxLayout()
        
        self.test_feed_btn = QPushButton("🧪 Test Selected Feed")
        self.test_feed_btn.clicked.connect(self.test_feed)
        feed_controls.addWidget(self.test_feed_btn)
        
        feed_controls.addStretch()
        config_layout.addLayout(feed_controls)
        
        layout.addWidget(config_group)
        
        # Update settings section
        settings_group = QGroupBox("⏰ Update Settings")
        settings_layout = QGridLayout(settings_group)
        
        # Update interval
        settings_layout.addWidget(QLabel("Update Interval:"), 0, 0)
        self.update_interval_slider = QSlider(Qt.Horizontal)
        self.update_interval_slider.setRange(5, 120)  # 5 minutes to 2 hours
        self.update_interval_slider.setValue(30)  # Default 30 minutes
        self.update_interval_slider.valueChanged.connect(self.update_interval_changed)
        settings_layout.addWidget(self.update_interval_slider, 0, 1)
        self.update_interval_label = QLabel("30 minutes")
        settings_layout.addWidget(self.update_interval_label, 0, 2)
        
        # Cache settings
        settings_layout.addWidget(QLabel("Cache Size:"), 1, 0)
        self.cache_size_slider = QSlider(Qt.Horizontal)
        self.cache_size_slider.setRange(1000, 50000)
        self.cache_size_slider.setValue(10000)
        self.cache_size_slider.valueChanged.connect(self.cache_size_changed)
        settings_layout.addWidget(self.cache_size_slider, 1, 1)
        self.cache_size_label = QLabel("10,000 entries")
        settings_layout.addWidget(self.cache_size_label, 1, 2)
        
        layout.addWidget(settings_group)
        
        return widget
    
    def create_threats_tab(self):
        """Create recent threats tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Filter controls
        filter_group = QGroupBox("🔎 Threat Filters")
        filter_layout = QHBoxLayout(filter_group)
        
        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_threats)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addWidget(QLabel("Category:"))
        self.category_filter = QComboBox()
        self.category_filter.addItems(["All", "Malware", "Virus", "Trojan", "Ransomware", "Spyware", "Adware"])
        self.category_filter.currentTextChanged.connect(self.filter_threats)
        filter_layout.addWidget(self.category_filter)
        
        filter_layout.addStretch()
        
        self.refresh_threats_btn = QPushButton("🔄 Refresh")
        self.refresh_threats_btn.clicked.connect(self.refresh_threats)
        filter_layout.addWidget(self.refresh_threats_btn)
        
        layout.addWidget(filter_group)
        
        # Threats table
        threats_group = QGroupBox("⚠️ Recent Threats")
        threats_layout = QVBoxLayout(threats_group)
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(7)
        self.threats_table.setHorizontalHeaderLabels([
            "Threat Name", "Category", "Severity", "Confidence", "Source", "First Seen", "Detection Count"
        ])
        self.threats_table.horizontalHeader().setStretchLastSection(True)
        self.threats_table.setSelectionBehavior(QTableWidget.SelectRows)
        threats_layout.addWidget(self.threats_table)
        
        # Threat actions
        action_controls = QHBoxLayout()
        
        self.export_threats_btn = QPushButton("📤 Export Threats")
        self.export_threats_btn.clicked.connect(self.export_threats)
        action_controls.addWidget(self.export_threats_btn)
        
        action_controls.addStretch()
        
        # Threat count info
        self.threat_count_label = QLabel("Showing 0 threats")
        self.threat_count_label.setStyleSheet("color: #666; font-size: 11px;")
        action_controls.addWidget(self.threat_count_label)
        
        threats_layout.addLayout(action_controls)
        layout.addWidget(threats_group)
        
        return widget
    
    def init_timer(self):
        """Initialize update timer"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def set_intelligence_engine(self, intelligence_engine):
        """Set the threat intelligence engine instance"""
        self.intelligence_engine = intelligence_engine
        
        if self.intelligence_engine:
            # Connect callbacks
            self.intelligence_engine.add_update_callback(self.on_intelligence_update)
            
            # Load initial data
            self.load_initial_data()
    
    def set_threat_classifier(self, threat_classifier):
        """Set threat classifier instance"""
        self.threat_classifier = threat_classifier
        self.logger.info("Threat classifier set for intelligence tab")
    
    def set_predictive_engine(self, predictive_engine):
        """Set predictive threat engine instance"""
        self.predictive_engine = predictive_engine
        self.logger.info("Predictive engine set for intelligence tab")
    
    def set_sharing_network(self, sharing_network):
        """Set threat sharing network instance"""
        self.sharing_network = sharing_network
        self.logger.info("Sharing network set for intelligence tab")
    
    def load_initial_data(self):
        """Load initial threat intelligence data"""
        try:
            if not self.intelligence_engine:
                return
            
            # Load feed configuration
            self.load_feed_configuration()
            
            # Load recent threats
            self.refresh_threats()
            
            # Update statistics
            self.update_statistics()
            
        except Exception as e:
            self.logger.error(f"Error loading initial data: {e}")
    
    def load_feed_configuration(self):
        """Load threat feed configuration into table"""
        try:
            if not self.intelligence_engine:
                return
            
            feeds = self.intelligence_engine.threat_feeds
            self.feeds_table.setRowCount(len(feeds))
            
            row = 0
            for feed_name, feed_config in feeds.items():
                if feed_name == 'custom_feeds':
                    continue
                
                # Feed name
                self.feeds_table.setItem(row, 0, QTableWidgetItem(feed_name))
                
                # Enabled checkbox
                enabled_cb = QCheckBox()
                enabled_cb.setChecked(feed_config.get('enabled', False))
                enabled_cb.stateChanged.connect(lambda state, name=feed_name: self.toggle_feed(name, state))
                self.feeds_table.setCellWidget(row, 1, enabled_cb)
                
                # URL
                url = feed_config.get('url', 'N/A')
                self.feeds_table.setItem(row, 2, QTableWidgetItem(url))
                
                # Last update
                last_update = feed_config.get('last_update', 'Never')
                if isinstance(last_update, datetime):
                    last_update = last_update.strftime('%Y-%m-%d %H:%M:%S')
                self.feeds_table.setItem(row, 3, QTableWidgetItem(str(last_update)))
                
                # Status
                status = "Active" if feed_config.get('enabled', False) else "Disabled"
                status_item = QTableWidgetItem(status)
                if status == "Active":
                    status_item.setBackground(QColor(76, 175, 80, 50))
                else:
                    status_item.setBackground(QColor(158, 158, 158, 50))
                self.feeds_table.setItem(row, 4, status_item)
                
                row += 1
            
        except Exception as e:
            self.logger.error(f"Error loading feed configuration: {e}")
    
    def update_display(self):
        """Update display with current data"""
        try:
            self.update_statistics()
            self.update_feed_status()
            self.update_activity_log()
            
        except Exception as e:
            self.logger.error(f"Error updating display: {e}")
    
    def update_statistics(self):
        """Update threat intelligence statistics"""
        try:
            if not self.intelligence_engine:
                return
            
            stats = self.intelligence_engine.get_threat_statistics()
            
            # Update labels
            self.total_threats_label.setText(str(stats.get('total_threats', 0)))
            self.threats_today_label.setText(str(stats.get('threats_today', 0)))
            self.high_threats_label.setText(str(stats.get('high_threats', 0)))
            
            # Calculate cache hit rate
            cache_hits = stats.get('cache_hits', 0)
            cache_misses = stats.get('cache_misses', 0)
            total_queries = cache_hits + cache_misses
            
            if total_queries > 0:
                hit_rate = (cache_hits / total_queries) * 100
                self.cache_hit_rate_label.setText(f"{hit_rate:.1f}%")
            else:
                self.cache_hit_rate_label.setText("N/A")
            
            # Update last update time
            last_update = stats.get('last_update')
            if last_update:
                if isinstance(last_update, datetime):
                    last_update_str = last_update.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    last_update_str = str(last_update)
                self.last_update_label.setText(f"Last update: {last_update_str}")
            
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def update_feed_status(self):
        """Update feed status table"""
        try:
            if not self.intelligence_engine:
                return
            
            feeds = self.intelligence_engine.threat_feeds
            self.feed_status_table.setRowCount(len([f for f in feeds.keys() if f != 'custom_feeds']))
            
            row = 0
            for feed_name, feed_config in feeds.items():
                if feed_name == 'custom_feeds':
                    continue
                
                # Feed name
                self.feed_status_table.setItem(row, 0, QTableWidgetItem(feed_name))
                
                # Status
                status = "🟢 Active" if feed_config.get('enabled', False) else "🔴 Disabled"
                self.feed_status_table.setItem(row, 1, QTableWidgetItem(status))
                
                # Last update
                last_update = feed_config.get('last_update', 'Never')
                if isinstance(last_update, datetime):
                    time_diff = datetime.now() - last_update
                    if time_diff.total_seconds() < 3600:  # Less than 1 hour
                        last_update_str = f"{int(time_diff.total_seconds() // 60)} min ago"
                    else:
                        last_update_str = last_update.strftime('%H:%M')
                else:
                    last_update_str = str(last_update)
                self.feed_status_table.setItem(row, 2, QTableWidgetItem(last_update_str))
                
                # Records (placeholder)
                self.feed_status_table.setItem(row, 3, QTableWidgetItem("N/A"))
                
                row += 1
            
        except Exception as e:
            self.logger.error(f"Error updating feed status: {e}")
    
    def update_activity_log(self):
        """Update activity log"""
        try:
            # This would show recent intelligence activities
            # For now, just show current time
            current_time = datetime.now().strftime('%H:%M:%S')
            
            # Keep only last 10 lines
            text = self.activity_log.toPlainText()
            lines = text.split('\n')
            if len(lines) > 10:
                lines = lines[-9:]  # Keep last 9 lines, add 1 new
            
            lines.append(f"[{current_time}] Intelligence engine running...")
            self.activity_log.setPlainText('\n'.join(lines))
            
            # Scroll to bottom
            cursor = self.activity_log.textCursor()
            cursor.movePosition(cursor.End)
            self.activity_log.setTextCursor(cursor)
            
        except Exception as e:
            self.logger.error(f"Error updating activity log: {e}")
    
    def on_intelligence_update(self, event_type: str, data: dict):
        """Handle intelligence update callback"""
        try:
            current_time = datetime.now().strftime('%H:%M:%S')
            
            if event_type == 'feeds_updated':
                feeds_updated = data.get('feeds_updated', 0)
                message = f"[{current_time}] Updated {feeds_updated} threat feeds"
                
                # Add to activity log
                text = self.activity_log.toPlainText()
                lines = text.split('\n')
                if len(lines) > 10:
                    lines = lines[-9:]
                
                lines.append(message)
                self.activity_log.setPlainText('\n'.join(lines))
                
                # Update display
                self.update_statistics()
                self.update_feed_status()
            
        except Exception as e:
            self.logger.error(f"Error handling intelligence update: {e}")
    
    # Event handlers
    def update_all_feeds(self):
        """Manually update all threat feeds"""
        try:
            if self.intelligence_engine:
                # Disable button temporarily
                self.update_all_btn.setEnabled(False)
                self.update_all_btn.setText("🔄 Updating...")
                
                # Update feeds in background
                self.intelligence_engine.update_threat_feeds()
                
                # Re-enable button after 5 seconds
                QTimer.singleShot(5000, lambda: [
                    self.update_all_btn.setEnabled(True),
                    self.update_all_btn.setText("🔄 Update All Feeds")
                ])
            
        except Exception as e:
            self.logger.error(f"Error updating feeds: {e}")
    
    def toggle_auto_update(self, state):
        """Toggle automatic feed updates"""
        try:
            auto_update = state == Qt.Checked
            self.logger.info(f"Auto-update {'enabled' if auto_update else 'disabled'}")
            
        except Exception as e:
            self.logger.error(f"Error toggling auto-update: {e}")
    
    def toggle_feed(self, feed_name: str, state):
        """Toggle individual feed enabled/disabled"""
        try:
            if self.intelligence_engine:
                enabled = state == Qt.Checked
                self.intelligence_engine.configure_feed(feed_name, {'enabled': enabled})
                self.logger.info(f"Feed {feed_name} {'enabled' if enabled else 'disabled'}")
                
                # Update feed status
                self.update_feed_status()
            
        except Exception as e:
            self.logger.error(f"Error toggling feed {feed_name}: {e}")
    
    def update_interval_changed(self, value):
        """Handle update interval change"""
        self.update_interval_label.setText(f"{value} minutes")
        
        if self.intelligence_engine:
            self.intelligence_engine.update_interval = value * 60  # Convert to seconds
    
    def cache_size_changed(self, value):
        """Handle cache size change"""
        self.cache_size_label.setText(f"{value:,} entries")
        
        if self.intelligence_engine:
            self.intelligence_engine.cache_max_size = value
    
    def test_feed(self):
        """Test selected threat feed"""
        try:
            selected_row = self.feeds_table.currentRow()
            if selected_row >= 0:
                feed_name = self.feeds_table.item(selected_row, 0).text()
                
                # Show test message
                QMessageBox.information(self, "Feed Test", f"Testing {feed_name} feed...")
                
                # This would test the actual feed
                self.logger.info(f"Testing feed: {feed_name}")
            else:
                QMessageBox.warning(self, "No Selection", "Please select a feed to test.")
            
        except Exception as e:
            self.logger.error(f"Error testing feed: {e}")
            QMessageBox.critical(self, "Error", f"Error testing feed: {e}")
    
    def filter_threats(self):
        """Filter threats based on selected criteria"""
        try:
            # This would filter the threats table
            self.refresh_threats()
            
        except Exception as e:
            self.logger.error(f"Error filtering threats: {e}")
    
    def refresh_threats(self):
        """Refresh threats table"""
        try:
            # Placeholder - would load actual threats from database
            self.threats_table.setRowCount(0)
            self.threat_count_label.setText("Showing 0 threats")
            
        except Exception as e:
            self.logger.error(f"Error refreshing threats: {e}")
    
    def export_threats(self):
        """Export threats to file"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Threats", "threats.json", "JSON Files (*.json)"
            )
            
            if file_path:
                # This would export actual threat data
                QMessageBox.information(self, "Export", f"Threats exported to {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error exporting threats: {e}")
            QMessageBox.critical(self, "Error", f"Error exporting threats: {e}")
