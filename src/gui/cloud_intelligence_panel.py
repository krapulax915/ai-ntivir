#!/usr/bin/env python3
"""
Cloud Threat Intelligence Management Panel
GUI for managing cloud threat intelligence synchronization
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget, 
    QTableWidgetItem, QPushButton, QLabel, QLineEdit, QComboBox,
    QCheckBox, QSpinBox, QTextEdit, QGroupBox, QProgressBar,
    QHeaderView, QMessageBox, QDialog, QFormLayout, QDialogButtonBox,
    QFrame, QSplitter, QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QColor, QPalette

# Import cloud threat sync system
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from intelligence.cloud_threat_sync import CloudThreatIntelligenceSync, CloudProvider

class CloudIntelligencePanel(QWidget):
    """Main cloud threat intelligence management panel"""
    
    sync_status_changed = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.cloud_intelligence_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize cloud sync system
        self.cloud_sync = None
        self.init_cloud_sync()
        
        # UI update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_displays)
        self.update_timer.start(5000)
        
        self.init_ui()
        self.load_initial_data()
        
    def init_cloud_sync(self):
        """Initialize cloud threat intelligence sync"""
        try:
            self.cloud_sync = CloudThreatIntelligenceSync(
                callback=self.on_sync_event
            )
            self.logger.info("Cloud threat intelligence sync initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize cloud sync: {e}")
    
    def init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Cloud Threat Intelligence")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_overview_tab()
        self.create_providers_tab()
        self.create_indicators_tab()
        self.create_sync_history_tab()
        
        # Control buttons
        self.create_control_buttons(layout)
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Statistics display
        self.stats_display = QTextEdit()
        self.stats_display.setMaximumHeight(200)
        self.stats_display.setReadOnly(True)
        layout.addWidget(self.stats_display)
        
        # Providers tree
        self.providers_tree = QTreeWidget()
        self.providers_tree.setHeaderLabels([
            "Provider", "Status", "Last Sync", "Indicators"
        ])
        layout.addWidget(self.providers_tree)
        
        # Activity display
        self.activity_display = QTextEdit()
        self.activity_display.setMaximumHeight(150)
        self.activity_display.setReadOnly(True)
        layout.addWidget(self.activity_display)
        
        self.tab_widget.addTab(tab, "Overview")
    
    def create_providers_tab(self):
        """Create providers management tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Providers table
        self.providers_table = QTableWidget()
        self.providers_table.setColumnCount(6)
        self.providers_table.setHorizontalHeaderLabels([
            "Provider", "Status", "API URL", "Sync Interval", 
            "Last Sync", "Indicators"
        ])
        layout.addWidget(self.providers_table)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.start_sync_btn = QPushButton("Start Sync")
        self.start_sync_btn.clicked.connect(self.start_sync)
        buttons_layout.addWidget(self.start_sync_btn)
        
        self.stop_sync_btn = QPushButton("Stop Sync")
        self.stop_sync_btn.clicked.connect(self.stop_sync)
        buttons_layout.addWidget(self.stop_sync_btn)
        
        layout.addLayout(buttons_layout)
        self.tab_widget.addTab(tab, "Providers")
    
    def create_indicators_tab(self):
        """Create threat indicators tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All", "hash", "ip", "domain", "url"])
        filter_layout.addWidget(self.type_filter)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search indicators...")
        filter_layout.addWidget(self.search_input)
        
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.load_indicators)
        filter_layout.addWidget(self.search_btn)
        
        layout.addLayout(filter_layout)
        
        # Indicators table
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(7)
        self.indicators_table.setHorizontalHeaderLabels([
            "Type", "Value", "Threat Type", "Confidence", 
            "Source", "First Seen", "Last Seen"
        ])
        layout.addWidget(self.indicators_table)
        
        self.tab_widget.addTab(tab, "Threat Indicators")
    
    def create_sync_history_tab(self):
        """Create synchronization history tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Provider", "Sync Time", "Status", "Added", "Updated", "Duration"
        ])
        layout.addWidget(self.history_table)
        
        self.tab_widget.addTab(tab, "Sync History")
    
    def create_control_buttons(self, layout):
        """Create main control buttons"""
        buttons_layout = QHBoxLayout()
        
        self.sync_status_label = QLabel("Status: Stopped")
        buttons_layout.addWidget(self.sync_status_label)
        
        buttons_layout.addStretch()
        
        layout.addLayout(buttons_layout)
    
    def load_initial_data(self):
        """Load initial data"""
        if self.cloud_sync:
            self.load_providers()
            self.load_indicators()
            self.update_statistics()
    
    def load_providers(self):
        """Load cloud providers"""
        if not self.cloud_sync:
            return
        
        try:
            providers = self.cloud_sync.providers
            self.providers_table.setRowCount(len(providers))
            
            for row, (provider_id, provider) in enumerate(providers.items()):
                self.providers_table.setItem(row, 0, QTableWidgetItem(provider.name))
                
                status = "Enabled" if provider.enabled else "Disabled"
                self.providers_table.setItem(row, 1, QTableWidgetItem(status))
                
                self.providers_table.setItem(row, 2, QTableWidgetItem(provider.api_url))
                self.providers_table.setItem(row, 3, QTableWidgetItem(f"{provider.sync_interval} min"))
                
                last_sync = provider.last_sync or "Never"
                self.providers_table.setItem(row, 4, QTableWidgetItem(last_sync))
                
                self.providers_table.setItem(row, 5, QTableWidgetItem(str(provider.indicators_count)))
            
        except Exception as e:
            self.logger.error(f"Failed to load providers: {e}")
    
    def load_indicators(self):
        """Load threat indicators"""
        if not self.cloud_sync:
            return
        
        try:
            indicators = self.cloud_sync.query_indicators(limit=100)
            self.indicators_table.setRowCount(len(indicators))
            
            for row, indicator in enumerate(indicators):
                self.indicators_table.setItem(row, 0, QTableWidgetItem(indicator['indicator_type']))
                self.indicators_table.setItem(row, 1, QTableWidgetItem(indicator['value']))
                self.indicators_table.setItem(row, 2, QTableWidgetItem(indicator['threat_type']))
                self.indicators_table.setItem(row, 3, QTableWidgetItem(f"{indicator['confidence']:.2f}"))
                self.indicators_table.setItem(row, 4, QTableWidgetItem(indicator['source']))
                self.indicators_table.setItem(row, 5, QTableWidgetItem(indicator['first_seen']))
                self.indicators_table.setItem(row, 6, QTableWidgetItem(indicator['last_seen']))
            
        except Exception as e:
            self.logger.error(f"Failed to load indicators: {e}")
    
    def update_statistics(self):
        """Update statistics display"""
        if not self.cloud_sync:
            return
        
        try:
            stats = self.cloud_sync.get_sync_statistics()
            
            stats_text = f"""
Total Indicators: {stats.get('total_indicators', 0):,}
Indicators Today: {stats.get('indicators_today', 0):,}
Successful Syncs: {stats.get('successful_syncs', 0):,}
Failed Syncs: {stats.get('failed_syncs', 0):,}
Active Providers: {stats.get('active_providers', 0)}
Last Sync: {stats.get('last_sync_time', 'Never')}
            """.strip()
            
            self.stats_display.setText(stats_text)
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def update_displays(self):
        """Update all displays"""
        self.update_statistics()
    
    def start_sync(self):
        """Start cloud synchronization"""
        if self.cloud_sync:
            self.cloud_sync.start_sync()
            self.sync_status_label.setText("Status: Running")
    
    def stop_sync(self):
        """Stop cloud synchronization"""
        if self.cloud_sync:
            self.cloud_sync.stop_sync()
            self.sync_status_label.setText("Status: Stopped")
    
    def on_sync_event(self, event_type: str, data: Dict[str, Any]):
        """Handle sync events"""
        try:
            if event_type == 'sync_completed':
                activity_text = f"[{datetime.now().strftime('%H:%M:%S')}] " \
                              f"{data['provider']}: Added {data['indicators_added']}, " \
                              f"Updated {data['indicators_updated']} indicators\n"
                self.activity_display.append(activity_text)
            
        except Exception as e:
            self.logger.error(f"Failed to handle sync event: {e}")
    
    def closeEvent(self, event):
        """Handle close event"""
        if self.cloud_sync:
            self.cloud_sync.cleanup()
        event.accept()
