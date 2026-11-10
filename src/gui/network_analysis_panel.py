#!/usr/bin/env python3
"""
Network Traffic Analysis GUI Panel
Comprehensive interface for network monitoring and threat detection
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QGroupBox, QGridLayout, QProgressBar, QTextEdit,
    QComboBox, QSpinBox, QCheckBox, QSlider, QFrame, QSplitter, QScrollArea,
    QHeaderView, QAbstractItemView, QMessageBox, QFileDialog, QLineEdit
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QColor, QPalette, QPixmap, QIcon

# Import network analysis modules
try:
    from ..network.deep_packet_inspector import DeepPacketInspector
    from ..network.network_anomaly_detector import NetworkAnomalyDetector
    from ..network.traffic_pattern_analyzer import TrafficPatternAnalyzer
    from ..network.botnet_detector import BotnetDetector
except ImportError:
    # Fallback for testing
    DeepPacketInspector = None
    NetworkAnomalyDetector = None
    TrafficPatternAnalyzer = None
    BotnetDetector = None

class NetworkAnalysisPanel(QWidget):
    """Network Traffic Analysis GUI Panel"""
    
    # Signals
    threat_detected = pyqtSignal(dict)
    anomaly_detected = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.network_analysis_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Network analysis components
        self.dpi_engine = None
        self.anomaly_detector = None
        self.pattern_analyzer = None
        self.botnet_detector = None
        
        # Monitoring state
        self.monitoring_active = False
        self.packets_captured = 0
        self.threats_detected = 0
        self.anomalies_detected = 0
        self.patterns_detected = 0
        
        # Update timers
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        
        # Initialize UI
        self.init_ui()
        self.init_network_components()
        
        self.logger.info("Network Analysis Panel initialized")
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Network Traffic Analysis")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Control buttons
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        header_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        header_layout.addWidget(self.stop_button)
        
        layout.addLayout(header_layout)
        
        # Status bar
        self.status_label = QLabel("Network monitoring stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # Main tabs
        self.tab_widget = QTabWidget()
        
        # Overview tab
        self.overview_tab = self.create_overview_tab()
        self.tab_widget.addTab(self.overview_tab, "Overview")
        
        # Deep Packet Inspection tab
        self.dpi_tab = self.create_dpi_tab()
        self.tab_widget.addTab(self.dpi_tab, "Deep Packet Inspection")
        
        # Anomaly Detection tab
        self.anomaly_tab = self.create_anomaly_tab()
        self.tab_widget.addTab(self.anomaly_tab, "Anomaly Detection")
        
        # Pattern Analysis tab
        self.pattern_tab = self.create_pattern_tab()
        self.tab_widget.addTab(self.pattern_tab, "Traffic Patterns")
        
        # Botnet Detection tab
        self.botnet_tab = self.create_botnet_tab()
        self.tab_widget.addTab(self.botnet_tab, "Botnet Detection")
        
        # Settings tab
        self.settings_tab = self.create_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        layout.addWidget(self.tab_widget)
        
        self.setLayout(layout)
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Statistics group
        stats_group = QGroupBox("Network Statistics")
        stats_layout = QGridLayout(stats_group)
        
        # Statistics labels
        self.packets_label = QLabel("Packets Captured: 0")
        self.threats_label = QLabel("Threats Detected: 0")
        self.anomalies_label = QLabel("Anomalies Detected: 0")
        self.patterns_label = QLabel("Patterns Detected: 0")
        
        stats_layout.addWidget(self.packets_label, 0, 0)
        stats_layout.addWidget(self.threats_label, 0, 1)
        stats_layout.addWidget(self.anomalies_label, 1, 0)
        stats_layout.addWidget(self.patterns_label, 1, 1)
        
        layout.addWidget(stats_group)
        
        # Real-time activity
        activity_group = QGroupBox("Real-time Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(6)
        self.activity_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Source", "Destination", "Protocol", "Details"
        ])
        self.activity_table.horizontalHeader().setStretchLastSection(True)
        self.activity_table.setAlternatingRowColors(True)
        self.activity_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        
        activity_layout.addWidget(self.activity_table)
        layout.addWidget(activity_group)
        
        return tab
    
    def create_dpi_tab(self):
        """Create Deep Packet Inspection tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # DPI controls
        controls_group = QGroupBox("DPI Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.dpi_enabled = QCheckBox("Enable Deep Packet Inspection")
        self.dpi_enabled.setChecked(True)
        controls_layout.addWidget(self.dpi_enabled)
        
        controls_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["eth0", "wlan0", "any"])
        controls_layout.addWidget(self.interface_combo)
        
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        # Packet capture table
        packets_group = QGroupBox("Captured Packets")
        packets_layout = QVBoxLayout(packets_group)
        
        self.packets_table = QTableWidget()
        self.packets_table.setColumnCount(7)
        self.packets_table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Dest IP", "Protocol", "Port", "Size", "Threat Score"
        ])
        self.packets_table.horizontalHeader().setStretchLastSection(True)
        self.packets_table.setAlternatingRowColors(True)
        
        packets_layout.addWidget(self.packets_table)
        layout.addWidget(packets_group)
        
        return tab
    
    def create_anomaly_tab(self):
        """Create Anomaly Detection tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Anomaly controls
        controls_group = QGroupBox("Anomaly Detection Controls")
        controls_layout = QGridLayout(controls_group)
        
        self.anomaly_enabled = QCheckBox("Enable Anomaly Detection")
        self.anomaly_enabled.setChecked(True)
        controls_layout.addWidget(self.anomaly_enabled, 0, 0)
        
        layout.addWidget(controls_group)
        
        # Anomalies table
        anomalies_group = QGroupBox("Detected Anomalies")
        anomalies_layout = QVBoxLayout(anomalies_group)
        
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(6)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Timestamp", "Source", "Anomaly Type", "Confidence", "Metrics", "Details"
        ])
        self.anomalies_table.horizontalHeader().setStretchLastSection(True)
        self.anomalies_table.setAlternatingRowColors(True)
        
        anomalies_layout.addWidget(self.anomalies_table)
        layout.addWidget(anomalies_group)
        
        return tab
    
    def create_pattern_tab(self):
        """Create Traffic Pattern Analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Pattern controls
        controls_group = QGroupBox("Pattern Analysis Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.pattern_enabled = QCheckBox("Enable Pattern Analysis")
        self.pattern_enabled.setChecked(True)
        controls_layout.addWidget(self.pattern_enabled)
        
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        # Detected patterns
        patterns_group = QGroupBox("Detected Patterns")
        patterns_layout = QVBoxLayout(patterns_group)
        
        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(6)
        self.patterns_table.setHorizontalHeaderLabels([
            "Timestamp", "Pattern Type", "Source", "Destination", "Confidence", "Description"
        ])
        self.patterns_table.horizontalHeader().setStretchLastSection(True)
        self.patterns_table.setAlternatingRowColors(True)
        
        patterns_layout.addWidget(self.patterns_table)
        layout.addWidget(patterns_group)
        
        return tab
    
    def create_botnet_tab(self):
        """Create Botnet Detection tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Botnet controls
        controls_group = QGroupBox("Botnet Detection Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.botnet_enabled = QCheckBox("Enable Botnet Detection")
        self.botnet_enabled.setChecked(True)
        controls_layout.addWidget(self.botnet_enabled)
        
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        # Botnet detections
        detections_group = QGroupBox("Botnet Communications")
        detections_layout = QVBoxLayout(detections_group)
        
        self.botnet_table = QTableWidget()
        self.botnet_table.setColumnCount(7)
        self.botnet_table.setHorizontalHeaderLabels([
            "Timestamp", "Botnet Family", "Type", "Source", "Destination", "Confidence", "Evidence"
        ])
        self.botnet_table.horizontalHeader().setStretchLastSection(True)
        self.botnet_table.setAlternatingRowColors(True)
        
        detections_layout.addWidget(self.botnet_table)
        layout.addWidget(detections_group)
        
        return tab
    
    def create_settings_tab(self):
        """Create Settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QGridLayout(general_group)
        
        general_layout.addWidget(QLabel("Update Interval (seconds):"), 0, 0)
        self.update_interval_spin = QSpinBox()
        self.update_interval_spin.setRange(1, 60)
        self.update_interval_spin.setValue(5)
        general_layout.addWidget(self.update_interval_spin, 0, 1)
        
        self.auto_scroll_checkbox = QCheckBox("Auto-scroll tables")
        self.auto_scroll_checkbox.setChecked(True)
        general_layout.addWidget(self.auto_scroll_checkbox, 1, 0)
        
        layout.addWidget(general_group)
        
        layout.addStretch()
        
        return tab
    
    def init_network_components(self):
        """Initialize network analysis components"""
        try:
            if DeepPacketInspector:
                self.dpi_engine = DeepPacketInspector()
                self.dpi_engine.add_threat_callback(self.on_threat_detected)
            
            if NetworkAnomalyDetector:
                self.anomaly_detector = NetworkAnomalyDetector()
                self.anomaly_detector.add_anomaly_callback(self.on_anomaly_detected)
            
            if TrafficPatternAnalyzer:
                self.pattern_analyzer = TrafficPatternAnalyzer()
                self.pattern_analyzer.add_pattern_callback(self.on_pattern_detected)
            
            if BotnetDetector:
                self.botnet_detector = BotnetDetector()
                self.botnet_detector.add_detection_callback(self.on_botnet_detected)
            
            self.logger.info("Network analysis components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize network components: {e}")
    
    def start_monitoring(self):
        """Start network monitoring"""
        try:
            if self.monitoring_active:
                return
            
            # Start DPI engine
            if self.dpi_engine and self.dpi_enabled.isChecked():
                interface = self.interface_combo.currentText()
                self.dpi_engine.start_capture(interface)
            
            # Start anomaly detector
            if self.anomaly_detector and self.anomaly_enabled.isChecked():
                self.anomaly_detector.start_analysis()
            
            # Start pattern analyzer
            if self.pattern_analyzer and self.pattern_enabled.isChecked():
                self.pattern_analyzer.start_analysis()
            
            # Start botnet detector
            if self.botnet_detector and self.botnet_enabled.isChecked():
                self.botnet_detector.start_analysis()
            
            self.monitoring_active = True
            
            # Update UI
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_label.setText("Network monitoring active")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
            
            # Start timers
            self.stats_timer.start(1000)  # Update stats every second
            self.ui_timer.start(self.update_interval_spin.value() * 1000)
            
            self.status_changed.emit("Network monitoring started")
            self.logger.info("Network monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        try:
            if not self.monitoring_active:
                return
            
            # Stop components
            if self.dpi_engine:
                self.dpi_engine.stop_capture()
            
            if self.anomaly_detector:
                self.anomaly_detector.stop_analysis()
            
            if self.pattern_analyzer:
                self.pattern_analyzer.stop_analysis()
            
            if self.botnet_detector:
                self.botnet_detector.stop_analysis()
            
            self.monitoring_active = False
            
            # Update UI
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Network monitoring stopped")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
            
            # Stop timers
            self.stats_timer.stop()
            self.ui_timer.stop()
            
            self.status_changed.emit("Network monitoring stopped")
            self.logger.info("Network monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
    
    def update_statistics(self):
        """Update statistics display"""
        try:
            # Update packet count
            if self.dpi_engine:
                stats = self.dpi_engine.get_capture_statistics()
                self.packets_captured = stats.get('packets_captured', 0)
                self.threats_detected = stats.get('threats_detected', 0)
            
            # Update anomaly count
            if self.anomaly_detector:
                anomaly_stats = self.anomaly_detector.get_anomaly_statistics()
                self.anomalies_detected = anomaly_stats.get('total_anomalies', 0)
            
            # Update pattern count
            if self.pattern_analyzer:
                pattern_stats = self.pattern_analyzer.get_pattern_statistics()
                self.patterns_detected = pattern_stats.get('patterns_detected', 0)
            
            # Update labels
            self.packets_label.setText(f"Packets Captured: {self.packets_captured:,}")
            self.threats_label.setText(f"Threats Detected: {self.threats_detected}")
            self.anomalies_label.setText(f"Anomalies Detected: {self.anomalies_detected}")
            self.patterns_label.setText(f"Patterns Detected: {self.patterns_detected}")
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def update_ui(self):
        """Update UI tables and displays"""
        try:
            self.update_activity_table()
            self.update_packets_table()
            self.update_anomalies_table()
            self.update_patterns_table()
            self.update_botnet_table()
            
        except Exception as e:
            self.logger.error(f"Failed to update UI: {e}")
    
    def update_activity_table(self):
        """Update real-time activity table"""
        try:
            if not self.dpi_engine:
                return
            
            # Get recent packets
            recent_packets = self.dpi_engine.get_recent_packets(50)
            
            self.activity_table.setRowCount(len(recent_packets))
            
            for row, packet in enumerate(recent_packets):
                timestamp = datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S')
                self.activity_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.activity_table.setItem(row, 1, QTableWidgetItem("Packet"))
                self.activity_table.setItem(row, 2, QTableWidgetItem(packet.get('src_ip', 'N/A')))
                self.activity_table.setItem(row, 3, QTableWidgetItem(packet.get('dst_ip', 'N/A')))
                self.activity_table.setItem(row, 4, QTableWidgetItem(packet.get('protocol', 'N/A')))
                self.activity_table.setItem(row, 5, QTableWidgetItem(f"Size: {packet.get('size', 0)} bytes"))
            
            if self.auto_scroll_checkbox.isChecked():
                self.activity_table.scrollToBottom()
            
        except Exception as e:
            self.logger.error(f"Failed to update activity table: {e}")
    
    def update_packets_table(self):
        """Update packets table"""
        try:
            if not self.dpi_engine:
                return
            
            packets = self.dpi_engine.get_recent_packets(100)
            self.packets_table.setRowCount(len(packets))
            
            for row, packet in enumerate(packets):
                timestamp = datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S')
                self.packets_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.packets_table.setItem(row, 1, QTableWidgetItem(packet.get('src_ip', 'N/A')))
                self.packets_table.setItem(row, 2, QTableWidgetItem(packet.get('dst_ip', 'N/A')))
                self.packets_table.setItem(row, 3, QTableWidgetItem(packet.get('protocol', 'N/A')))
                self.packets_table.setItem(row, 4, QTableWidgetItem(str(packet.get('dst_port', 'N/A'))))
                self.packets_table.setItem(row, 5, QTableWidgetItem(str(packet.get('size', 0))))
                self.packets_table.setItem(row, 6, QTableWidgetItem(f"{packet.get('threat_score', 0.0):.2f}"))
            
        except Exception as e:
            self.logger.error(f"Failed to update packets table: {e}")
    
    def update_anomalies_table(self):
        """Update anomalies table"""
        try:
            if not self.anomaly_detector:
                return
            
            anomalies = self.anomaly_detector.get_recent_anomalies(50)
            self.anomalies_table.setRowCount(len(anomalies))
            
            for row, anomaly in enumerate(anomalies):
                timestamp = datetime.fromtimestamp(anomaly['timestamp']).strftime('%H:%M:%S')
                self.anomalies_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.anomalies_table.setItem(row, 1, QTableWidgetItem(anomaly.get('src_ip', 'N/A')))
                self.anomalies_table.setItem(row, 2, QTableWidgetItem(anomaly.get('anomaly_type', 'Unknown')))
                self.anomalies_table.setItem(row, 3, QTableWidgetItem(f"{anomaly.get('confidence', 0.0):.2f}"))
                self.anomalies_table.setItem(row, 4, QTableWidgetItem(str(anomaly.get('metrics', {}))))
                self.anomalies_table.setItem(row, 5, QTableWidgetItem(anomaly.get('description', 'N/A')))
            
        except Exception as e:
            self.logger.error(f"Failed to update anomalies table: {e}")
    
    def update_patterns_table(self):
        """Update patterns table"""
        try:
            if not self.pattern_analyzer:
                return
            
            patterns = self.pattern_analyzer.get_recent_patterns(50)
            self.patterns_table.setRowCount(len(patterns))
            
            for row, pattern in enumerate(patterns):
                timestamp = datetime.fromtimestamp(pattern['timestamp']).strftime('%H:%M:%S')
                self.patterns_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.patterns_table.setItem(row, 1, QTableWidgetItem(pattern.get('pattern_type', 'Unknown')))
                self.patterns_table.setItem(row, 2, QTableWidgetItem(pattern.get('src_ip', 'N/A')))
                self.patterns_table.setItem(row, 3, QTableWidgetItem(pattern.get('dst_ip', 'N/A')))
                self.patterns_table.setItem(row, 4, QTableWidgetItem(f"{pattern.get('confidence', 0.0):.2f}"))
                self.patterns_table.setItem(row, 5, QTableWidgetItem(pattern.get('description', 'N/A')))
            
        except Exception as e:
            self.logger.error(f"Failed to update patterns table: {e}")
    
    def update_botnet_table(self):
        """Update botnet table"""
        try:
            if not self.botnet_detector:
                return
            
            detections = self.botnet_detector.get_recent_detections(50)
            self.botnet_table.setRowCount(len(detections))
            
            for row, detection in enumerate(detections):
                timestamp = datetime.fromtimestamp(detection['timestamp']).strftime('%H:%M:%S')
                self.botnet_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.botnet_table.setItem(row, 1, QTableWidgetItem(detection.get('botnet_family', 'Unknown')))
                self.botnet_table.setItem(row, 2, QTableWidgetItem(detection.get('communication_type', 'Unknown')))
                self.botnet_table.setItem(row, 3, QTableWidgetItem(detection.get('src_ip', 'N/A')))
                self.botnet_table.setItem(row, 4, QTableWidgetItem(detection.get('dst_ip', 'N/A')))
                self.botnet_table.setItem(row, 5, QTableWidgetItem(f"{detection.get('confidence', 0.0):.2f}"))
                self.botnet_table.setItem(row, 6, QTableWidgetItem(str(detection.get('evidence', {}))))
            
        except Exception as e:
            self.logger.error(f"Failed to update botnet table: {e}")
    
    # Callback methods
    def on_threat_detected(self, threat_data):
        """Handle threat detection callback"""
        self.threat_detected.emit(threat_data)
    
    def on_anomaly_detected(self, anomaly_data):
        """Handle anomaly detection callback"""
        self.anomaly_detected.emit(anomaly_data)
    
    def on_pattern_detected(self, pattern_data):
        """Handle pattern detection callback"""
        pass  # Handle pattern detection
    
    def on_botnet_detected(self, detection_data):
        """Handle botnet detection callback"""
        pass  # Handle botnet detection
    
    def get_monitoring_status(self):
        """Get current monitoring status"""
        return {
            'active': self.monitoring_active,
            'packets_captured': self.packets_captured,
            'threats_detected': self.threats_detected,
            'anomalies_detected': self.anomalies_detected,
            'patterns_detected': self.patterns_detected
        }
