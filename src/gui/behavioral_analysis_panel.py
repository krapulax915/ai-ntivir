#!/usr/bin/env python3
"""
Behavioral Analysis GUI Panel
Real-time behavioral monitoring and pattern analysis interface
"""

import sys
import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QLabel, QTableWidget, QTableWidgetItem, QPushButton,
                             QProgressBar, QTextEdit, QGroupBox, QGridLayout,
                             QSpinBox, QDoubleSpinBox, QCheckBox, QComboBox,
                             QFrame, QSplitter, QHeaderView, QMessageBox)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QColor, QPalette
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any

class BehavioralAnalysisPanel(QWidget):
    """GUI panel for behavioral analysis monitoring and control"""
    
    # Signals for communication with main window
    behavior_alert_signal = pyqtSignal(dict)
    status_changed_signal = pyqtSignal(str)
    
    def __init__(self, behavioral_analyzer=None):
        super().__init__()
        self.behavioral_analyzer = behavioral_analyzer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_displays)
        self.update_timer.start(2000)  # Update every 2 seconds
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_overview_tab()
        self.create_processes_tab()
        self.create_patterns_tab()
        self.create_settings_tab()
        
        # Control buttons
        self.create_control_buttons(layout)
    
    def create_overview_tab(self):
        """Create overview tab with statistics and status"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Status section
        status_group = QGroupBox("Behavioral Analysis Status")
        status_layout = QGridLayout(status_group)
        
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        status_layout.addWidget(QLabel("Status:"), 0, 0)
        status_layout.addWidget(self.status_label, 0, 1)
        
        self.uptime_label = QLabel("00:00:00")
        status_layout.addWidget(QLabel("Uptime:"), 1, 0)
        status_layout.addWidget(self.uptime_label, 1, 1)
        
        layout.addWidget(status_group)
        
        # Statistics section
        stats_group = QGroupBox("Real-time Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.active_processes_label = QLabel("0")
        stats_layout.addWidget(QLabel("Active Processes:"), 0, 0)
        stats_layout.addWidget(self.active_processes_label, 0, 1)
        
        self.high_risk_processes_label = QLabel("0")
        stats_layout.addWidget(QLabel("High Risk Processes:"), 1, 0)
        stats_layout.addWidget(self.high_risk_processes_label, 1, 1)
        
        self.behavioral_sequences_label = QLabel("0")
        stats_layout.addWidget(QLabel("Behavioral Sequences:"), 2, 0)
        stats_layout.addWidget(self.behavioral_sequences_label, 2, 1)
        
        self.total_behaviors_label = QLabel("0")
        stats_layout.addWidget(QLabel("Total Behaviors Analyzed:"), 3, 0)
        stats_layout.addWidget(self.total_behaviors_label, 3, 1)
        
        layout.addWidget(stats_group)
        
        self.tab_widget.addTab(tab, "Overview")
    
    def create_processes_tab(self):
        """Create processes monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Process Name", "Risk Score", "Risk Indicators", "Start Time", "Status"
        ])
        
        # Adjust column widths
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        layout.addWidget(self.process_table)
        
        # Process details
        details_group = QGroupBox("Process Details")
        details_layout = QVBoxLayout(details_group)
        
        self.process_details_text = QTextEdit()
        self.process_details_text.setMaximumHeight(150)
        self.process_details_text.setReadOnly(True)
        details_layout.addWidget(self.process_details_text)
        
        layout.addWidget(details_group)
        
        # Connect table selection
        self.process_table.itemSelectionChanged.connect(self.on_process_selected)
        
        self.tab_widget.addTab(tab, "Processes")
    
    def create_patterns_tab(self):
        """Create behavioral patterns tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Pattern types filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Pattern Type:"))
        
        self.pattern_filter = QComboBox()
        self.pattern_filter.addItems([
            "All", "coordinated_attack", "process_chain", 
            "persistence_mechanism", "memory_anomaly", "network_anomaly"
        ])
        filter_layout.addWidget(self.pattern_filter)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Patterns table
        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(6)
        self.patterns_table.setHorizontalHeaderLabels([
            "Sequence ID", "Process Name", "Pattern Type", "Risk Score", "Confidence", "Actions"
        ])
        
        layout.addWidget(self.patterns_table)
        
        self.tab_widget.addTab(tab, "Patterns")
    
    def create_settings_tab(self):
        """Create settings and configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Analysis settings
        analysis_group = QGroupBox("Analysis Settings")
        analysis_layout = QGridLayout(analysis_group)
        
        # Risk threshold
        analysis_layout.addWidget(QLabel("Risk Threshold:"), 0, 0)
        self.risk_threshold_spin = QDoubleSpinBox()
        self.risk_threshold_spin.setRange(0.1, 1.0)
        self.risk_threshold_spin.setSingleStep(0.1)
        self.risk_threshold_spin.setValue(0.7)
        analysis_layout.addWidget(self.risk_threshold_spin, 0, 1)
        
        # Monitoring interval
        analysis_layout.addWidget(QLabel("Monitoring Interval (seconds):"), 1, 0)
        self.monitoring_interval_spin = QSpinBox()
        self.monitoring_interval_spin.setRange(1, 60)
        self.monitoring_interval_spin.setValue(5)
        analysis_layout.addWidget(self.monitoring_interval_spin, 1, 1)
        
        layout.addWidget(analysis_group)
        
        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QVBoxLayout(detection_group)
        
        self.enable_process_monitoring = QCheckBox("Enable Process Monitoring")
        self.enable_process_monitoring.setChecked(True)
        detection_layout.addWidget(self.enable_process_monitoring)
        
        self.enable_network_monitoring = QCheckBox("Enable Network Monitoring")
        self.enable_network_monitoring.setChecked(True)
        detection_layout.addWidget(self.enable_network_monitoring)
        
        self.enable_memory_monitoring = QCheckBox("Enable Memory Monitoring")
        self.enable_memory_monitoring.setChecked(True)
        detection_layout.addWidget(self.enable_memory_monitoring)
        
        layout.addWidget(detection_group)
        
        # Apply settings button
        apply_layout = QHBoxLayout()
        apply_layout.addStretch()
        
        self.apply_settings_btn = QPushButton("Apply Settings")
        self.apply_settings_btn.clicked.connect(self.apply_settings)
        apply_layout.addWidget(self.apply_settings_btn)
        
        layout.addLayout(apply_layout)
        layout.addStretch()
        
        self.tab_widget.addTab(tab, "Settings")
    
    def create_control_buttons(self, layout):
        """Create control buttons"""
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.clicked.connect(self.start_analysis)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Analysis")
        self.stop_btn.clicked.connect(self.stop_analysis)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        button_layout.addStretch()
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        button_layout.addWidget(self.export_btn)
        
        layout.addLayout(button_layout)
    
    def start_analysis(self):
        """Start behavioral analysis"""
        try:
            if self.behavioral_analyzer:
                result = self.behavioral_analyzer.start_monitoring()
                if result:
                    self.status_label.setText("Running")
                    self.status_label.setStyleSheet("color: green; font-weight: bold;")
                    
                    self.start_btn.setEnabled(False)
                    self.stop_btn.setEnabled(True)
                    
                    # Update statistics immediately
                    self.update_displays()
                    
                    self.status_changed_signal.emit("started")
                    print("Behavioral analysis started successfully")
                else:
                    print("Failed to start behavioral analysis")
            else:
                print("No behavioral analyzer available")
                
        except Exception as e:
            print(f"Error starting analysis: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start analysis: {e}")
    
    def stop_analysis(self):
        """Stop behavioral analysis"""
        try:
            if self.behavioral_analyzer:
                self.behavioral_analyzer.stop_monitoring()
                self.status_label.setText("Stopped")
                self.status_label.setStyleSheet("color: red; font-weight: bold;")
                
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                
                self.status_changed_signal.emit("stopped")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop analysis: {e}")
    
    def update_displays(self):
        """Update all display elements with current data"""
        try:
            if not self.behavioral_analyzer:
                return
            
            # Update statistics
            stats = self.behavioral_analyzer.get_behavior_statistics()
            
            self.active_processes_label.setText(str(stats.get('processes_analyzed', 0)))
            self.high_risk_processes_label.setText(str(stats.get('suspicious_behaviors', 0)))
            self.behavioral_sequences_label.setText(str(stats.get('blocked_processes', 0)))
            self.total_behaviors_label.setText(str(stats.get('total_events', 0)))
            
            # Update process table
            self.update_process_table()
            
        except Exception as e:
            print(f"Display update error: {e}")
    
    def update_process_table(self):
        """Update process monitoring table"""
        try:
            if not self.behavioral_analyzer:
                return
            
            processes = self.behavioral_analyzer.process_behaviors
            self.process_table.setRowCount(len(processes))
            
            for row, (pid, behavior) in enumerate(processes.items()):
                self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self.process_table.setItem(row, 1, QTableWidgetItem(behavior.process_name))
                
                # Color-code risk score
                risk_item = QTableWidgetItem(f"{behavior.behavior_score:.2f}")
                if behavior.behavior_score >= 0.8:
                    risk_item.setBackground(QColor(255, 200, 200))  # Light red
                elif behavior.behavior_score >= 0.5:
                    risk_item.setBackground(QColor(255, 255, 200))  # Light yellow
                self.process_table.setItem(row, 2, risk_item)
                
                indicators = ", ".join(list(behavior.risk_indicators)[:3])
                if len(behavior.risk_indicators) > 3:
                    indicators += f" (+{len(behavior.risk_indicators) - 3} more)"
                self.process_table.setItem(row, 3, QTableWidgetItem(indicators))
                
                self.process_table.setItem(row, 4, QTableWidgetItem(
                    behavior.start_time.strftime("%H:%M:%S")
                ))
                
                status = "High Risk" if behavior.behavior_score >= 0.7 else "Normal"
                self.process_table.setItem(row, 5, QTableWidgetItem(status))
            
        except Exception as e:
            print(f"Process table update error: {e}")
    
    def on_process_selected(self):
        """Handle process table selection"""
        try:
            current_row = self.process_table.currentRow()
            if current_row < 0:
                return
            
            pid_item = self.process_table.item(current_row, 0)
            if not pid_item:
                return
            
            pid = int(pid_item.text())
            behavior = self.behavioral_analyzer.process_behaviors.get(pid)
            
            if behavior:
                details = f"""Process Details:
                
PID: {behavior.process_id}
Name: {behavior.process_name}
Start Time: {behavior.start_time.strftime("%Y-%m-%d %H:%M:%S")}
Risk Score: {behavior.behavior_score:.3f}

Risk Indicators:
{chr(10).join(f"• {indicator}" for indicator in behavior.risk_indicators)}"""
                
                self.process_details_text.setText(details)
            
        except Exception as e:
            print(f"Process selection error: {e}")
    
    def apply_settings(self):
        """Apply configuration settings"""
        try:
            if self.behavioral_analyzer:
                # Update analyzer settings
                self.behavioral_analyzer.risk_threshold = self.risk_threshold_spin.value()
                
                # Save settings
                self.save_settings()
                
                QMessageBox.information(self, "Settings", "Settings applied successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply settings: {e}")
    
    def save_settings(self):
        """Save current settings"""
        try:
            settings = {
                'risk_threshold': self.risk_threshold_spin.value(),
                'monitoring_interval': self.monitoring_interval_spin.value(),
                'enable_process_monitoring': self.enable_process_monitoring.isChecked(),
                'enable_network_monitoring': self.enable_network_monitoring.isChecked(),
                'enable_memory_monitoring': self.enable_memory_monitoring.isChecked()
            }
            
            # Save to file
            config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "behavioral_analysis.json")
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(settings, f, indent=2)
            
        except Exception as e:
            print(f"Settings save error: {e}")
    
    def load_settings(self):
        """Load saved settings"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "behavioral_analysis.json")
            
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    settings = json.load(f)
                
                self.risk_threshold_spin.setValue(settings.get('risk_threshold', 0.7))
                self.monitoring_interval_spin.setValue(settings.get('monitoring_interval', 5))
                self.enable_process_monitoring.setChecked(settings.get('enable_process_monitoring', True))
                self.enable_network_monitoring.setChecked(settings.get('enable_network_monitoring', True))
                self.enable_memory_monitoring.setChecked(settings.get('enable_memory_monitoring', True))
            
        except Exception as e:
            print(f"Settings load error: {e}")
    
    def export_report(self):
        """Export behavioral analysis report"""
        try:
            if not self.behavioral_analyzer:
                QMessageBox.warning(self, "Warning", "No behavioral analyzer available")
                return
            
            # Generate report
            stats = self.behavioral_analyzer.get_behavior_statistics()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            report_path = f"behavioral_analysis_report_{timestamp}.json"
            
            with open(report_path, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'statistics': stats
                }, f, indent=2)
            
            QMessageBox.information(self, "Export", f"Report exported to {report_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {e}")
