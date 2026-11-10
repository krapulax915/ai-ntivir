#!/usr/bin/env python3
"""
Automated Threat Response Control Panel
GUI for managing automated threat response system
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class ResponseRuleWidget(QWidget):
    """Widget for managing response rules"""
    
    rule_changed = pyqtSignal(str, dict)  # rule_id, rule_data
    
    def __init__(self, response_system=None):
        super().__init__()
        self.response_system = response_system
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.response_control_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.init_ui()
        self.load_rules()
    
    def init_ui(self):
        """Initialize rule management UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("📋 Response Rules")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Add rule button
        add_rule_btn = QPushButton("➕ Add Rule")
        add_rule_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
        """)
        add_rule_btn.clicked.connect(self.add_new_rule)
        header_layout.addWidget(add_rule_btn)
        
        layout.addLayout(header_layout)
        
        # Rules table
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(7)
        self.rules_table.setHorizontalHeaderLabels([
            "Enabled", "Rule Name", "Priority", "Conditions", "Actions", "Cooldown", "Controls"
        ])
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rules_table.setAlternatingRowColors(True)
        
        # Set column widths
        header = self.rules_table.horizontalHeader()
        header.resizeSection(0, 80)   # Enabled
        header.resizeSection(1, 200)  # Rule Name
        header.resizeSection(2, 80)   # Priority
        header.resizeSection(3, 250)  # Conditions
        header.resizeSection(4, 200)  # Actions
        header.resizeSection(5, 100)  # Cooldown
        
        layout.addWidget(self.rules_table)
        
        # Rule details
        details_group = QGroupBox("Rule Details")
        details_layout = QVBoxLayout(details_group)
        
        self.rule_details = QTextEdit()
        self.rule_details.setReadOnly(True)
        self.rule_details.setMaximumHeight(150)
        self.rule_details.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        details_layout.addWidget(self.rule_details)
        
        layout.addWidget(details_group)
        
        # Connect table selection
        self.rules_table.itemSelectionChanged.connect(self.show_rule_details)
    
    def load_rules(self):
        """Load rules from response system"""
        if not self.response_system:
            return
        
        try:
            rules = self.response_system.rules
            self.rules_table.setRowCount(len(rules))
            
            for row, rule in enumerate(rules):
                # Enabled checkbox
                enabled_checkbox = QCheckBox()
                enabled_checkbox.setChecked(rule.enabled)
                enabled_checkbox.stateChanged.connect(
                    lambda state, rule_id=rule.rule_id: self.toggle_rule(rule_id, state == Qt.Checked)
                )
                self.rules_table.setCellWidget(row, 0, enabled_checkbox)
                
                # Rule name
                name_item = QTableWidgetItem(rule.name)
                if rule.enabled:
                    name_item.setBackground(QColor(46, 204, 113, 50))
                else:
                    name_item.setBackground(QColor(149, 165, 166, 50))
                self.rules_table.setItem(row, 1, name_item)
                
                # Priority
                priority_item = QTableWidgetItem(str(rule.priority))
                if rule.priority == 0:
                    priority_item.setBackground(QColor(231, 76, 60, 100))
                elif rule.priority <= 2:
                    priority_item.setBackground(QColor(243, 156, 18, 100))
                self.rules_table.setItem(row, 2, priority_item)
                
                # Conditions summary
                conditions_text = self.format_conditions(rule.conditions)
                self.rules_table.setItem(row, 3, QTableWidgetItem(conditions_text))
                
                # Actions summary
                actions_text = ", ".join([action.value for action in rule.actions])
                self.rules_table.setItem(row, 4, QTableWidgetItem(actions_text))
                
                # Cooldown
                cooldown_text = f"{rule.cooldown_seconds}s"
                self.rules_table.setItem(row, 5, QTableWidgetItem(cooldown_text))
                
                # Control buttons
                controls_widget = QWidget()
                controls_layout = QHBoxLayout(controls_widget)
                controls_layout.setContentsMargins(5, 2, 5, 2)
                
                edit_btn = QPushButton("✏️")
                edit_btn.setToolTip("Edit Rule")
                edit_btn.setMaximumSize(30, 25)
                edit_btn.clicked.connect(lambda _, rule_id=rule.rule_id: self.edit_rule(rule_id))
                controls_layout.addWidget(edit_btn)
                
                delete_btn = QPushButton("🗑️")
                delete_btn.setToolTip("Delete Rule")
                delete_btn.setMaximumSize(30, 25)
                delete_btn.clicked.connect(lambda _, rule_id=rule.rule_id: self.delete_rule(rule_id))
                controls_layout.addWidget(delete_btn)
                
                controls_layout.addStretch()
                self.rules_table.setCellWidget(row, 6, controls_widget)
                
        except Exception as e:
            self.logger.error(f"Failed to load rules: {e}")
    
    def format_conditions(self, conditions: Dict[str, Any]) -> str:
        """Format conditions for display"""
        parts = []
        
        if 'threat_score_min' in conditions:
            parts.append(f"Score≥{conditions['threat_score_min']}")
        
        if 'severity' in conditions:
            severity = conditions['severity']
            if isinstance(severity, list):
                parts.append(f"Severity: {', '.join(severity)}")
            else:
                parts.append(f"Severity: {severity}")
        
        if 'source' in conditions:
            source = conditions['source']
            if isinstance(source, list):
                parts.append(f"Source: {', '.join(source)}")
            else:
                parts.append(f"Source: {source}")
        
        return "; ".join(parts) if parts else "No conditions"
    
    def toggle_rule(self, rule_id: str, enabled: bool):
        """Toggle rule enabled state"""
        try:
            if self.response_system:
                self.response_system.enable_rule(rule_id, enabled)
                self.load_rules()  # Refresh display
        except Exception as e:
            self.logger.error(f"Failed to toggle rule {rule_id}: {e}")
    
    def add_new_rule(self):
        """Add new response rule"""
        # Implementation would show rule creation dialog
        QMessageBox.information(self, "Add Rule", "Rule creation dialog would be implemented here")
    
    def edit_rule(self, rule_id: str):
        """Edit existing rule"""
        # Implementation would show rule editing dialog
        QMessageBox.information(self, "Edit Rule", f"Rule editing dialog for {rule_id} would be implemented here")
    
    def delete_rule(self, rule_id: str):
        """Delete rule"""
        try:
            reply = QMessageBox.question(
                self, "Delete Rule", 
                f"Are you sure you want to delete rule '{rule_id}'?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes and self.response_system:
                self.response_system.remove_rule(rule_id)
                self.load_rules()  # Refresh display
                
        except Exception as e:
            self.logger.error(f"Failed to delete rule {rule_id}: {e}")
    
    def show_rule_details(self):
        """Show details for selected rule"""
        try:
            current_row = self.rules_table.currentRow()
            if current_row >= 0 and self.response_system:
                rule = self.response_system.rules[current_row]
                
                details = f"""Rule ID: {rule.rule_id}
Name: {rule.name}
Description: {rule.description}
Priority: {rule.priority}
Enabled: {rule.enabled}
Cooldown: {rule.cooldown_seconds} seconds

Conditions:
{json.dumps(rule.conditions, indent=2)}

Actions:
{[action.value for action in rule.actions]}
"""
                self.rule_details.setPlainText(details)
                
        except Exception as e:
            self.logger.error(f"Failed to show rule details: {e}")

class ResponseHistoryWidget(QWidget):
    """Widget for displaying response history"""
    
    def __init__(self, response_system=None):
        super().__init__()
        self.response_system = response_system
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.response_control_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.init_ui()
        self.load_history()
    
    def init_ui(self):
        """Initialize history display UI"""
        layout = QVBoxLayout(self)
        
        # Header with filters
        header_layout = QHBoxLayout()
        
        title_label = QLabel("📊 Response History")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Time filter
        header_layout.addWidget(QLabel("Last:"))
        self.time_filter = QComboBox()
        self.time_filter.addItems(["1 Hour", "6 Hours", "24 Hours", "7 Days"])
        self.time_filter.setCurrentText("24 Hours")
        self.time_filter.currentTextChanged.connect(self.load_history)
        header_layout.addWidget(self.time_filter)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_history)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Rule", "Success", "Actions", "Threat Score", "Details"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSortingEnabled(True)
        
        # Set column widths
        header = self.history_table.horizontalHeader()
        header.resizeSection(0, 150)  # Timestamp
        header.resizeSection(1, 200)  # Rule
        header.resizeSection(2, 80)   # Success
        header.resizeSection(3, 200)  # Actions
        header.resizeSection(4, 100)  # Threat Score
        
        layout.addWidget(self.history_table)
        
        # Response details
        details_group = QGroupBox("Response Details")
        details_layout = QVBoxLayout(details_group)
        
        self.response_details = QTextEdit()
        self.response_details.setReadOnly(True)
        self.response_details.setMaximumHeight(150)
        self.response_details.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
        """)
        details_layout.addWidget(self.response_details)
        
        layout.addWidget(details_group)
        
        # Connect table selection
        self.history_table.itemSelectionChanged.connect(self.show_response_details)
    
    def load_history(self):
        """Load response history"""
        if not self.response_system:
            return
        
        try:
            # Get time filter value
            time_text = self.time_filter.currentText()
            hours = {"1 Hour": 1, "6 Hours": 6, "24 Hours": 24, "7 Days": 168}[time_text]
            
            responses = self.response_system.get_recent_responses(hours)
            self.history_table.setRowCount(len(responses))
            
            for row, response in enumerate(responses):
                # Timestamp
                timestamp = response.get('timestamp', '')
                if isinstance(timestamp, str):
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                self.history_table.setItem(row, 0, QTableWidgetItem(str(timestamp)))
                
                # Rule name
                rule_name = response.get('rule_id', 'Unknown')
                self.history_table.setItem(row, 1, QTableWidgetItem(rule_name))
                
                # Success status with color coding
                success = response.get('success', False)
                success_item = QTableWidgetItem("✅ Success" if success else "❌ Failed")
                if success:
                    success_item.setBackground(QColor(46, 204, 113, 100))
                else:
                    success_item.setBackground(QColor(231, 76, 60, 100))
                self.history_table.setItem(row, 2, success_item)
                
                # Actions
                actions = response.get('actions', [])
                if isinstance(actions, list):
                    actions_text = ", ".join([a.get('action', '') for a in actions])
                else:
                    actions_text = str(actions)
                self.history_table.setItem(row, 3, QTableWidgetItem(actions_text))
                
                # Threat score
                threat_score = response.get('threat_score', 0.0)
                score_item = QTableWidgetItem(f"{threat_score:.2f}")
                if threat_score > 0.8:
                    score_item.setBackground(QColor(231, 76, 60, 100))
                elif threat_score > 0.6:
                    score_item.setBackground(QColor(243, 156, 18, 100))
                self.history_table.setItem(row, 4, score_item)
                
                # Details summary
                details = response.get('details', [])
                if isinstance(details, list):
                    details_text = "; ".join(details[:2])  # Show first 2 details
                    if len(details) > 2:
                        details_text += f" (+{len(details)-2} more)"
                else:
                    details_text = str(details)
                self.history_table.setItem(row, 5, QTableWidgetItem(details_text))
            
            # Sort by timestamp (newest first)
            self.history_table.sortItems(0, Qt.DescendingOrder)
            
        except Exception as e:
            self.logger.error(f"Failed to load response history: {e}")
    
    def show_response_details(self):
        """Show details for selected response"""
        try:
            current_row = self.history_table.currentRow()
            if current_row >= 0 and self.response_system:
                # Get response data from table
                timestamp_item = self.history_table.item(current_row, 0)
                rule_item = self.history_table.item(current_row, 1)
                success_item = self.history_table.item(current_row, 2)
                
                details = f"""Response Details:
Timestamp: {timestamp_item.text() if timestamp_item else 'Unknown'}
Rule: {rule_item.text() if rule_item else 'Unknown'}
Status: {success_item.text() if success_item else 'Unknown'}

Full response data would be shown here with complete action details and metadata.
"""
                self.response_details.setPlainText(details)
                
        except Exception as e:
            self.logger.error(f"Failed to show response details: {e}")

class ResponseControlPanel(QWidget):
    """Main response control panel widget"""
    
    def __init__(self, response_system=None):
        super().__init__()
        self.response_system = response_system
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.response_control_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.init_ui()
        self.update_statistics()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_statistics)
        self.update_timer.start(30000)  # Update every 30 seconds
    
    def init_ui(self):
        """Initialize control panel UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("🤖 Automated Threat Response")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Status indicator
        self.status_label = QLabel("🟢 Active")
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #27ae60;
                padding: 5px 10px;
                border: 2px solid #27ae60;
                border-radius: 15px;
                background-color: rgba(39, 174, 96, 0.1);
            }
        """)
        header_layout.addWidget(self.status_label)
        
        layout.addLayout(header_layout)
        
        # Statistics cards
        stats_layout = QHBoxLayout()
        
        self.total_responses_card = self.create_stat_card("Total Responses", "0", "#3498db")
        stats_layout.addWidget(self.total_responses_card)
        
        self.quarantined_files_card = self.create_stat_card("Quarantined Files", "0", "#e74c3c")
        stats_layout.addWidget(self.quarantined_files_card)
        
        self.blocked_processes_card = self.create_stat_card("Blocked Processes", "0", "#f39c12")
        stats_layout.addWidget(self.blocked_processes_card)
        
        self.active_rules_card = self.create_stat_card("Active Rules", "0", "#27ae60")
        stats_layout.addWidget(self.active_rules_card)
        
        layout.addLayout(stats_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Rules tab
        self.rules_widget = ResponseRuleWidget(self.response_system)
        self.tab_widget.addTab(self.rules_widget, "📋 Rules")
        
        # History tab
        self.history_widget = ResponseHistoryWidget(self.response_system)
        self.tab_widget.addTab(self.history_widget, "📊 History")
        
        layout.addWidget(self.tab_widget)
    
    def create_stat_card(self, title: str, value: str, color: str) -> QWidget:
        """Create statistics card widget"""
        card = QFrame()
        card.setFrameStyle(QFrame.Box)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: white;
                border: 2px solid {color};
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)
        
        # Store value label for updates
        card.value_label = value_label
        
        return card
    
    def update_statistics(self):
        """Update statistics display"""
        try:
            if not self.response_system:
                return
            
            stats = self.response_system.get_response_statistics()
            
            # Update stat cards
            self.total_responses_card.value_label.setText(str(stats.get('total_responses', 0)))
            self.quarantined_files_card.value_label.setText(str(stats.get('quarantined_files', 0)))
            self.blocked_processes_card.value_label.setText(str(stats.get('blocked_processes', 0)))
            self.active_rules_card.value_label.setText(str(stats.get('active_rules', 0)))
            
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {e}")
    
    def set_response_system(self, response_system):
        """Set response system reference"""
        self.response_system = response_system
        self.rules_widget.response_system = response_system
        self.history_widget.response_system = response_system
        self.update_statistics()
