#!/usr/bin/env python3
"""
Enhanced Quarantine Tab
=======================

Fejlett karantén kezelő GUI komponens thread-safe funkcionalitással.
"""

import os
import sys
import sqlite3
import time
from datetime import datetime
from typing import Dict, List

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QGroupBox, QCheckBox, QMessageBox, QProgressBar,
    QComboBox, QLineEdit, QSplitter, QTextEdit, QFrame
)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor, QFont

class QuarantineStatsWorker(QThread):
    """Background worker for quarantine statistics"""
    stats_updated = pyqtSignal(dict)
    
    def __init__(self, quarantine_manager):
        super().__init__()
        self.quarantine_manager = quarantine_manager
        self.running = True
    
    def run(self):
        while self.running:
            try:
                stats = self.quarantine_manager.get_quarantine_stats()
                self.stats_updated.emit(stats)
                self.msleep(5000)  # Update every 5 seconds
            except Exception as e:
                print(f"Stats worker error: {e}")
                self.msleep(10000)  # Wait longer on error
    
    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class EnhancedQuarantineTab(QWidget):
    """Enhanced Quarantine Management Tab"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.quarantine_manager = None
        self.stats_worker = None
        self.auto_refresh_timer = QTimer()
        self.auto_refresh_timer.timeout.connect(self.refresh_quarantine_list)
        
        self.init_ui()
        self.init_quarantine_manager()
        
    def init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout(self)
        
        # Create splitter for better layout
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)
        
        # Top section: Statistics and controls
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        
        # Statistics section
        self.create_statistics_section(top_layout)
        
        # Controls section
        self.create_controls_section(top_layout)
        
        splitter.addWidget(top_widget)
        
        # Bottom section: Quarantine table and details
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        
        # Quarantine table
        self.create_quarantine_table(bottom_layout)
        
        # Details panel
        self.create_details_panel(bottom_layout)
        
        splitter.addWidget(bottom_widget)
        
        # Set splitter proportions
        splitter.setSizes([200, 400])
    
    def create_statistics_section(self, layout):
        """Create statistics display section"""
        stats_group = QGroupBox("📊 Quarantine Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        # Statistics labels
        self.stats_labels = {
            'active': QLabel("Active: 0"),
            'recent': QLabel("Recent (24h): 0"),
            'total_size': QLabel("Total Size: 0 KB"),
            'threat_levels': QLabel("Threats: 0"),
            'in_progress': QLabel("In Progress: 0")
        }
        
        for label in self.stats_labels.values():
            label.setStyleSheet("QLabel { font-weight: bold; padding: 5px; }")
            stats_layout.addWidget(label)
        
        # Progress indicator
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        stats_layout.addWidget(self.progress_bar)
        
        layout.addWidget(stats_group)
    
    def create_controls_section(self, layout):
        """Create control buttons and options"""
        controls_group = QGroupBox("🔧 Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Action buttons
        self.restore_btn = QPushButton("🔄 Restore Selected")
        self.restore_btn.clicked.connect(self.restore_selected_file)
        controls_layout.addWidget(self.restore_btn)
        
        self.delete_btn = QPushButton("🗑️ Delete Selected")
        self.delete_btn.clicked.connect(self.delete_selected_file)
        controls_layout.addWidget(self.delete_btn)
        
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_quarantine_list)
        controls_layout.addWidget(self.refresh_btn)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        controls_layout.addWidget(separator)
        
        # Filter options
        self.status_filter = QComboBox()
        self.status_filter.addItems(["quarantined", "restored", "deleted", "all"])
        self.status_filter.currentTextChanged.connect(self.filter_changed)
        controls_layout.addWidget(QLabel("Status:"))
        controls_layout.addWidget(self.status_filter)
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search files...")
        self.search_box.textChanged.connect(self.search_changed)
        controls_layout.addWidget(self.search_box)
        
        # Auto-refresh toggle
        self.auto_refresh_cb = QCheckBox("Auto-refresh (30s)")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        controls_layout.addWidget(self.auto_refresh_cb)
        
        controls_layout.addStretch()
        layout.addWidget(controls_group)
    
    def create_quarantine_table(self, layout):
        """Create quarantine files table"""
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        # Table
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(7)
        self.quarantine_table.setHorizontalHeaderLabels([
            "File Name", "Original Path", "Threat Level", "Score", 
            "Detection Time", "File Size", "ID"
        ])
        self.quarantine_table.hideColumn(6)  # Hide ID column
        self.quarantine_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.quarantine_table.itemSelectionChanged.connect(self.selection_changed)
        
        table_layout.addWidget(QLabel("🔒 Quarantined Files"))
        table_layout.addWidget(self.quarantine_table)
        
        layout.addWidget(table_widget, 2)  # 2/3 of width
    
    def create_details_panel(self, layout):
        """Create file details panel"""
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        details_layout.addWidget(QLabel("📋 File Details"))
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(200)
        details_layout.addWidget(self.details_text)
        
        # Threat info
        threat_group = QGroupBox("⚠️ Threat Information")
        threat_layout = QVBoxLayout(threat_group)
        
        self.threat_info_text = QTextEdit()
        self.threat_info_text.setReadOnly(True)
        threat_layout.addWidget(self.threat_info_text)
        
        details_layout.addWidget(threat_group)
        details_layout.addStretch()
        
        layout.addWidget(details_widget, 1)  # 1/3 of width
    
    def init_quarantine_manager(self):
        """Initialize quarantine manager"""
        try:
            from src.core.quarantine import QuarantineManager
            self.quarantine_manager = QuarantineManager()
            
            # Start statistics worker
            self.stats_worker = QuarantineStatsWorker(self.quarantine_manager)
            self.stats_worker.stats_updated.connect(self.update_statistics)
            self.stats_worker.start()
            
            # Initial load
            self.refresh_quarantine_list()
            self.toggle_auto_refresh()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize quarantine manager: {e}")
    
    def update_statistics(self, stats: Dict):
        """Update statistics display"""
        try:
            # Update labels
            self.stats_labels['active'].setText(f"Active: {stats.get('active_quarantined', 0)}")
            self.stats_labels['recent'].setText(f"Recent (24h): {stats.get('recent_quarantined', 0)}")
            
            # Format file size
            total_bytes = stats.get('total_size_bytes', 0)
            if total_bytes < 1024:
                size_str = f"{total_bytes} B"
            elif total_bytes < 1024 * 1024:
                size_str = f"{total_bytes / 1024:.1f} KB"
            else:
                size_str = f"{total_bytes / (1024 * 1024):.1f} MB"
            
            self.stats_labels['total_size'].setText(f"Total Size: {size_str}")
            
            # Threat levels
            threat_levels = stats.get('threat_levels', {})
            threat_count = sum(threat_levels.values())
            self.stats_labels['threat_levels'].setText(f"Threats: {threat_count}")
            
            # In progress
            in_progress = stats.get('in_progress_count', 0)
            self.stats_labels['in_progress'].setText(f"In Progress: {in_progress}")
            
            # Color coding based on activity
            if in_progress > 0:
                self.stats_labels['in_progress'].setStyleSheet("QLabel { color: orange; font-weight: bold; }")
            else:
                self.stats_labels['in_progress'].setStyleSheet("QLabel { color: green; font-weight: bold; }")
                
        except Exception as e:
            print(f"Error updating statistics: {e}")
    
    def refresh_quarantine_list(self):
        """Refresh quarantine files list"""
        if not self.quarantine_manager:
            return
        
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            
            # Get filter status
            status_filter = self.status_filter.currentText()
            if status_filter == "all":
                status_filter = None
            
            # Get quarantined files
            if status_filter:
                files = self.quarantine_manager.list_quarantined_files(status_filter)
            else:
                # Get all statuses
                files = []
                for status in ['quarantined', 'restored', 'deleted']:
                    files.extend(self.quarantine_manager.list_quarantined_files(status))
            
            # Apply search filter
            search_text = self.search_box.text().lower()
            if search_text:
                files = [f for f in files if search_text in f['original_path'].lower()]
            
            # Clear and populate table
            self.quarantine_table.setRowCount(len(files))
            
            for row, file_info in enumerate(files):
                # File name
                file_name = os.path.basename(file_info['original_path'])
                self.quarantine_table.setItem(row, 0, QTableWidgetItem(file_name))
                
                # Original path
                self.quarantine_table.setItem(row, 1, QTableWidgetItem(file_info['original_path']))
                
                # Threat level with color coding
                threat_level = file_info.get('threat_level', 'Unknown')
                score = file_info.get('threat_score', 0.0)
                
                threat_item = QTableWidgetItem(threat_level)
                if threat_level == 'CRITICAL':
                    threat_item.setBackground(QColor(231, 76, 60, 100))  # Red
                elif threat_level == 'HIGH':
                    threat_item.setBackground(QColor(230, 126, 34, 100))  # Orange
                elif threat_level == 'MEDIUM':
                    threat_item.setBackground(QColor(241, 196, 15, 100))  # Yellow
                
                self.quarantine_table.setItem(row, 2, threat_item)
                
                # Threat score
                self.quarantine_table.setItem(row, 3, QTableWidgetItem(f"{score:.2f}"))
                
                # Detection time
                timestamp = file_info.get('quarantine_time', 0)
                if timestamp:
                    dt = datetime.fromtimestamp(timestamp)
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    time_str = "Unknown"
                self.quarantine_table.setItem(row, 4, QTableWidgetItem(time_str))
                
                # File size
                file_size = file_info.get('file_size', 0)
                if file_size > 0:
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size / (1024 * 1024):.1f} MB"
                else:
                    size_str = "0 B"
                self.quarantine_table.setItem(row, 5, QTableWidgetItem(size_str))
                
                # Hidden ID
                self.quarantine_table.setItem(row, 6, QTableWidgetItem(str(file_info['id'])))
            
            # Resize columns
            self.quarantine_table.resizeColumnsToContents()
            
            self.progress_bar.setVisible(False)
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            QMessageBox.critical(self, "Error", f"Failed to refresh quarantine list: {e}")
    
    def selection_changed(self):
        """Handle table selection change"""
        try:
            current_row = self.quarantine_table.currentRow()
            if current_row >= 0:
                # Get file info
                file_name = self.quarantine_table.item(current_row, 0).text()
                original_path = self.quarantine_table.item(current_row, 1).text()
                threat_level = self.quarantine_table.item(current_row, 2).text()
                score = self.quarantine_table.item(current_row, 3).text()
                detection_time = self.quarantine_table.item(current_row, 4).text()
                file_size = self.quarantine_table.item(current_row, 5).text()
                
                # Update details panel
                details = f"""File Name: {file_name}
Original Path: {original_path}
Detection Time: {detection_time}
File Size: {file_size}
"""
                self.details_text.setPlainText(details)
                
                # Update threat info
                threat_info = f"""Threat Level: {threat_level}
Threat Score: {score}
Risk Assessment: {"HIGH RISK" if float(score) >= 0.7 else "MEDIUM RISK" if float(score) >= 0.4 else "LOW RISK"}
"""
                self.threat_info_text.setPlainText(threat_info)
                
                # Enable/disable buttons
                self.restore_btn.setEnabled(True)
                self.delete_btn.setEnabled(True)
            else:
                self.details_text.clear()
                self.threat_info_text.clear()
                self.restore_btn.setEnabled(False)
                self.delete_btn.setEnabled(False)
                
        except Exception as e:
            print(f"Selection change error: {e}")
    
    def restore_selected_file(self):
        """Restore selected quarantined file"""
        try:
            current_row = self.quarantine_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
                return
            
            quarantine_id = int(self.quarantine_table.item(current_row, 6).text())
            original_path = self.quarantine_table.item(current_row, 1).text()
            file_name = self.quarantine_table.item(current_row, 0).text()
            
            reply = QMessageBox.question(
                self, "Confirm Restore",
                f"Are you sure you want to restore this file?\n\nFile: {file_name}\nOriginal Path: {original_path}\n\n⚠️ Warning: This file was quarantined as a threat!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if self.quarantine_manager.restore_file(quarantine_id):
                    QMessageBox.information(self, "Success", f"File '{file_name}' restored successfully.")
                    self.refresh_quarantine_list()
                else:
                    QMessageBox.critical(self, "Error", "Failed to restore file. Check logs for details.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error restoring file: {e}")
    
    def delete_selected_file(self):
        """Delete selected quarantined file"""
        try:
            current_row = self.quarantine_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
                return
            
            quarantine_id = int(self.quarantine_table.item(current_row, 6).text())
            file_name = self.quarantine_table.item(current_row, 0).text()
            
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to permanently delete this file?\n\nFile: {file_name}\n\n🗑️ This action cannot be undone!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if self.quarantine_manager.delete_quarantined_file(quarantine_id):
                    QMessageBox.information(self, "Success", f"File '{file_name}' deleted permanently.")
                    self.refresh_quarantine_list()
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete file. Check logs for details.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error deleting file: {e}")
    
    def filter_changed(self):
        """Handle filter change"""
        self.refresh_quarantine_list()
    
    def search_changed(self):
        """Handle search text change"""
        # Debounce search - refresh after 500ms of no typing
        if hasattr(self, 'search_timer'):
            self.search_timer.stop()
        
        self.search_timer = QTimer()
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self.refresh_quarantine_list)
        self.search_timer.start(500)
    
    def toggle_auto_refresh(self):
        """Toggle auto-refresh functionality"""
        if self.auto_refresh_cb.isChecked():
            self.auto_refresh_timer.start(30000)  # 30 seconds
        else:
            self.auto_refresh_timer.stop()
    
    def closeEvent(self, event):
        """Handle widget close"""
        if self.stats_worker:
            self.stats_worker.stop()
        if self.auto_refresh_timer.isActive():
            self.auto_refresh_timer.stop()
        event.accept()
