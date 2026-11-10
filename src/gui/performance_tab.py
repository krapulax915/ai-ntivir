#!/usr/bin/env python3
"""
Performance Management Tab for AI Antivirus GUI
Provides controls and monitoring for system performance optimization
"""

import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QPushButton, QLabel, QTextEdit, QCheckBox, 
                            QSlider, QSpinBox, QProgressBar, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSplitter,
                            QComboBox, QGridLayout, QFrame)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QFont, QPixmap, QIcon, QPalette
import logging
from datetime import datetime
import psutil

class PerformanceTab(QWidget):
    """Performance management and monitoring tab"""
    
    performance_mode_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.performance_tab')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.performance_manager = None
        
        self.init_ui()
        self.init_timer()
    
    def init_ui(self):
        """Initialize the performance tab UI"""
        layout = QVBoxLayout(self)
        
        # Performance mode section
        mode_group = self.create_mode_section()
        layout.addWidget(mode_group)
        
        # Real-time monitoring section
        monitoring_group = self.create_monitoring_section()
        layout.addWidget(monitoring_group)
        
        # Resource limits section
        limits_group = self.create_limits_section()
        layout.addWidget(limits_group)
        
        # Performance settings section
        settings_group = self.create_settings_section()
        layout.addWidget(settings_group)
        
        layout.addStretch()
    
    def create_mode_section(self):
        """Create performance mode selection section"""
        group = QGroupBox("🚀 Performance Mode")
        layout = QVBoxLayout(group)
        
        # Mode selection
        mode_layout = QHBoxLayout()
        
        mode_layout.addWidget(QLabel("Current Mode:"))
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "Maximum Performance",
            "Balanced",
            "Conservative",
            "Gaming Mode",
            "Battery Saver"
        ])
        self.mode_combo.setCurrentText("Balanced")
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(self.mode_combo)
        
        mode_layout.addStretch()
        
        # Auto-optimization toggle
        self.adaptive_scaling_cb = QCheckBox("Enable adaptive scaling")
        self.adaptive_scaling_cb.setChecked(True)
        self.adaptive_scaling_cb.stateChanged.connect(self.on_settings_changed)
        mode_layout.addWidget(self.adaptive_scaling_cb)
        
        self.gaming_detection_cb = QCheckBox("Auto-detect gaming mode")
        self.gaming_detection_cb.setChecked(True)
        self.gaming_detection_cb.stateChanged.connect(self.on_settings_changed)
        mode_layout.addWidget(self.gaming_detection_cb)
        
        layout.addLayout(mode_layout)
        
        # Mode description
        self.mode_description = QLabel("Balanced mode provides optimal performance while maintaining reasonable resource usage.")
        self.mode_description.setWordWrap(True)
        self.mode_description.setStyleSheet("color: #666; font-style: italic; margin: 5px;")
        layout.addWidget(self.mode_description)
        
        return group
    
    def create_monitoring_section(self):
        """Create real-time monitoring section"""
        group = QGroupBox("📊 Real-time Performance Monitoring")
        layout = QVBoxLayout(group)
        
        # Metrics grid
        metrics_layout = QGridLayout()
        
        # CPU Usage
        metrics_layout.addWidget(QLabel("CPU Usage:"), 0, 0)
        self.cpu_progress = QProgressBar()
        self.cpu_progress.setRange(0, 100)
        self.cpu_progress.setTextVisible(True)
        metrics_layout.addWidget(self.cpu_progress, 0, 1)
        self.cpu_label = QLabel("0%")
        metrics_layout.addWidget(self.cpu_label, 0, 2)
        
        # Memory Usage
        metrics_layout.addWidget(QLabel("Memory Usage:"), 1, 0)
        self.memory_progress = QProgressBar()
        self.memory_progress.setRange(0, 1024)  # MB
        self.memory_progress.setTextVisible(True)
        metrics_layout.addWidget(self.memory_progress, 1, 1)
        self.memory_label = QLabel("0 MB")
        metrics_layout.addWidget(self.memory_label, 1, 2)
        
        # Thread Count
        metrics_layout.addWidget(QLabel("Active Threads:"), 2, 0)
        self.thread_progress = QProgressBar()
        self.thread_progress.setRange(0, 16)
        self.thread_progress.setTextVisible(True)
        metrics_layout.addWidget(self.thread_progress, 2, 1)
        self.thread_label = QLabel("0")
        metrics_layout.addWidget(self.thread_label, 2, 2)
        
        # Scan Rate
        metrics_layout.addWidget(QLabel("Scan Rate:"), 3, 0)
        self.scan_rate_progress = QProgressBar()
        self.scan_rate_progress.setRange(0, 500)
        self.scan_rate_progress.setTextVisible(True)
        metrics_layout.addWidget(self.scan_rate_progress, 3, 1)
        self.scan_rate_label = QLabel("0 files/sec")
        metrics_layout.addWidget(self.scan_rate_label, 3, 2)
        
        layout.addLayout(metrics_layout)
        
        # System metrics
        system_layout = QHBoxLayout()
        
        self.system_cpu_label = QLabel("System CPU: 0%")
        self.system_memory_label = QLabel("System Memory: 0%")
        self.available_memory_label = QLabel("Available: 0 GB")
        
        for label in [self.system_cpu_label, self.system_memory_label, self.available_memory_label]:
            label.setStyleSheet("font-size: 11px; color: #666; margin: 2px;")
            system_layout.addWidget(label)
        
        system_layout.addStretch()
        layout.addLayout(system_layout)
        
        return group
    
    def create_limits_section(self):
        """Create resource limits configuration section"""
        group = QGroupBox("⚙️ Resource Limits")
        layout = QGridLayout(group)
        
        # CPU Limit
        layout.addWidget(QLabel("Max CPU Usage:"), 0, 0)
        self.cpu_limit_slider = QSlider(Qt.Horizontal)
        self.cpu_limit_slider.setRange(10, 100)
        self.cpu_limit_slider.setValue(50)
        self.cpu_limit_slider.valueChanged.connect(self.on_limits_changed)
        layout.addWidget(self.cpu_limit_slider, 0, 1)
        self.cpu_limit_label = QLabel("50%")
        layout.addWidget(self.cpu_limit_label, 0, 2)
        
        # Memory Limit
        layout.addWidget(QLabel("Max Memory Usage:"), 1, 0)
        self.memory_limit_slider = QSlider(Qt.Horizontal)
        self.memory_limit_slider.setRange(128, 2048)
        self.memory_limit_slider.setValue(512)
        self.memory_limit_slider.valueChanged.connect(self.on_limits_changed)
        layout.addWidget(self.memory_limit_slider, 1, 1)
        self.memory_limit_label = QLabel("512 MB")
        layout.addWidget(self.memory_limit_label, 1, 2)
        
        # Thread Limit
        layout.addWidget(QLabel("Max Threads:"), 2, 0)
        self.thread_limit_slider = QSlider(Qt.Horizontal)
        self.thread_limit_slider.setRange(1, 16)
        self.thread_limit_slider.setValue(4)
        self.thread_limit_slider.valueChanged.connect(self.on_limits_changed)
        layout.addWidget(self.thread_limit_slider, 2, 1)
        self.thread_limit_label = QLabel("4")
        layout.addWidget(self.thread_limit_label, 2, 2)
        
        # Scan Rate Limit
        layout.addWidget(QLabel("Max Scan Rate:"), 3, 0)
        self.scan_rate_limit_slider = QSlider(Qt.Horizontal)
        self.scan_rate_limit_slider.setRange(10, 500)
        self.scan_rate_limit_slider.setValue(200)
        self.scan_rate_limit_slider.valueChanged.connect(self.on_limits_changed)
        layout.addWidget(self.scan_rate_limit_slider, 3, 1)
        self.scan_rate_limit_label = QLabel("200 files/sec")
        layout.addWidget(self.scan_rate_limit_label, 3, 2)
        
        return group
    
    def create_settings_section(self):
        """Create performance settings section"""
        group = QGroupBox("🔧 Performance Settings")
        layout = QVBoxLayout(group)
        
        # Optimization controls
        controls_layout = QHBoxLayout()
        
        self.optimize_memory_btn = QPushButton("🧹 Optimize Memory")
        self.optimize_memory_btn.clicked.connect(self.optimize_memory)
        self.optimize_memory_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        controls_layout.addWidget(self.optimize_memory_btn)
        
        self.reset_limits_btn = QPushButton("🔄 Reset to Defaults")
        self.reset_limits_btn.clicked.connect(self.reset_limits)
        controls_layout.addWidget(self.reset_limits_btn)
        
        controls_layout.addStretch()
        
        # Performance statistics
        self.performance_stats_label = QLabel("Performance Statistics: Collecting data...")
        self.performance_stats_label.setStyleSheet("font-size: 11px; color: #666;")
        controls_layout.addWidget(self.performance_stats_label)
        
        layout.addLayout(controls_layout)
        
        # Advanced settings
        advanced_layout = QHBoxLayout()
        
        self.throttling_enabled_cb = QCheckBox("Enable automatic throttling")
        self.throttling_enabled_cb.setChecked(True)
        self.throttling_enabled_cb.stateChanged.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.throttling_enabled_cb)
        
        self.priority_boost_cb = QCheckBox("Boost critical scan priority")
        self.priority_boost_cb.setChecked(True)
        self.priority_boost_cb.stateChanged.connect(self.on_settings_changed)
        advanced_layout.addWidget(self.priority_boost_cb)
        
        advanced_layout.addStretch()
        
        layout.addLayout(advanced_layout)
        
        # Performance alerts
        alerts_layout = QHBoxLayout()
        
        self.performance_alerts = QLabel("")
        self.performance_alerts.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        alerts_layout.addWidget(self.performance_alerts)
        
        alerts_layout.addStretch()
        
        layout.addLayout(alerts_layout)
        
        return group
    
    def init_timer(self):
        """Initialize update timer"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_performance_display)
        self.update_timer.start(1000)  # Update every second
    
    def set_performance_manager(self, performance_manager):
        """Set the performance manager instance"""
        self.performance_manager = performance_manager
        
        # Connect performance manager callbacks
        if self.performance_manager:
            self.performance_manager.add_performance_callback(self.on_performance_update)
            self.performance_manager.add_throttling_callback(self.on_throttling_event)
            
            # Load initial settings
            self.load_current_settings()
    
    def load_current_settings(self):
        """Load current performance settings"""
        try:
            if not self.performance_manager:
                return
            
            status = self.performance_manager.get_performance_status()
            
            # Update mode selection
            mode_map = {
                'maximum': 'Maximum Performance',
                'balanced': 'Balanced',
                'conservative': 'Conservative',
                'gaming': 'Gaming Mode',
                'battery': 'Battery Saver'
            }
            
            current_mode = status.get('mode', 'balanced')
            if current_mode in mode_map:
                self.mode_combo.setCurrentText(mode_map[current_mode])
            
            # Update checkboxes
            self.adaptive_scaling_cb.setChecked(status.get('adaptive_scaling', True))
            self.gaming_detection_cb.setChecked(status.get('gaming_mode_detection', True))
            
            # Update limits
            limits = status.get('limits', {})
            if limits:
                self.cpu_limit_slider.setValue(int(limits.get('max_cpu_percent', 50)))
                self.memory_limit_slider.setValue(int(limits.get('max_memory_mb', 512)))
                self.thread_limit_slider.setValue(int(limits.get('max_threads', 4)))
                self.scan_rate_limit_slider.setValue(int(limits.get('max_scan_rate', 200)))
                
                self.update_limit_labels()
            
        except Exception as e:
            self.logger.error(f"Error loading current settings: {e}")
    
    def on_mode_changed(self, mode_text):
        """Handle performance mode change"""
        try:
            mode_map = {
                'Maximum Performance': 'maximum',
                'Balanced': 'balanced',
                'Conservative': 'conservative',
                'Gaming Mode': 'gaming',
                'Battery Saver': 'battery'
            }
            
            mode = mode_map.get(mode_text, 'balanced')
            
            if self.performance_manager:
                from src.core.performance_manager import PerformanceMode
                performance_mode = PerformanceMode(mode)
                self.performance_manager.set_performance_mode(performance_mode)
            
            # Update mode description
            descriptions = {
                'Maximum Performance': 'Maximum performance with high resource usage. Best for dedicated antivirus systems.',
                'Balanced': 'Balanced performance and resource usage. Recommended for most users.',
                'Conservative': 'Minimal resource usage with reduced performance. Good for older systems.',
                'Gaming Mode': 'Optimized for gaming with minimal background activity.',
                'Battery Saver': 'Power-efficient mode for laptops and mobile devices.'
            }
            
            self.mode_description.setText(descriptions.get(mode_text, ''))
            
            # Update limits based on mode
            self.update_limits_for_mode(mode)
            
            self.performance_mode_changed.emit(mode)
            
        except Exception as e:
            self.logger.error(f"Error changing performance mode: {e}")
    
    def update_limits_for_mode(self, mode):
        """Update limit sliders based on performance mode"""
        try:
            if not self.performance_manager:
                return
            
            limits = self.performance_manager._get_default_limits()
            from src.core.performance_manager import PerformanceMode
            
            mode_enum = PerformanceMode(mode)
            if mode_enum in limits:
                mode_limits = limits[mode_enum]
                
                self.cpu_limit_slider.setValue(int(mode_limits.max_cpu_percent))
                self.memory_limit_slider.setValue(int(mode_limits.max_memory_mb))
                self.thread_limit_slider.setValue(int(mode_limits.max_threads))
                self.scan_rate_limit_slider.setValue(int(mode_limits.max_scan_rate))
                
                self.update_limit_labels()
            
        except Exception as e:
            self.logger.error(f"Error updating limits for mode: {e}")
    
    def on_limits_changed(self):
        """Handle resource limits change"""
        self.update_limit_labels()
        
        # Apply new limits to performance manager
        if self.performance_manager:
            try:
                current_limits = self.performance_manager.get_current_limits()
                if isinstance(current_limits, dict):
                    current_limits['max_cpu_percent'] = self.cpu_limit_slider.value()
                    current_limits['max_memory_mb'] = self.memory_limit_slider.value()
                    current_limits['max_threads'] = self.thread_limit_slider.value()
                    current_limits['max_scan_rate'] = self.scan_rate_limit_slider.value()
                else:
                    current_limits.max_cpu_percent = self.cpu_limit_slider.value()
                    current_limits.max_memory_mb = self.memory_limit_slider.value()
                    current_limits.max_threads = self.thread_limit_slider.value()
                    current_limits.max_scan_rate = self.scan_rate_limit_slider.value()
                
            except Exception as e:
                self.logger.error(f"Error applying new limits: {e}")
    
    def update_limit_labels(self):
        """Update limit display labels"""
        self.cpu_limit_label.setText(f"{self.cpu_limit_slider.value()}%")
        self.memory_limit_label.setText(f"{self.memory_limit_slider.value()} MB")
        self.thread_limit_label.setText(str(self.thread_limit_slider.value()))
        self.scan_rate_limit_label.setText(f"{self.scan_rate_limit_slider.value()} files/sec")
    
    def on_settings_changed(self):
        """Handle settings changes"""
        try:
            if not self.performance_manager:
                return
            
            # Update performance manager settings
            self.performance_manager.adaptive_scaling = self.adaptive_scaling_cb.isChecked()
            self.performance_manager.gaming_mode_detection = self.gaming_detection_cb.isChecked()
            
        except Exception as e:
            self.logger.error(f"Error updating settings: {e}")
    
    def update_performance_display(self):
        """Update performance monitoring display"""
        try:
            if not self.performance_manager:
                return
            
            status = self.performance_manager.get_performance_status()
            current_metrics = status.get('current_metrics', {})
            system_metrics = status.get('system_metrics', {})
            limits = status.get('limits', {})
            
            # Update current metrics
            cpu_usage = current_metrics.get('cpu_usage', 0)
            memory_usage = current_metrics.get('memory_usage', 0)
            thread_count = current_metrics.get('thread_count', 0)
            scan_rate = current_metrics.get('scan_rate', 0)
            
            # Update progress bars
            self.cpu_progress.setValue(int(cpu_usage))
            self.cpu_label.setText(f"{cpu_usage:.1f}%")
            
            self.memory_progress.setValue(int(memory_usage))
            self.memory_label.setText(f"{memory_usage:.0f} MB")
            
            self.thread_progress.setValue(thread_count)
            self.thread_label.setText(str(thread_count))
            
            self.scan_rate_progress.setValue(int(scan_rate))
            self.scan_rate_label.setText(f"{scan_rate:.0f} files/sec")
            
            # Update system metrics
            system_cpu = system_metrics.get('system_cpu', 0)
            system_memory = system_metrics.get('system_memory', 0)
            available_memory = system_metrics.get('available_memory_gb', 0)
            
            self.system_cpu_label.setText(f"System CPU: {system_cpu:.1f}%")
            self.system_memory_label.setText(f"System Memory: {system_memory:.1f}%")
            self.available_memory_label.setText(f"Available: {available_memory:.1f} GB")
            
            # Update performance statistics
            avg_metrics = status.get('average_metrics', {})
            if avg_metrics:
                avg_cpu = avg_metrics.get('avg_cpu_usage', 0)
                avg_memory = avg_metrics.get('avg_memory_usage', 0)
                sample_count = avg_metrics.get('sample_count', 0)
                
                self.performance_stats_label.setText(
                    f"5-min avg: CPU {avg_cpu:.1f}%, Memory {avg_memory:.0f}MB ({sample_count} samples)"
                )
            
            # Check for performance alerts
            self.check_performance_alerts(current_metrics, limits)
            
        except Exception as e:
            self.logger.error(f"Error updating performance display: {e}")
    
    def check_performance_alerts(self, metrics, limits):
        """Check and display performance alerts"""
        try:
            alerts = []
            
            cpu_usage = metrics.get('cpu_usage', 0)
            memory_usage = metrics.get('memory_usage', 0)
            max_cpu = limits.get('max_cpu_percent', 50)
            max_memory = limits.get('max_memory_mb', 512)
            
            if cpu_usage > max_cpu * 0.9:
                alerts.append(f"High CPU usage: {cpu_usage:.1f}%")
            
            if memory_usage > max_memory * 0.9:
                alerts.append(f"High memory usage: {memory_usage:.0f}MB")
            
            # System-wide alerts
            system_cpu = psutil.cpu_percent()
            system_memory = psutil.virtual_memory().percent
            
            if system_cpu > 90:
                alerts.append("System CPU overloaded")
            
            if system_memory > 90:
                alerts.append("System memory critical")
            
            if alerts:
                self.performance_alerts.setText("⚠️ " + " | ".join(alerts))
            else:
                self.performance_alerts.setText("")
            
        except Exception as e:
            self.logger.error(f"Error checking performance alerts: {e}")
    
    def optimize_memory(self):
        """Trigger memory optimization"""
        try:
            if self.performance_manager:
                self.performance_manager.optimize_memory_usage()
                
                # Show temporary feedback
                original_text = self.optimize_memory_btn.text()
                self.optimize_memory_btn.setText("✅ Optimized")
                self.optimize_memory_btn.setEnabled(False)
                
                # Reset button after 2 seconds
                QTimer.singleShot(2000, lambda: [
                    self.optimize_memory_btn.setText(original_text),
                    self.optimize_memory_btn.setEnabled(True)
                ])
            
        except Exception as e:
            self.logger.error(f"Error optimizing memory: {e}")
    
    def reset_limits(self):
        """Reset limits to defaults"""
        try:
            # Reset to balanced mode defaults
            self.cpu_limit_slider.setValue(50)
            self.memory_limit_slider.setValue(512)
            self.thread_limit_slider.setValue(4)
            self.scan_rate_limit_slider.setValue(200)
            
            self.update_limit_labels()
            self.on_limits_changed()
            
        except Exception as e:
            self.logger.error(f"Error resetting limits: {e}")
    
    def on_performance_update(self, data):
        """Handle performance update callback"""
        try:
            update_type = data.get('type')
            
            if update_type == 'mode_change':
                # Update UI to reflect mode change
                new_mode = data.get('new_mode', 'balanced')
                mode_map = {
                    'maximum': 'Maximum Performance',
                    'balanced': 'Balanced',
                    'conservative': 'Conservative',
                    'gaming': 'Gaming Mode',
                    'battery': 'Battery Saver'
                }
                
                if new_mode in mode_map:
                    self.mode_combo.setCurrentText(mode_map[new_mode])
            
        except Exception as e:
            self.logger.error(f"Error handling performance update: {e}")
    
    def on_throttling_event(self, data):
        """Handle throttling event callback"""
        try:
            # Handle both string and dict data types
            if isinstance(data, str):
                throttle_type = data
            else:
                throttle_type = data.get('type') if isinstance(data, dict) else str(data)
            
            if throttle_type == 'cpu_throttling':
                current_usage = data.get('current_usage', 0)
                limit = data.get('limit', 0)
                
                # Show throttling notification in system tray if available
                if hasattr(self.parent, 'system_tray') and self.parent.system_tray:
                    self.parent.system_tray.show_custom_notification(
                        "Performance Throttling",
                        f"CPU usage {current_usage:.1f}% exceeds limit {limit:.1f}%. Reducing scan speed.",
                        "warning"
                    )
            
            elif throttle_type == 'memory_optimization':
                current_usage = data.get('current_usage', 0)
                limit = data.get('limit', 0)
                
                if hasattr(self.parent, 'system_tray') and self.parent.system_tray:
                    self.parent.system_tray.show_custom_notification(
                        "Memory Optimization",
                        f"Memory usage {current_usage:.0f}MB exceeds limit {limit:.0f}MB. Optimizing resources.",
                        "warning"
                    )
            
        except Exception as e:
            self.logger.error(f"Error handling throttling event: {e}")
