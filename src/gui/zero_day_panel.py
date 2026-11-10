#!/usr/bin/env python3
"""
Zero-Day Detection Panel GUI
GUI interface for zero-day threat detection system
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                           QLabel, QPushButton, QTableWidget, QTableWidgetItem,
                           QComboBox, QSpinBox, QTextEdit, QProgressBar, 
                           QGroupBox, QGridLayout, QCheckBox, QMessageBox, 
                           QFileDialog, QSlider)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

# Import zero-day detection components
try:
    from ..detection.zero_day_detector import ZeroDayDetector
    from ..detection.behavioral_signature_generator import BehavioralSignatureGenerator
    from ..ai.zero_day_classifier import ZeroDayClassifier
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from detection.zero_day_detector import ZeroDayDetector
    from detection.behavioral_signature_generator import BehavioralSignatureGenerator
    from ai.zero_day_classifier import ZeroDayClassifier

class ZeroDayPanel(QWidget):
    """Main zero-day detection panel widget"""
    
    # Signals
    zero_day_detected = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.zero_day_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize zero-day components
        self.models_dir = os.path.join(os.path.dirname(__file__), "..", "..", "models")
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.zero_day_detector = ZeroDayDetector()
        self.signature_generator = BehavioralSignatureGenerator(self.models_dir)
        self.zero_day_classifier = ZeroDayClassifier(self.models_dir)
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_displays)
        self.update_timer.start(3000)
        
        # Connect callbacks
        self.zero_day_detector.add_detection_callback(self.handle_zero_day_detection)
        
        self.init_ui()
        self.load_initial_data()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Zero-Day Threat Detection")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_overview_tab()
        self.create_detection_tab()
        self.create_signatures_tab()
        self.create_classification_tab()
        self.create_settings_tab()
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Statistics group
        stats_group = QGroupBox("Zero-Day Detection Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.total_detections_label = QLabel("0")
        self.active_threats_label = QLabel("0")
        self.signatures_count_label = QLabel("0")
        self.classification_accuracy_label = QLabel("0.00%")
        
        stats_layout.addWidget(QLabel("Total Detections:"), 0, 0)
        stats_layout.addWidget(self.total_detections_label, 0, 1)
        stats_layout.addWidget(QLabel("Active Threats:"), 1, 0)
        stats_layout.addWidget(self.active_threats_label, 1, 1)
        stats_layout.addWidget(QLabel("Behavioral Signatures:"), 0, 2)
        stats_layout.addWidget(self.signatures_count_label, 0, 3)
        stats_layout.addWidget(QLabel("Classification Accuracy:"), 1, 2)
        stats_layout.addWidget(self.classification_accuracy_label, 1, 3)
        
        layout.addWidget(stats_group)
        
        # Recent detections table
        detections_group = QGroupBox("Recent Zero-Day Detections")
        detections_layout = QVBoxLayout(detections_group)
        
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(7)
        self.detections_table.setHorizontalHeaderLabels([
            "Time", "File Path", "Threat Score", "Category", "Risk Level", "Confidence", "Status"
        ])
        detections_layout.addWidget(self.detections_table)
        
        layout.addWidget(detections_group)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        self.start_monitoring_btn = QPushButton("Start Monitoring")
        self.start_monitoring_btn.clicked.connect(self.start_monitoring)
        controls_layout.addWidget(self.start_monitoring_btn)
        
        self.stop_monitoring_btn = QPushButton("Stop Monitoring")
        self.stop_monitoring_btn.clicked.connect(self.stop_monitoring)
        self.stop_monitoring_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_monitoring_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_overview)
        controls_layout.addWidget(self.refresh_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(tab, "Overview")
    
    def create_detection_tab(self):
        """Create detection configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Detection configuration
        config_group = QGroupBox("Detection Configuration")
        config_layout = QGridLayout(config_group)
        
        # Behavioral threshold
        config_layout.addWidget(QLabel("Behavioral Threshold:"), 0, 0)
        self.behavioral_threshold_slider = QSlider(Qt.Horizontal)
        self.behavioral_threshold_slider.setRange(50, 100)
        self.behavioral_threshold_slider.setValue(70)
        self.behavioral_threshold_slider.valueChanged.connect(self.update_behavioral_threshold)
        config_layout.addWidget(self.behavioral_threshold_slider, 0, 1)
        self.behavioral_threshold_label = QLabel("0.70")
        config_layout.addWidget(self.behavioral_threshold_label, 0, 2)
        
        # Zero-day threshold
        config_layout.addWidget(QLabel("Zero-Day Threshold:"), 1, 0)
        self.zero_day_threshold_slider = QSlider(Qt.Horizontal)
        self.zero_day_threshold_slider.setRange(70, 100)
        self.zero_day_threshold_slider.setValue(85)
        self.zero_day_threshold_slider.valueChanged.connect(self.update_zero_day_threshold)
        config_layout.addWidget(self.zero_day_threshold_slider, 1, 1)
        self.zero_day_threshold_label = QLabel("0.85")
        config_layout.addWidget(self.zero_day_threshold_label, 1, 2)
        
        layout.addWidget(config_group)
        
        # Behavioral patterns
        patterns_group = QGroupBox("Active Behavioral Patterns")
        patterns_layout = QVBoxLayout(patterns_group)
        
        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(6)
        self.patterns_table.setHorizontalHeaderLabels([
            "Pattern ID", "Type", "Severity", "Confidence", "Occurrences", "Last Seen"
        ])
        patterns_layout.addWidget(self.patterns_table)
        
        layout.addWidget(patterns_group)
        
        self.tab_widget.addTab(tab, "Detection")
    
    def create_signatures_tab(self):
        """Create behavioral signatures tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Signature generation
        generation_group = QGroupBox("Signature Generation")
        generation_layout = QGridLayout(generation_group)
        
        generation_layout.addWidget(QLabel("Threat Family:"), 0, 0)
        self.threat_family_combo = QComboBox()
        self.threat_family_combo.addItems([
            'unknown', 'ransomware', 'trojan', 'spyware', 'adware', 
            'rootkit', 'backdoor', 'worm', 'virus'
        ])
        generation_layout.addWidget(self.threat_family_combo, 0, 1)
        
        self.generate_signature_btn = QPushButton("Generate Signature")
        self.generate_signature_btn.clicked.connect(self.generate_signature)
        generation_layout.addWidget(self.generate_signature_btn, 0, 2)
        
        layout.addWidget(generation_group)
        
        # Signatures table
        signatures_group = QGroupBox("Behavioral Signatures")
        signatures_layout = QVBoxLayout(signatures_group)
        
        self.signatures_table = QTableWidget()
        self.signatures_table.setColumnCount(7)
        self.signatures_table.setHorizontalHeaderLabels([
            "Signature ID", "Name", "Threat Family", "Confidence", "Severity", "Usage Count", "Created"
        ])
        signatures_layout.addWidget(self.signatures_table)
        
        layout.addWidget(signatures_group)
        
        self.tab_widget.addTab(tab, "Signatures")
    
    def create_classification_tab(self):
        """Create ML classification tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Classification test
        test_group = QGroupBox("Threat Classification Test")
        test_layout = QVBoxLayout(test_group)
        
        test_controls_layout = QHBoxLayout()
        
        self.test_file_btn = QPushButton("Select Test File")
        self.test_file_btn.clicked.connect(self.select_test_file)
        test_controls_layout.addWidget(self.test_file_btn)
        
        self.classify_btn = QPushButton("Classify Threat")
        self.classify_btn.clicked.connect(self.classify_threat)
        test_controls_layout.addWidget(self.classify_btn)
        
        test_controls_layout.addStretch()
        test_layout.addLayout(test_controls_layout)
        
        self.test_file_label = QLabel("No file selected")
        test_layout.addWidget(self.test_file_label)
        
        layout.addWidget(test_group)
        
        # Classification results
        results_group = QGroupBox("Classification Results")
        results_layout = QVBoxLayout(results_group)
        
        self.classification_results_text = QTextEdit()
        self.classification_results_text.setReadOnly(True)
        results_layout.addWidget(self.classification_results_text)
        
        layout.addWidget(results_group)
        
        self.tab_widget.addTab(tab, "Classification")
    
    def create_settings_tab(self):
        """Create settings tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Detection settings
        detection_settings_group = QGroupBox("Detection Settings")
        detection_settings_layout = QGridLayout(detection_settings_group)
        
        self.enable_behavioral_cb = QCheckBox("Enable Behavioral Analysis")
        self.enable_behavioral_cb.setChecked(True)
        detection_settings_layout.addWidget(self.enable_behavioral_cb, 0, 0)
        
        self.enable_ml_cb = QCheckBox("Enable ML Classification")
        self.enable_ml_cb.setChecked(True)
        detection_settings_layout.addWidget(self.enable_ml_cb, 0, 1)
        
        layout.addWidget(detection_settings_group)
        
        # Settings controls
        settings_controls_layout = QHBoxLayout()
        
        self.save_settings_btn = QPushButton("Save Settings")
        self.save_settings_btn.clicked.connect(self.save_settings)
        settings_controls_layout.addWidget(self.save_settings_btn)
        
        settings_controls_layout.addStretch()
        layout.addLayout(settings_controls_layout)
        
        self.tab_widget.addTab(tab, "Settings")
    
    def load_initial_data(self):
        """Load initial data for all tabs"""
        try:
            self.refresh_overview()
            
        except Exception as e:
            self.logger.error(f"Failed to load initial data: {e}")
    
    def refresh_overview(self):
        """Refresh overview statistics"""
        try:
            detection_stats = self.zero_day_detector.get_detection_statistics()
            
            self.total_detections_label.setText(str(detection_stats.get('total_detections', 0)))
            self.active_threats_label.setText(str(detection_stats.get('active_patterns', 0)))
            
            signature_stats = self.signature_generator.get_signature_statistics()
            self.signatures_count_label.setText(str(signature_stats.get('total_signatures', 0)))
            
            classifier_stats = self.zero_day_classifier.get_classifier_statistics()
            avg_confidence = classifier_stats.get('average_confidence', 0.0)
            self.classification_accuracy_label.setText(f"{avg_confidence * 100:.1f}%")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh overview: {e}")
    
    def update_displays(self):
        """Update all displays"""
        try:
            self.refresh_overview()
            
        except Exception as e:
            self.logger.error(f"Failed to update displays: {e}")
    
    def start_monitoring(self):
        """Start zero-day monitoring"""
        try:
            self.zero_day_detector.start_monitoring()
            
            self.start_monitoring_btn.setEnabled(False)
            self.stop_monitoring_btn.setEnabled(True)
            
            self.status_changed.emit("started")
            QMessageBox.information(self, "Success", "Zero-day monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop zero-day monitoring"""
        try:
            self.zero_day_detector.stop_monitoring()
            
            self.start_monitoring_btn.setEnabled(True)
            self.stop_monitoring_btn.setEnabled(False)
            
            self.status_changed.emit("stopped")
            QMessageBox.information(self, "Success", "Zero-day monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
            QMessageBox.critical(self, "Error", f"Failed to stop monitoring: {e}")
    
    def update_behavioral_threshold(self, value):
        """Update behavioral threshold"""
        threshold = value / 100.0
        self.behavioral_threshold_label.setText(f"{threshold:.2f}")
        self.zero_day_detector.behavioral_threshold = threshold
    
    def update_zero_day_threshold(self, value):
        """Update zero-day threshold"""
        threshold = value / 100.0
        self.zero_day_threshold_label.setText(f"{threshold:.2f}")
        self.zero_day_detector.zero_day_threshold = threshold
    
    def generate_signature(self):
        """Generate behavioral signature"""
        try:
            threat_family = self.threat_family_combo.currentText()
            
            sample_patterns = [
                {
                    'type': 'process',
                    'process_name': 'suspicious_process.exe',
                    'activities': ['process_injection', 'anti_analysis']
                }
            ]
            
            signature = self.signature_generator.generate_signature_from_patterns(
                sample_patterns, threat_family
            )
            
            if signature:
                QMessageBox.information(self, "Success", f"Generated signature: {signature.signature_name}")
            else:
                QMessageBox.warning(self, "Warning", "Failed to generate signature")
                
        except Exception as e:
            self.logger.error(f"Failed to generate signature: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate signature: {e}")
    
    def select_test_file(self):
        """Select file for threat classification test"""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self, "Select Test File", "", "All Files (*.*)"
            )
            
            if filename:
                self.test_file_label.setText(filename)
                self.selected_test_file = filename
            
        except Exception as e:
            self.logger.error(f"Failed to select test file: {e}")
    
    def classify_threat(self):
        """Classify selected threat"""
        try:
            if not hasattr(self, 'selected_test_file'):
                QMessageBox.warning(self, "Warning", "Please select a test file first")
                return
            
            behavior_data = {
                'process': {
                    'name': os.path.basename(self.selected_test_file),
                    'command_line': f'"{self.selected_test_file}"',
                    'activities': ['file_access', 'network_activity']
                }
            }
            
            result = self.zero_day_classifier.classify_threat(behavior_data)
            
            results_text = f"""Classification Results:
Prediction: {result.prediction}
Confidence: {result.confidence:.3f}
Threat Probability: {result.threat_probability:.3f}
Model Used: {result.model_used}
Classification Time: {result.classification_time:.3f}s"""
            
            self.classification_results_text.setText(results_text)
            
        except Exception as e:
            self.logger.error(f"Failed to classify threat: {e}")
            QMessageBox.critical(self, "Error", f"Failed to classify threat: {e}")
    
    def handle_zero_day_detection(self, zero_day_threat):
        """Handle zero-day threat detection"""
        try:
            threat_data = {
                'threat_id': zero_day_threat.threat_id,
                'file_path': zero_day_threat.file_path,
                'threat_score': zero_day_threat.threat_score,
                'threat_category': zero_day_threat.threat_category,
                'risk_level': zero_day_threat.risk_level
            }
            
            self.zero_day_detected.emit(threat_data)
            self.refresh_overview()
            
        except Exception as e:
            self.logger.error(f"Failed to handle zero-day detection: {e}")
    
    def save_settings(self):
        """Save current settings"""
        try:
            settings = {
                'behavioral_threshold': self.behavioral_threshold_slider.value() / 100.0,
                'zero_day_threshold': self.zero_day_threshold_slider.value() / 100.0,
                'enable_behavioral': self.enable_behavioral_cb.isChecked(),
                'enable_ml': self.enable_ml_cb.isChecked()
            }
            
            settings_file = os.path.join(self.models_dir, "zero_day_settings.json")
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            
            QMessageBox.information(self, "Success", "Settings saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
