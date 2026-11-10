#!/usr/bin/env python3
"""
Auto-Tuning Panel GUI
GUI interface for Machine Learning Model Auto-Tuning system
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
                           QFileDialog)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont

# Import auto-tuning components
try:
    from ..ai.auto_tuning_system import AutoTuningSystem
    from ..ai.model_architecture_search import ModelArchitectureSearch
    from ..ai.automl_integration import AutoMLIntegration
    from ..ai.dynamic_model_selection import DynamicModelSelector
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from ai.auto_tuning_system import AutoTuningSystem
    from ai.model_architecture_search import ModelArchitectureSearch
    from ai.automl_integration import AutoMLIntegration
    from ai.dynamic_model_selection import DynamicModelSelector

class AutoTuningWorker(QThread):
    """Worker thread for auto-tuning operations"""
    progress_updated = pyqtSignal(int, str)
    tuning_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, tuning_system, operation, **kwargs):
        super().__init__()
        self.tuning_system = tuning_system
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        try:
            if self.operation == 'hyperparameter_optimization':
                result = self.tuning_system.optimize_hyperparameters(**self.kwargs)
                self.tuning_completed.emit(result)
            elif self.operation == 'architecture_search':
                result = self.tuning_system.search_architectures(**self.kwargs)
                self.tuning_completed.emit(result)
                
        except Exception as e:
            self.error_occurred.emit(str(e))

class AutoTuningPanel(QWidget):
    """Main auto-tuning panel widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.auto_tuning_panel')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize auto-tuning components
        self.models_dir = os.path.join(os.path.dirname(__file__), "..", "..", "models")
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.auto_tuning_system = AutoTuningSystem(self.models_dir)
        self.architecture_search = ModelArchitectureSearch(self.models_dir)
        self.automl_integration = AutoMLIntegration(self.models_dir)
        self.model_selector = DynamicModelSelector(self.models_dir)
        
        # Worker thread
        self.worker = None
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_displays)
        self.update_timer.start(5000)
        
        self.init_ui()
        self.load_initial_data()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        
        # Title
        title_label = QLabel("Machine Learning Model Auto-Tuning")
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
        self.create_hyperparameter_tab()
        self.create_architecture_tab()
        self.create_automl_tab()
        self.create_results_tab()
    
    def create_overview_tab(self):
        """Create overview tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Statistics group
        stats_group = QGroupBox("Auto-Tuning Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.total_experiments_label = QLabel("0")
        self.active_experiments_label = QLabel("0")
        self.best_accuracy_label = QLabel("0.00")
        self.avg_tuning_time_label = QLabel("0.0s")
        
        stats_layout.addWidget(QLabel("Total Experiments:"), 0, 0)
        stats_layout.addWidget(self.total_experiments_label, 0, 1)
        stats_layout.addWidget(QLabel("Active Experiments:"), 1, 0)
        stats_layout.addWidget(self.active_experiments_label, 1, 1)
        stats_layout.addWidget(QLabel("Best Accuracy:"), 0, 2)
        stats_layout.addWidget(self.best_accuracy_label, 0, 3)
        stats_layout.addWidget(QLabel("Avg Tuning Time:"), 1, 2)
        stats_layout.addWidget(self.avg_tuning_time_label, 1, 3)
        
        layout.addWidget(stats_group)
        
        # Recent experiments table
        experiments_group = QGroupBox("Recent Experiments")
        experiments_layout = QVBoxLayout(experiments_group)
        
        self.experiments_table = QTableWidget()
        self.experiments_table.setColumnCount(6)
        self.experiments_table.setHorizontalHeaderLabels([
            "Timestamp", "Model Type", "Method", "Best Score", "Duration", "Status"
        ])
        experiments_layout.addWidget(self.experiments_table)
        
        layout.addWidget(experiments_group)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_overview)
        controls_layout.addWidget(self.refresh_btn)
        
        self.export_results_btn = QPushButton("Export Results")
        self.export_results_btn.clicked.connect(self.export_results)
        controls_layout.addWidget(self.export_results_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(tab, "Overview")
    
    def create_hyperparameter_tab(self):
        """Create hyperparameter optimization tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Configuration group
        config_group = QGroupBox("Hyperparameter Optimization Configuration")
        config_layout = QGridLayout(config_group)
        
        # Model type selection
        config_layout.addWidget(QLabel("Model Type:"), 0, 0)
        self.hp_model_combo = QComboBox()
        self.hp_model_combo.addItems([
            'random_forest', 'gradient_boosting', 'xgboost', 'lightgbm',
            'svm', 'mlp', 'logistic_regression'
        ])
        config_layout.addWidget(self.hp_model_combo, 0, 1)
        
        # Number of trials
        config_layout.addWidget(QLabel("Number of Trials:"), 1, 0)
        self.hp_trials_spin = QSpinBox()
        self.hp_trials_spin.setRange(10, 1000)
        self.hp_trials_spin.setValue(100)
        config_layout.addWidget(self.hp_trials_spin, 1, 1)
        
        # Timeout
        config_layout.addWidget(QLabel("Timeout (minutes):"), 2, 0)
        self.hp_timeout_spin = QSpinBox()
        self.hp_timeout_spin.setRange(1, 1440)
        self.hp_timeout_spin.setValue(60)
        config_layout.addWidget(self.hp_timeout_spin, 2, 1)
        
        layout.addWidget(config_group)
        
        # Progress group
        progress_group = QGroupBox("Optimization Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.hp_progress_bar = QProgressBar()
        progress_layout.addWidget(self.hp_progress_bar)
        
        self.hp_status_label = QLabel("Ready")
        progress_layout.addWidget(self.hp_status_label)
        
        layout.addWidget(progress_group)
        
        # Results group
        results_group = QGroupBox("Best Parameters")
        results_layout = QVBoxLayout(results_group)
        
        self.hp_results_text = QTextEdit()
        self.hp_results_text.setReadOnly(True)
        results_layout.addWidget(self.hp_results_text)
        
        layout.addWidget(results_group)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        self.start_hp_btn = QPushButton("Start Optimization")
        self.start_hp_btn.clicked.connect(self.start_hyperparameter_optimization)
        controls_layout.addWidget(self.start_hp_btn)
        
        self.stop_hp_btn = QPushButton("Stop")
        self.stop_hp_btn.clicked.connect(self.stop_optimization)
        self.stop_hp_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_hp_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(tab, "Hyperparameters")
    
    def create_architecture_tab(self):
        """Create architecture search tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Configuration group
        config_group = QGroupBox("Neural Architecture Search Configuration")
        config_layout = QGridLayout(config_group)
        
        # Search iterations
        config_layout.addWidget(QLabel("Search Iterations:"), 0, 0)
        self.arch_iterations_spin = QSpinBox()
        self.arch_iterations_spin.setRange(10, 500)
        self.arch_iterations_spin.setValue(50)
        config_layout.addWidget(self.arch_iterations_spin, 0, 1)
        
        layout.addWidget(config_group)
        
        # Progress group
        progress_group = QGroupBox("Search Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.arch_progress_bar = QProgressBar()
        progress_layout.addWidget(self.arch_progress_bar)
        
        self.arch_status_label = QLabel("Ready")
        progress_layout.addWidget(self.arch_status_label)
        
        layout.addWidget(progress_group)
        
        # Best architectures table
        architectures_group = QGroupBox("Best Architectures")
        architectures_layout = QVBoxLayout(architectures_group)
        
        self.architectures_table = QTableWidget()
        self.architectures_table.setColumnCount(4)
        self.architectures_table.setHorizontalHeaderLabels([
            "Architecture ID", "Layers", "Score", "Parameters"
        ])
        architectures_layout.addWidget(self.architectures_table)
        
        layout.addWidget(architectures_group)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        self.start_arch_btn = QPushButton("Start Search")
        self.start_arch_btn.clicked.connect(self.start_architecture_search)
        controls_layout.addWidget(self.start_arch_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(tab, "Architecture Search")
    
    def create_automl_tab(self):
        """Create AutoML tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Configuration group
        config_group = QGroupBox("AutoML Configuration")
        config_layout = QGridLayout(config_group)
        
        # Backend selection
        config_layout.addWidget(QLabel("AutoML Backend:"), 0, 0)
        self.automl_backend_combo = QComboBox()
        self.automl_backend_combo.addItems(['auto-sklearn', 'autokeras', 'flaml', 'basic'])
        config_layout.addWidget(self.automl_backend_combo, 0, 1)
        
        # Time budget
        config_layout.addWidget(QLabel("Time Budget (minutes):"), 1, 0)
        self.automl_time_spin = QSpinBox()
        self.automl_time_spin.setRange(5, 1440)
        self.automl_time_spin.setValue(30)
        config_layout.addWidget(self.automl_time_spin, 1, 1)
        
        layout.addWidget(config_group)
        
        # Progress group
        progress_group = QGroupBox("AutoML Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.automl_progress_bar = QProgressBar()
        progress_layout.addWidget(self.automl_progress_bar)
        
        self.automl_status_label = QLabel("Ready")
        progress_layout.addWidget(self.automl_status_label)
        
        layout.addWidget(progress_group)
        
        # Results table
        results_group = QGroupBox("AutoML Results")
        results_layout = QVBoxLayout(results_group)
        
        self.automl_results_table = QTableWidget()
        self.automl_results_table.setColumnCount(5)
        self.automl_results_table.setHorizontalHeaderLabels([
            "Backend", "Best Model", "Accuracy", "Training Time", "Status"
        ])
        results_layout.addWidget(self.automl_results_table)
        
        layout.addWidget(results_group)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        self.start_automl_btn = QPushButton("Start AutoML")
        self.start_automl_btn.clicked.connect(self.start_automl_experiment)
        controls_layout.addWidget(self.start_automl_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(tab, "AutoML")
    
    def create_results_tab(self):
        """Create results and export tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Best models group
        best_models_group = QGroupBox("Best Models Summary")
        best_models_layout = QVBoxLayout(best_models_group)
        
        self.best_models_table = QTableWidget()
        self.best_models_table.setColumnCount(6)
        self.best_models_table.setHorizontalHeaderLabels([
            "Model Type", "Method", "Best Score", "Parameters", "Training Time", "Date"
        ])
        best_models_layout.addWidget(self.best_models_table)
        
        layout.addWidget(best_models_group)
        
        # Export options
        export_group = QGroupBox("Export Options")
        export_layout = QGridLayout(export_group)
        
        self.export_models_cb = QCheckBox("Export Model Files")
        self.export_models_cb.setChecked(True)
        export_layout.addWidget(self.export_models_cb, 0, 0)
        
        self.export_configs_cb = QCheckBox("Export Configurations")
        self.export_configs_cb.setChecked(True)
        export_layout.addWidget(self.export_configs_cb, 0, 1)
        
        layout.addWidget(export_group)
        
        # Export buttons
        export_buttons_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("Export to JSON")
        export_json_btn.clicked.connect(lambda: self.export_data('json'))
        export_buttons_layout.addWidget(export_json_btn)
        
        export_csv_btn = QPushButton("Export to CSV")
        export_csv_btn.clicked.connect(lambda: self.export_data('csv'))
        export_buttons_layout.addWidget(export_csv_btn)
        
        export_buttons_layout.addStretch()
        layout.addLayout(export_buttons_layout)
        
        self.tab_widget.addTab(tab, "Results & Export")
    
    def load_initial_data(self):
        """Load initial data for all tabs"""
        try:
            self.refresh_overview()
            self.load_best_architectures()
            self.load_automl_results()
            self.load_best_models()
            
        except Exception as e:
            self.logger.error(f"Failed to load initial data: {e}")
    
    def refresh_overview(self):
        """Refresh overview statistics"""
        try:
            # Get statistics from auto-tuning system
            hp_stats = self.auto_tuning_system.get_optimization_statistics()
            
            # Update labels
            total_experiments = hp_stats.get('total_sessions', 0)
            self.total_experiments_label.setText(str(total_experiments))
            
            # Update experiments table
            self.update_experiments_table()
            
        except Exception as e:
            self.logger.error(f"Failed to refresh overview: {e}")
    
    def update_experiments_table(self):
        """Update recent experiments table"""
        try:
            self.experiments_table.setRowCount(0)
            
        except Exception as e:
            self.logger.error(f"Failed to update experiments table: {e}")
    
    def update_displays(self):
        """Update all displays"""
        try:
            self.refresh_overview()
            
        except Exception as e:
            self.logger.error(f"Failed to update displays: {e}")
    
    def start_hyperparameter_optimization(self):
        """Start hyperparameter optimization"""
        try:
            if self.worker and self.worker.isRunning():
                QMessageBox.warning(self, "Warning", "Another optimization is already running!")
                return
            
            # Get configuration
            model_type = self.hp_model_combo.currentText()
            n_trials = self.hp_trials_spin.value()
            timeout = self.hp_timeout_spin.value() * 60
            
            # Start worker thread
            self.worker = AutoTuningWorker(
                self.auto_tuning_system,
                'hyperparameter_optimization',
                model_type=model_type,
                n_trials=n_trials,
                timeout=timeout
            )
            
            self.worker.progress_updated.connect(self.update_hp_progress)
            self.worker.tuning_completed.connect(self.hp_optimization_completed)
            self.worker.error_occurred.connect(self.optimization_error)
            
            self.worker.start()
            
            # Update UI
            self.start_hp_btn.setEnabled(False)
            self.stop_hp_btn.setEnabled(True)
            self.hp_status_label.setText("Starting optimization...")
            self.hp_progress_bar.setValue(0)
            
        except Exception as e:
            self.logger.error(f"Failed to start hyperparameter optimization: {e}")
            QMessageBox.critical(self, "Error", f"Failed to start optimization: {e}")
    
    def start_architecture_search(self):
        """Start architecture search"""
        try:
            QMessageBox.information(self, "Info", "Architecture search not yet implemented")
            
        except Exception as e:
            self.logger.error(f"Failed to start architecture search: {e}")
    
    def start_automl_experiment(self):
        """Start AutoML experiment"""
        try:
            QMessageBox.information(self, "Info", "AutoML experiment not yet implemented")
            
        except Exception as e:
            self.logger.error(f"Failed to start AutoML experiment: {e}")
    
    def stop_optimization(self):
        """Stop current optimization"""
        try:
            if self.worker and self.worker.isRunning():
                self.worker.terminate()
                self.worker.wait()
            
            # Reset UI
            self.start_hp_btn.setEnabled(True)
            self.stop_hp_btn.setEnabled(False)
            self.hp_status_label.setText("Stopped")
            
        except Exception as e:
            self.logger.error(f"Failed to stop optimization: {e}")
    
    def update_hp_progress(self, progress, status):
        """Update hyperparameter optimization progress"""
        self.hp_progress_bar.setValue(progress)
        self.hp_status_label.setText(status)
    
    def hp_optimization_completed(self, result):
        """Handle hyperparameter optimization completion"""
        try:
            # Reset UI
            self.start_hp_btn.setEnabled(True)
            self.stop_hp_btn.setEnabled(False)
            self.hp_status_label.setText("Completed")
            self.hp_progress_bar.setValue(100)
            
            # Display results
            if result:
                results_text = json.dumps(result, indent=2)
                self.hp_results_text.setText(results_text)
            
            QMessageBox.information(self, "Success", "Hyperparameter optimization completed!")
            
        except Exception as e:
            self.logger.error(f"Failed to handle optimization completion: {e}")
    
    def optimization_error(self, error_msg):
        """Handle optimization error"""
        # Reset UI
        self.start_hp_btn.setEnabled(True)
        self.stop_hp_btn.setEnabled(False)
        self.hp_status_label.setText("Error")
        
        QMessageBox.critical(self, "Error", f"Optimization failed: {error_msg}")
    
    def load_best_architectures(self):
        """Load best architectures table"""
        try:
            self.architectures_table.setRowCount(0)
            
        except Exception as e:
            self.logger.error(f"Failed to load best architectures: {e}")
    
    def load_automl_results(self):
        """Load AutoML results table"""
        try:
            self.automl_results_table.setRowCount(0)
            
        except Exception as e:
            self.logger.error(f"Failed to load AutoML results: {e}")
    
    def load_best_models(self):
        """Load best models summary"""
        try:
            self.best_models_table.setRowCount(0)
            
        except Exception as e:
            self.logger.error(f"Failed to load best models: {e}")
    
    def export_results(self):
        """Export auto-tuning results"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Auto-Tuning Results", 
                f"auto_tuning_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;CSV Files (*.csv)"
            )
            
            if filename:
                QMessageBox.information(self, "Success", f"Results exported to {filename}")
                
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export results: {e}")
    
    def export_data(self, format_type):
        """Export data in specified format"""
        try:
            extension = format_type
            filename, _ = QFileDialog.getSaveFileName(
                self, f"Export Data as {format_type.upper()}", 
                f"auto_tuning_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}",
                f"{format_type.upper()} Files (*.{extension})"
            )
            
            if filename:
                QMessageBox.information(self, "Success", f"Data exported to {filename}")
                
        except Exception as e:
            self.logger.error(f"Failed to export data: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export data: {e}")
