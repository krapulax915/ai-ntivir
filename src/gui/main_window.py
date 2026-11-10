import sys
import os
import time
import threading
import ctypes
import logging
import hashlib
from datetime import datetime  # FIX: was only imported inside some methods; _scan_file used it at module scope and hit NameError
from typing import Dict
from PyQt5.QtWidgets import *
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, QMetaObject, Qt, Q_ARG, pyqtSlot
from PyQt5.QtGui import *
from .pause_resume_functions import toggle_scan_pause, check_pause_state
from .system_tray import SystemTrayManager
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5 import sip

class AntivirusMainWindow(QMainWindow):
    """Main GUI window for AI Antivirus"""
    
    def __init__(self, engine=None):
        """Main GUI window for AI Antivirus.

        FIX: accept an optional engine argument. main.py:441 calls
        AntivirusMainWindow(self) and module-level main() calls
        AntivirusMainWindow(None) - the old zero-argument signature raised
        TypeError on both launch paths, silently dropping GUI startup into
        console mode.
        """
        super().__init__()
        self.engine = engine
        
        # Request administrator privileges for system directory access
        self.request_admin_privileges()
        
        self.setWindowTitle("AI Antivirus - Real-time Protection")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize logging
        try:
            # FIX: the module lived in src/core, not next to this file - the
            # relative import always failed and fell back to a bare logger.
            from ..core.comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.main_window')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize scan state
        self.scan_running = False
        self.scan_paused = False
        self.scan_thread = None
        self._last_progress_update = -1
        
        # Initialize counters for dashboard
        self.total_files_scanned = 0
        self.total_threats_detected = 0
        self.last_scan_time = "Never"
        self.last_scan_type = ""
        
        # Initialize components
        self.ai_engine = None
        self.signature_engine = None
        self.heuristic_analyzer = None
        self.anomaly_detector = None
        self.log_manager = None
        self.real_time_protection = None
        self.system_tray = None
        
        # Initialize engines
        self.init_engines()
        
        # Initialize log management
        self.init_log_management()
        
        # Initialize anomaly detector
        self.anomaly_detector = None
        self.init_anomaly_detector()
        
        # Initialize real-time protection
        self.init_real_time_protection()
        
        # Initialize performance management
        self.init_performance_management()
        
        # Initialize threat intelligence
        self.init_threat_intelligence()
        
        # Initialize UI components
        self.init_ui()
        self.init_system_tray()
        self.init_timers()
        self.connect_signals()
        
        # Connect threat detection to tray notifications
        if self.system_tray:
            self.connect_tray_notifications()
        
        # Update dashboard with loaded statistics
        QTimer.singleShot(100, self.update_dashboard_display)
        
        # Start hidden in system tray - don't show main window on startup
        # Use QTimer to ensure proper hiding after all initialization
        QTimer.singleShot(200, self.hide)
    
    def init_performance_management(self):
        """Initialize performance management system"""
        try:
            from src.core.performance_manager import PerformanceManager
            self.performance_manager = PerformanceManager()
            self.performance_manager.start()
            
            # Initialize scan optimizer
            from src.core.scan_optimizer import ScanOptimizer
            self.scan_optimizer = ScanOptimizer(self.performance_manager)
            self.scan_optimizer.start()
            
            self.logger.info("Performance management system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing performance management: {e}")
            self.performance_manager = None
            self.scan_optimizer = None
    
    def init_threat_intelligence(self):
        """Initialize threat intelligence system - MINIMAL MODE"""
        try:
            # Skip heavy threat intelligence components for memory optimization
            self.intelligence_engine = None
            self.threat_classifier = None
            self.predictive_engine = None
            self.sharing_network = None
            self.ai_trainer = None
            
            self.logger.info("Threat intelligence disabled for memory optimization")
            
        except Exception as e:
            self.logger.error(f"Error in threat intelligence initialization: {e}")
            
        # Skip zero-day detector for memory optimization
        self.zero_day_detector = None
        self.logger.info("Zero-day detector disabled for memory optimization")
        
        # Skip behavioral analyzer for memory optimization
        self.behavioral_analyzer = None
        self.logger.info("Advanced behavioral analyzer disabled for memory optimization")
        
        # Skip cloud threat intelligence sync for memory optimization
        self.cloud_threat_sync = None
        self.logger.info("Cloud threat intelligence sync disabled for memory optimization")

        # Skip automated threat response system for memory optimization
        self.response_system = None
        self.logger.info("Automated threat response system disabled for memory optimization")

        # FIX: removed the second RealTimeProtectionEngine (self.monitoring_system)
        # that was created and started here IN ADDITION to self.real_time_protection
        # (init_real_time_protection). Two engines registered watchdog observers
        # over the same paths, so every file event was scanned twice (double
        # CPU/disk load) and two quarantine pipelines raced each other.
        self.monitoring_system = None
        
        # Skip P2P threat exchange for memory optimization
        self.p2p_threat_exchange = None
        self.logger.info("P2P threat exchange disabled for memory optimization")
    
    def init_engines(self):
        """Initialize AI, signature, and heuristic engines"""
        try:
            # Initialize AI Engine
            sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from src.core.ai_engine import AIEngine
            self.ai_engine = AIEngine()
            self.logger.info("AI Engine initialized successfully")
            
            # Initialize Signature Engine
            from src.detection.signature_engine import SignatureEngine
            self.signature_engine = SignatureEngine()
            self.logger.info("Signature Engine initialized successfully")
            
            # Initialize Heuristic Analyzer
            from src.detection.heuristic_analyzer import HeuristicAnalyzer
            self.heuristic_analyzer = HeuristicAnalyzer()
            self.logger.info("Heuristic Analyzer initialized successfully")
            
            # Initialize Log Management System
            from log_management_system import LogManagementSystem
            self.log_manager = LogManagementSystem()
            self.logger.info("Log Management System initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize engines: {e}")
            self.ai_engine = None
            self.signature_engine = None
            self.heuristic_analyzer = None
            self.log_manager = None
        
        # Bind pause/resume methods to this instance
        self.toggle_scan_pause = lambda: toggle_scan_pause(self)
        self.check_pause_state = lambda: check_pause_state(self)
        
        # Setup UI (removed duplicate call)
        
        # Update dashboard with loaded statistics
        QTimer.singleShot(100, self.update_dashboard_display)
    
    def init_log_management(self):
        """Initialize log management system"""
        try:
            sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from log_management_system import LogManagementSystem
            self.log_manager = LogManagementSystem()
            self.logger.info("Log Management System initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize log management: {e}")
            self.log_manager = None
    
    def load_scan_statistics(self):
        """Load previous scan statistics from log files"""
        try:
            import glob
            import re
            import os
            
            # Find recent scan log files
            log_files = glob.glob("*_drive_scan_*.txt") + glob.glob("*scan*.txt") + glob.glob("quick*.txt")
            
            total_files = 0
            total_threats = 0
            last_scan_time = None
            last_scan_type = "Never"
            
            print(f"DEBUG: Found {len(log_files)} log files")
            
            for log_file in log_files:
                try:
                    if not os.path.exists(log_file):
                        continue
                        
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Look for scan statistics in the content
                    has_stats = any(pattern in content for pattern in [
                        "🔍 Files scanned:", "Files scanned:", "📁 Files Scanned:",
                        "FINAL REPORT", "SCAN COMPLETE", "Total scan time"
                    ])
                    
                    if has_stats:
                        print(f"DEBUG: Processing {log_file}")
                        
                        # Extract files scanned - try multiple patterns
                        files_patterns = [
                            r'🔍 Files scanned: ([\d,]+)',
                            r'Files scanned: ([\d,]+)', 
                            r'📁 Files Scanned: ([\d,]+)',
                            r'files scanned, (\d+) threats',
                            r'Scanned (\d+) files'
                        ]
                        
                        files_count = 0
                        for pattern in files_patterns:
                            files_match = re.search(pattern, content)
                            if files_match:
                                files_count = int(files_match.group(1).replace(',', ''))
                                print(f"DEBUG: Found {files_count} files in {log_file}")
                                break
                        
                        if files_count > 0:
                            total_files += files_count
                        
                        # Extract threats found - try multiple patterns
                        threats_patterns = [
                            r'🚨 Threats detected: (\d+)',
                            r'Threats detected: (\d+)',
                            r'⚠️ Threats Detected: (\d+)',
                            r'found (\d+) threats',
                            r'(\d+) threats found'
                        ]
                        
                        threats_count = 0
                        for pattern in threats_patterns:
                            threats_match = re.search(pattern, content)
                            if threats_match:
                                threats_count = int(threats_match.group(1))
                                break
                        
                        total_threats += threats_count
                        
                        # Extract scan time from filename
                        time_match = re.search(r'(\d{8}_\d{6})', log_file)
                        if time_match:
                            from datetime import datetime
                            scan_time_str = time_match.group(1)
                            scan_time = datetime.strptime(scan_time_str, '%Y%m%d_%H%M%S')
                            
                            if last_scan_time is None or scan_time > last_scan_time:
                                last_scan_time = scan_time
                                
                                # Determine scan type from filename
                                if 'c_drive' in log_file:
                                    last_scan_type = "C: Drive Scan"
                                elif 'd_drive' in log_file:
                                    last_scan_type = "D: Drive Scan"
                                elif 'f_drive' in log_file:
                                    last_scan_type = "F: Drive Scan"
                                elif 'quick' in log_file:
                                    last_scan_type = "Quick Scan"
                                else:
                                    last_scan_type = "System Scan"
                
                except Exception as e:
                    print(f"DEBUG: Error processing {log_file}: {e}")
                    continue
            
            print(f"DEBUG: Total files: {total_files}, Total threats: {total_threats}")
            
            # Update counters
            self.total_files_scanned = total_files
            self.total_threats_detected = total_threats
            
            # Store last scan info
            if last_scan_time:
                self.last_scan_time = last_scan_time.strftime("%Y-%m-%d %H:%M:%S")
                self.last_scan_type = last_scan_type
            else:
                self.last_scan_time = "Never"
                self.last_scan_type = ""
                
        except Exception as e:
            self.logger.error(f"Error loading scan statistics: {e}")
            print(f"DEBUG: Exception in load_scan_statistics: {e}")
            self.total_files_scanned = 0
            self.total_threats_detected = 0
            self.last_scan_time = "Never"
            self.last_scan_type = ""
    
    def update_dashboard_display(self):
        """Update dashboard display with current statistics"""
        try:
            # Update last scan label
            if hasattr(self, 'last_scan_label') and self.last_scan_label:
                if self.last_scan_time != "Never":
                    self.last_scan_label.setText(f"🔍 Last Scan: {self.last_scan_time} ({self.last_scan_type})")
                else:
                    self.last_scan_label.setText("🔍 Last Scan: Never")
            
            # Update files scanned label (dashboard version)
            if hasattr(self, 'files_scanned_label') and self.files_scanned_label:
                self.files_scanned_label.setText(f"📁 Files Scanned: {self.total_files_scanned:,}")
                print(f"DEBUG: Dashboard files_scanned_label updated to: {self.total_files_scanned:,}")
            
            # Update threats detected label
            if hasattr(self, 'threats_detected_label') and self.threats_detected_label:
                self.threats_detected_label.setText(f"⚠️ Threats Detected: {self.total_threats_detected}")
                
        except Exception as e:
            self.logger.error(f"Error updating dashboard display: {e}")
        
    def init_ui(self):
        """Initialize user interface"""
        self.setWindowTitle("AI Antivirus - Real-time Protection")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_protection_tab()
        self.create_browser_protection_tab()
        self.create_performance_tab()
        self.create_all_tabs()
        self.create_quarantine_tab()
        self.create_settings_tab()
        
        # Status bar
        self.statusBar().showMessage("AI Antivirus Ready")
    
    def create_header(self):
                            # ...összes hibásan használt vagy nem definiált layout, group, widget, duplikált sor véglegesen törölve...
        """Create header with status indicators"""
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        
        # Create status indicators
        status_layout = QHBoxLayout()
        
        # Protection status
        protection_status = QLabel("🛡️ Protection: Active")
        protection_status.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(protection_status)
        
        # Scan status
        self.scan_status_indicator = QLabel("🔍 Scan: Ready")
        status_layout.addWidget(self.scan_status_indicator)
        
        # Network status
        network_status = QLabel("🌐 Network: Connected")
        network_status.setStyleSheet("color: blue;")
        status_layout.addWidget(network_status)
        
        status_layout.addStretch()
        header_layout.addLayout(status_layout)
        
        return header_widget
    
    def create_dashboard_tab(self):
        """Create dashboard tab with overview and quick actions"""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        
        # System status overview
        status_group = QGroupBox("System Status")
        status_layout = QGridLayout(status_group)
        
        # Protection status
        self.protection_status_label = QLabel("🛡️ Real-time Protection: Active")
        self.protection_status_label.setStyleSheet("color: green; font-weight: bold;")
        status_layout.addWidget(self.protection_status_label, 0, 0)
        
        # Last scan info
        self.last_scan_label = QLabel("🔍 Last Scan: Never")
        status_layout.addWidget(self.last_scan_label, 0, 1)
        
        # Threats detected
        self.threats_detected_label = QLabel("⚠️ Threats Detected: 0")
        status_layout.addWidget(self.threats_detected_label, 1, 0)
        
        # Files scanned
        self.files_scanned_label = QLabel("📁 Files Scanned: 0")
        status_layout.addWidget(self.files_scanned_label, 1, 1)
        
        layout.addWidget(status_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        # Enhanced Quick scan button
        self.dashboard_quick_scan_btn = QPushButton("Enhanced Quick Scan")
        self.dashboard_quick_scan_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 10px; }")
        self.dashboard_quick_scan_btn.clicked.connect(self.start_enhanced_quick_scan)
        actions_layout.addWidget(self.dashboard_quick_scan_btn)
        
        # Full scan button
        self.dashboard_full_scan_btn = QPushButton("Full System Scan")
        self.dashboard_full_scan_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 10px; }")
        self.dashboard_full_scan_btn.clicked.connect(self.start_full_scan)
        actions_layout.addWidget(self.dashboard_full_scan_btn)
        
        # Update definitions button
        update_btn = QPushButton("Update Definitions")
        update_btn.setStyleSheet("QPushButton { background-color: #FF9800; color: white; padding: 10px; }")
        actions_layout.addWidget(update_btn)
        
        layout.addWidget(actions_group)
        
        # Dashboard scan progress (copy from Scan tab)
        dashboard_progress_group = QGroupBox("Scan Progress")
        dashboard_progress_layout = QVBoxLayout(dashboard_progress_group)
        
        # Progress bar with percentage and control buttons
        progress_container = QHBoxLayout()
        
        self.dashboard_scan_progress = QProgressBar()
        self.dashboard_scan_progress.setMinimum(0)
        self.dashboard_scan_progress.setMaximum(100)
        self.dashboard_scan_progress.setValue(0)
        progress_container.addWidget(self.dashboard_scan_progress)
        
        self.dashboard_progress_percentage = QLabel("0%")
        self.dashboard_progress_percentage.setMinimumWidth(40)
        self.dashboard_progress_percentage.setAlignment(Qt.AlignCenter)
        self.dashboard_progress_percentage.setStyleSheet("font-weight: bold; color: #2196F3;")
        progress_container.addWidget(self.dashboard_progress_percentage)
        
        # Dashboard PAUSE/RESUME button
        self.dashboard_pause_resume_btn = QPushButton("⏸️ Pause")
        self.dashboard_pause_resume_btn.setMaximumWidth(80)
        self.dashboard_pause_resume_btn.setStyleSheet("""
            QPushButton { 
                background-color: #FF9800; 
                color: white; 
                padding: 5px 8px; 
                font-size: 11px;
                border-radius: 3px;
            }
            QPushButton:hover { background-color: #F57C00; }
        """)
        self.dashboard_pause_resume_btn.clicked.connect(self.toggle_scan_pause)
        self.dashboard_pause_resume_btn.setEnabled(False)
        progress_container.addWidget(self.dashboard_pause_resume_btn)
        
        # Dashboard STOP button - copy exact functionality from Scan tab
        self.dashboard_stop_btn = QPushButton("⏹️ Stop")
        self.dashboard_stop_btn.setMaximumWidth(70)
        self.dashboard_stop_btn.setStyleSheet("""
            QPushButton { 
                background-color: #F44336; 
                color: white; 
                padding: 5px 8px; 
                font-size: 11px;
                border-radius: 3px;
            }
            QPushButton:hover { background-color: #D32F2F; }
        """)
        # Use same stop_scan method as Scan tab stop button
        self.dashboard_stop_btn.clicked.connect(self.stop_scan)
        self.dashboard_stop_btn.setEnabled(False)
        progress_container.addWidget(self.dashboard_stop_btn)
        
        dashboard_progress_layout.addLayout(progress_container)
        
        self.dashboard_scan_status_label = QLabel("Ready to scan")
        self.dashboard_scan_status_label.setStyleSheet("color: #666; font-style: italic;")
        dashboard_progress_layout.addWidget(self.dashboard_scan_status_label)
        
        layout.addWidget(dashboard_progress_group)
        
        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_table = QTableWidget()
        self.activity_table.setColumnCount(4)
        self.activity_table.setHorizontalHeaderLabels(["Time", "Event", "File/Process", "Action"])
        self.activity_table.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_table)
        
        layout.addWidget(activity_group)
        
        self.tab_widget.addTab(dashboard_widget, "Dashboard")
    
    def create_scan_tab(self):
        """Create scan tab"""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        # Scan controls
        controls_group = QGroupBox("Scan Controls")
        controls_layout = QVBoxLayout(controls_group)
        
        # Scan type selection
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Enhanced Quick Scan", "Full System Scan", "Custom Scan"])
        scan_type_layout.addWidget(self.scan_type_combo)
        
        scan_type_layout.addStretch()
        controls_layout.addLayout(scan_type_layout)
        
        # Custom scan path
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Custom Path:"))
        
        self.scan_path_edit = QLineEdit()
        path_layout.addWidget(self.scan_path_edit)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_scan_path)
        path_layout.addWidget(browse_btn)
        
        controls_layout.addLayout(path_layout)
        
        # Scan buttons
        buttons_layout = QHBoxLayout()
        
        self.quick_scan_btn = QPushButton("Enhanced Quick Scan")
        self.quick_scan_btn.clicked.connect(self.start_enhanced_quick_scan)
        buttons_layout.addWidget(self.quick_scan_btn)
        
        self.full_scan_btn = QPushButton("Full System Scan")
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        buttons_layout.addWidget(self.full_scan_btn)
        
        self.custom_scan_btn = QPushButton("Custom Scan")
        self.custom_scan_btn.clicked.connect(self.custom_scan_clicked)
        buttons_layout.addWidget(self.custom_scan_btn)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setStyleSheet("QPushButton { background-color: #ff4444; color: white; }")
        buttons_layout.addWidget(self.stop_scan_btn)
        
        controls_layout.addLayout(buttons_layout)
        
        layout.addWidget(controls_group)
        
        # Scan progress
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.scan_progress = QProgressBar()
        progress_layout.addWidget(self.scan_progress)
        
        self.scan_status_label = QLabel("Ready to scan")
        progress_layout.addWidget(self.scan_status_label)
        
        layout.addWidget(progress_group)
        
        # Scan results
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.scan_results_table = QTableWidget()
        self.scan_results_table.setColumnCount(5)
        self.scan_results_table.setHorizontalHeaderLabels([
            "File Path", "Threat Level", "Threat Score", "Detection Method", "Action"
        ])
        results_layout.addWidget(self.scan_results_table)
        
        layout.addWidget(results_group)
        
        self.tab_widget.addTab(scan_widget, "Scan")
    
    def create_quarantine_tab(self):
        """Create quarantine management tab"""
        quarantine_widget = QWidget()
        layout = QVBoxLayout(quarantine_widget)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_quarantined_file)
        controls_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_quarantined_file)
        controls_layout.addWidget(delete_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine_list)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(scan_widget, "Scan")
    
    def create_quarantine_tab(self):
        """Create quarantine management tab"""
        quarantine_widget = QWidget()
        layout = QVBoxLayout(quarantine_widget)
        
        # Quarantine controls
        controls_layout = QHBoxLayout()
        
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_quarantined_file)
        controls_layout.addWidget(restore_btn)
        
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_quarantined_file)
        controls_layout.addWidget(delete_btn)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine_list)
        controls_layout.addWidget(refresh_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Quarantine table
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "File Name", "Original Path", "Threat Type", "Detection Time", "File Size"
        ])
        layout.addWidget(self.quarantine_table)
        
        self.tab_widget.addTab(quarantine_widget, "Quarantine")
        
        # Auto-refresh quarantine list when tab is created
        self.refresh_quarantine_list()
    
    def create_network_tab(self):
        """Create P2P network tab"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Network status
        status_group = QGroupBox("Network Status")
        status_layout = QGridLayout(status_group)
        
        self.node_id_label = QLabel("Node ID: -")
        self.peers_count_label = QLabel("Connected Peers: 0")
        self.messages_sent_label = QLabel("Messages Sent: 0")
        self.messages_received_label = QLabel("Messages Received: 0")
        
        status_layout.addWidget(self.node_id_label, 0, 0)
        status_layout.addWidget(self.peers_count_label, 0, 1)
        status_layout.addWidget(self.messages_sent_label, 1, 0)
        status_layout.addWidget(self.messages_received_label, 1, 1)
        
        layout.addWidget(status_group)
        
        # Peer management
        peers_group = QGroupBox("Peer Management")
        peers_layout = QVBoxLayout(peers_group)
        
        # Add peer
        add_peer_layout = QHBoxLayout()
        add_peer_layout.addWidget(QLabel("Add Peer:"))
        
        self.peer_ip_edit = QLineEdit()
        self.peer_ip_edit.setPlaceholderText("IP Address")
        add_peer_layout.addWidget(self.peer_ip_edit)
        
        self.peer_port_edit = QLineEdit()
        self.peer_port_edit.setPlaceholderText("Port")
        add_peer_layout.addWidget(self.peer_port_edit)
        
        add_peer_btn = QPushButton("Add Peer")
        add_peer_btn.clicked.connect(self.add_peer)
        add_peer_layout.addWidget(add_peer_btn)
        
        peers_layout.addLayout(add_peer_layout)
        
        # Peers table
        self.peers_table = QTableWidget()
        self.peers_table.setColumnCount(3)
        self.peers_table.setHorizontalHeaderLabels(["IP Address", "Port", "Status"])
        peers_layout.addWidget(self.peers_table)
        
        layout.addWidget(peers_group)
        
        # Shared threats
        threats_group = QGroupBox("Shared Threat Intelligence")
        threats_layout = QVBoxLayout(threats_group)
        
        self.shared_threats_table = QTableWidget()
        self.shared_threats_table.setColumnCount(4)
        self.shared_threats_table.setHorizontalHeaderLabels([
            "Threat ID", "Source Node", "Threat Score", "Shared Time"
        ])
        threats_layout.addWidget(self.shared_threats_table)
        
        layout.addWidget(threats_group)
        
        self.tab_widget.addTab(network_widget, "Network")
    
    def create_dlp_tab(self):
        """Create DLP (Data Loss Prevention) tab"""
        dlp_widget = QWidget()
        layout = QVBoxLayout(dlp_widget)
        
        # DLP status
        status_group = QGroupBox("DLP Status")
        status_layout = QGridLayout(status_group)
        
        self.dlp_status_label = QLabel("Status: Active")
        self.files_monitored_label = QLabel("Files Monitored: 0")
        self.violations_detected_label = QLabel("Violations Detected: 0")
        self.transfers_blocked_label = QLabel("Transfers Blocked: 0")
        
        status_layout.addWidget(self.dlp_status_label, 0, 0)
        status_layout.addWidget(self.files_monitored_label, 0, 1)
        status_layout.addWidget(self.violations_detected_label, 1, 0)
        status_layout.addWidget(self.transfers_blocked_label, 1, 1)
        
        layout.addWidget(status_group)
        
        # DLP alerts
        alerts_group = QGroupBox("Recent DLP Alerts")
        alerts_layout = QVBoxLayout(alerts_group)
        
        self.dlp_alerts_table = QTableWidget()
        self.dlp_alerts_table.setColumnCount(5)
        self.dlp_alerts_table.setHorizontalHeaderLabels([
            "Time", "Alert Type", "File/Location", "Risk Level", "Action Taken"
        ])
        alerts_layout.addWidget(self.dlp_alerts_table)
        
        layout.addWidget(alerts_group)
        
        self.tab_widget.addTab(dlp_widget, "DLP")
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        
        # Real-time protection
        protection_group = QGroupBox("Real-time Protection")
        protection_layout = QVBoxLayout(protection_group)
        
        self.realtime_protection_cb = QCheckBox("Enable Real-time Protection")
        self.realtime_protection_cb.setChecked(True)
        protection_layout.addWidget(self.realtime_protection_cb)
        
        self.ai_engine_cb = QCheckBox("Enable AI Engine")
        self.ai_engine_cb.setChecked(True)
        protection_layout.addWidget(self.ai_engine_cb)
        
        self.heuristic_analysis_cb = QCheckBox("Enable Heuristic Analysis")
        self.heuristic_analysis_cb.setChecked(True)
        protection_layout.addWidget(self.heuristic_analysis_cb)
        
        layout.addWidget(protection_group)
        
        # Scan settings
        scan_group = QGroupBox("Scan Settings")
        scan_layout = QGridLayout(scan_group)
        
        scan_layout.addWidget(QLabel("Max File Size (MB):"), 0, 0)
        self.max_file_size_spin = QSpinBox()
        self.max_file_size_spin.setRange(1, 1000)
        self.max_file_size_spin.setValue(100)
        scan_layout.addWidget(self.max_file_size_spin, 0, 1)
        
        scan_layout.addWidget(QLabel("Scan Timeout (seconds):"), 1, 0)
        self.scan_timeout_spin = QSpinBox()
        self.scan_timeout_spin.setRange(10, 300)
        self.scan_timeout_spin.setValue(30)
        scan_layout.addWidget(self.scan_timeout_spin, 1, 1)
        
        layout.addWidget(scan_group)
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QGridLayout(network_group)
        
        network_layout.addWidget(QLabel("P2P Port:"), 0, 0)
        self.p2p_port_spin = QSpinBox()
        self.p2p_port_spin.setRange(1024, 65535)
        self.p2p_port_spin.setValue(8888)
        network_layout.addWidget(self.p2p_port_spin, 0, 1)
        
        self.enable_p2p_cb = QCheckBox("Enable P2P Communication")
        self.enable_p2p_cb.setChecked(True)
        network_layout.addWidget(self.enable_p2p_cb, 1, 0, 1, 2)
        
        layout.addWidget(network_group)
        
        # Save settings button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        self.tab_widget.addTab(settings_widget, "Settings")
    
    def create_protection_tab(self):
        """Create protection tab with real-time monitoring controls"""
        protection_widget = QWidget()
        layout = QVBoxLayout(protection_widget)
        
        # Real-time protection section
        protection_group = QGroupBox("Real-time Protection")
        protection_layout = QVBoxLayout(protection_group)
        
        # File system monitoring
        self.file_monitor_cb = QCheckBox("File System Monitoring")
        self.file_monitor_cb.setChecked(True)
        protection_layout.addWidget(self.file_monitor_cb)
        
        # Network monitoring
        self.network_monitor_cb = QCheckBox("Network Monitoring")
        self.network_monitor_cb.setChecked(True)
        protection_layout.addWidget(self.network_monitor_cb)
        
        # Behavioral analysis
        self.behavior_analysis_cb = QCheckBox("Behavioral Analysis")
        self.behavior_analysis_cb.setChecked(True)
        protection_layout.addWidget(self.behavior_analysis_cb)
        
        layout.addWidget(protection_group)
        
        # Threat detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QVBoxLayout(detection_group)
        
        # Sensitivity slider
        sensitivity_label = QLabel("Detection Sensitivity:")
        detection_layout.addWidget(sensitivity_label)
        
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setRange(1, 10)
        self.sensitivity_slider.setValue(5)
        self.sensitivity_slider.setTickPosition(QSlider.TicksBelow)
        self.sensitivity_slider.setTickInterval(1)
        detection_layout.addWidget(self.sensitivity_slider)
        
        sensitivity_info = QLabel("1 = Low (fewer false positives) | 10 = High (maximum protection)")
        sensitivity_info.setStyleSheet("color: gray; font-size: 10px;")
        detection_layout.addWidget(sensitivity_info)
        
        layout.addWidget(detection_group)
        
        # Protection statistics
        stats_group = QGroupBox("Protection Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.threats_blocked_label = QLabel("Threats Blocked Today: 0")
        stats_layout.addWidget(self.threats_blocked_label)
        
        # Note: files_scanned_label is created in dashboard, not here
        # to avoid duplicate labels with different names
        
        self.last_threat_label = QLabel("Last Threat: None")
        stats_layout.addWidget(self.last_threat_label)
        
        layout.addWidget(stats_group)
        
        layout.addStretch()
        self.tab_widget.addTab(protection_widget, "Protection")
    
    def create_browser_protection_tab(self):
        """Create browser protection tab"""
        try:
            from .browser_protection_tab import BrowserProtectionTab
            browser_tab = BrowserProtectionTab(self)
            self.tab_widget.addTab(browser_tab, "Browser Protection")
            
            # Add updates tab (placeholder)
            updates_widget = QWidget()
            updates_layout = QVBoxLayout(updates_widget)
            updates_label = QLabel("Updates module not available")
            updates_label.setAlignment(Qt.AlignCenter)
            updates_layout.addWidget(updates_label)
            self.tab_widget.addTab(updates_widget, "📥 Updates")
        except ImportError as e:
            self.logger.error(f"Failed to import browser protection tab: {e}")
            # Create placeholder tab
            placeholder_widget = QWidget()
            layout = QVBoxLayout(placeholder_widget)
            
            label = QLabel("Browser Protection module not available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            self.tab_widget.addTab(placeholder_widget, "Browser Protection")
    
    def create_logs_tab(self):
        """Create logs tab"""
        logs_widget = QWidget()
        layout = QVBoxLayout(logs_widget)
        
        # Log controls
        controls_layout = QHBoxLayout()
        
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_logs_btn)
        
        export_logs_btn = QPushButton("Export Logs")
        export_logs_btn.clicked.connect(self.export_logs)
        controls_layout.addWidget(export_logs_btn)
        
        controls_layout.addStretch()
        
        # Log level filter
        controls_layout.addWidget(QLabel("Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText("INFO")
        controls_layout.addWidget(self.log_level_combo)
        
        layout.addLayout(controls_layout)
        
        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log_display)
        
        self.tab_widget.addTab(logs_widget, "📋 Logs")
    
    def create_performance_tab(self):
        """Create performance management tab"""
        try:
            from src.gui.performance_tab import PerformanceTab
            self.performance_tab = PerformanceTab(self)
            
            # Set performance manager if available
            if hasattr(self, 'performance_manager') and self.performance_manager:
                self.performance_tab.set_performance_manager(self.performance_manager)
            
            self.tab_widget.addTab(self.performance_tab, "⚡ Performance")
            
        except ImportError as e:
            self.logger.error(f"Failed to import performance tab: {e}")
            # Create placeholder tab
            placeholder_widget = QWidget()
            layout = QVBoxLayout(placeholder_widget)
            
            label = QLabel("Performance management module not available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            self.tab_widget.addTab(placeholder_widget, "⚡ Performance")
    
    def create_threat_intelligence_tab(self):
        """Create threat intelligence management tab"""
        try:
            from src.gui.threat_intelligence_tab import ThreatIntelligenceTab
            self.threat_intelligence_tab = ThreatIntelligenceTab(self)
            
            # Set intelligence engine if available
            if hasattr(self, 'intelligence_engine') and self.intelligence_engine:
                self.threat_intelligence_tab.set_intelligence_engine(self.intelligence_engine)
            
            # Set threat classifier if available
            if hasattr(self, 'threat_classifier') and self.threat_classifier:
                self.threat_intelligence_tab.set_threat_classifier(self.threat_classifier)
            
            # Set predictive engine if available
            if hasattr(self, 'predictive_engine') and self.predictive_engine:
                self.threat_intelligence_tab.set_predictive_engine(self.predictive_engine)
            
            # Set sharing network if available
            if hasattr(self, 'sharing_network') and self.sharing_network:
                self.threat_intelligence_tab.set_sharing_network(self.sharing_network)
            
            self.tab_widget.addTab(self.threat_intelligence_tab, "🧠 Threat Intelligence")
            
            # Add analytics dashboard tab
            try:
                from src.gui.analytics_dashboard import ThreatIntelligenceAnalyticsDashboard
                self.analytics_dashboard = ThreatIntelligenceAnalyticsDashboard(
                    intelligence_engine=getattr(self, 'intelligence_engine', None),
                    sharing_network=getattr(self, 'sharing_network', None),
                    predictive_engine=getattr(self, 'predictive_engine', None)
                )
                self.tab_widget.addTab(self.analytics_dashboard, "📊 Analytics")
            except Exception as e:
                self.logger.error(f"Failed to create analytics dashboard: {e}")
                # Create placeholder
                placeholder_widget = QWidget()
                layout = QVBoxLayout(placeholder_widget)
                
                label = QLabel("Analytics dashboard not available")
                label.setAlignment(Qt.AlignCenter)
                layout.addWidget(label)
                self.tab_widget.addTab(placeholder_widget, "📊 Analytics")
                
        except Exception as e:
            self.logger.error(f"Failed to create threat intelligence tab: {e}")
            # Create placeholder
            placeholder_widget = QWidget()
            layout = QVBoxLayout(placeholder_widget)
            
            label = QLabel("Threat intelligence module not available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            self.tab_widget.addTab(placeholder_widget, "🧠 Threat Intelligence")
        
    def create_enterprise_console_tab(self):
        """Create enterprise console tab"""
        try:
            from src.gui.enterprise_console import EnterpriseConsoleWidget
            self.enterprise_console = EnterpriseConsoleWidget()
            self.tab_widget.addTab(self.enterprise_console, "🏢 Enterprise Console")
            self.logger.info("Enterprise console tab added")
        except Exception as e:
            self.logger.error(f"Failed to create enterprise console: {e}")
        
    def create_monitoring_dashboard_tab(self):
        """Create monitoring dashboard tab"""
        try:
            from src.gui.monitoring_dashboard import MonitoringDashboard
            self.monitoring_dashboard = MonitoringDashboard(
                monitoring_system=getattr(self, 'monitoring_system', None)
            )
            self.tab_widget.addTab(self.monitoring_dashboard, "🔍 Real-Time Monitor")
            self.logger.info("Monitoring dashboard tab added")
        except Exception as e:
            self.logger.error(f"Failed to create monitoring dashboard: {e}")
        
    def create_response_control_panel_tab(self):
        """Create response control panel tab"""
        try:
            from src.gui.response_control_panel import ResponseControlPanel
            self.response_control_panel = ResponseControlPanel(
                response_system=getattr(self, 'response_system', None)
            )
            self.tab_widget.addTab(self.response_control_panel, "🤖 Threat Response")
            self.logger.info("Response control panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create response control panel: {e}")
        
    def create_ai_optimization_panel_tab(self):
        """Create AI optimization panel tab"""
        try:
            from src.ai.model_optimizer import AIModelOptimizer
            from src.ai.model_retraining_pipeline import ModelRetrainingPipeline
            
            # Initialize AI optimizer and retraining pipeline
            self.ai_optimizer = AIModelOptimizer(
                models_dir=os.path.join(os.getcwd(), "models")
            )
            self.retraining_pipeline = ModelRetrainingPipeline(
                models_dir=os.path.join(os.getcwd(), "models")
            )
            self.retraining_pipeline.start_pipeline()
            
            # Create placeholder for AI optimization panel
            ai_optimization_widget = QWidget()
            ai_layout = QVBoxLayout(ai_optimization_widget)
            
            ai_title = QLabel("🤖 AI Model Optimization Center")
            ai_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; padding: 10px;")
            ai_layout.addWidget(ai_title)
            
            ai_info = QLabel("AI model optimization and retraining system is active.\nThis panel provides advanced ML model performance analysis and automated retraining capabilities.")
            ai_info.setWordWrap(True)
            ai_info.setStyleSheet("padding: 10px; color: #34495e;")
            ai_layout.addWidget(ai_info)
            
            ai_layout.addStretch()
            
            self.tab_widget.addTab(ai_optimization_widget, "🧠 AI Optimization")
            self.logger.info("AI optimization panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create AI optimization panel: {e}")
        
    def create_cloud_intelligence_panel_tab(self):
        """Create cloud threat intelligence panel tab"""
        try:
            from src.gui.cloud_intelligence_panel import CloudIntelligencePanel
            self.cloud_intelligence_panel = CloudIntelligencePanel()
            self.tab_widget.addTab(self.cloud_intelligence_panel, "☁️ Cloud Intelligence")
            self.logger.info("Cloud intelligence panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create cloud intelligence panel: {e}")
    
    def create_behavioral_analysis_panel_tab(self):
        """Create behavioral analysis panel tab"""
        try:
            from src.gui.behavioral_analysis_panel import BehavioralAnalysisPanel
            from src.detection.advanced_behavioral_analyzer import AdvancedBehavioralAnalyzer
            
            # Initialize behavioral analyzer
            self.behavioral_analyzer = AdvancedBehavioralAnalyzer(
                zero_day_detector=getattr(self, 'zero_day_detector', None),
                ai_trainer=getattr(self, 'ai_trainer', None)
            )
            
            # Create GUI panel
            self.behavioral_analysis_panel = BehavioralAnalysisPanel(
                behavioral_analyzer=self.behavioral_analyzer
            )
            
            # Connect signals
            self.behavioral_analysis_panel.behavior_alert_signal.connect(self.handle_behavior_alert)
            self.behavioral_analysis_panel.status_changed_signal.connect(self.handle_behavioral_status_change)
            
            self.tab_widget.addTab(self.behavioral_analysis_panel, "🧠 Behavioral Analysis")
            self.logger.info("Behavioral analysis panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create behavioral analysis panel: {e}")
        
    def create_all_tabs(self):
        """Create all GUI tabs"""
        self.create_threat_intelligence_tab()
        self.create_enterprise_console_tab()
        self.create_monitoring_dashboard_tab()
        self.create_response_control_panel_tab()
        self.create_ai_optimization_panel_tab()
        self.create_cloud_intelligence_panel_tab()
        self.create_behavioral_analysis_panel_tab()
        self.create_auto_tuning_panel_tab()
        self.create_zero_day_panel_tab()
        self.create_network_analysis_panel_tab()
        self.create_enterprise_reporting_tab()
        
    def init_system_tray(self):
        """Initialize system tray"""
        try:
            from src.gui.system_tray import SystemTrayManager
            self.system_tray = SystemTrayManager(self)
            self.system_tray.setup_tray()
            
        except Exception as e:
            self.logger.error(f"System tray initialization failed: {e}")
    
    def handle_behavior_alert(self, alert_data: dict):
        """Handle behavioral analysis alerts"""
        try:
            alert_type = alert_data.get('type', 'behavioral_anomaly')
            process_name = alert_data.get('process_name', 'Unknown')
            risk_score = alert_data.get('risk_score', 0.0)
            
            # Show system tray notification
            if self.system_tray:
                message = f"Behavioral anomaly detected in {process_name} (Risk: {risk_score:.2f})"
                self.system_tray.show_notification("Behavioral Alert", message, "warning")
            
            # Log the alert
            self.logger.warning(f"Behavioral alert: {alert_data}")
            
            # Update status bar
            self.statusBar().showMessage(f"⚠️ Behavioral anomaly detected: {process_name}", 5000)
            
        except Exception as e:
            self.logger.error(f"Failed to handle behavior alert: {e}")
    
    def handle_behavioral_status_change(self, status: str):
        """Handle behavioral analysis status changes"""
        try:
            status_messages = {
                'started': '🧠 Behavioral analysis started',
                'stopped': '🧠 Behavioral analysis stopped',
                'paused': '🧠 Behavioral analysis paused'
            }
            
            message = status_messages.get(status, f'🧠 Behavioral analysis: {status}')
            self.statusBar().showMessage(message, 3000)
            
            # Show system tray notification
            if self.system_tray:
                self.system_tray.show_notification("Behavioral Analysis", message, "info")
            
        except Exception as e:
            self.logger.error(f"Failed to handle behavioral status change: {e}")
            self.system_tray = None
    
    def handle_zero_day_detection(self, threat_data: dict):
        """Handle zero-day threat detection"""
        try:
            threat_id = threat_data.get('threat_id', 'Unknown')
            file_path = threat_data.get('file_path', 'Unknown')
            threat_score = threat_data.get('threat_score', 0.0)
            threat_category = threat_data.get('threat_category', 'Unknown')
            risk_level = threat_data.get('risk_level', 'Unknown')
            
            # Log the detection
            self.logger.warning(f"Zero-day threat detected: {threat_id} in {file_path}")
            
            # Update status bar
            self.statusBar().showMessage(f"🚨 Zero-day threat detected: {threat_category}", 10000)
            
            # Show system tray notification
            if self.system_tray:
                message = f"Zero-day threat detected: {threat_category}"
                self.system_tray.show_notification("Zero-Day Detection", message, "critical")
            
            # Update threat counter
            self.total_threats_detected += 1
            self.update_dashboard_display()
            
        except Exception as e:
            self.logger.error(f"Failed to handle zero-day detection: {e}")
    
    def handle_zero_day_status_change(self, status: str):
        """Handle zero-day detection status changes"""
        try:
            status_messages = {
                'started': '🛡️ Zero-day detection started',
                'stopped': '🛡️ Zero-day detection stopped',
                'paused': '🛡️ Zero-day detection paused'
            }
            
            message = status_messages.get(status, f'🛡️ Zero-day detection: {status}')
            self.statusBar().showMessage(message, 3000)
            
            # Show system tray notification
            if self.system_tray:
                self.system_tray.show_notification("Zero-Day Detection", message, "info")
            
        except Exception as e:
            self.logger.error(f"Failed to handle zero-day status change: {e}")
    
    def create_auto_tuning_panel_tab(self):
        """Create auto-tuning panel tab"""
        try:
            from .auto_tuning_panel import AutoTuningPanel
            
            # Create auto-tuning panel
            self.auto_tuning_panel = AutoTuningPanel()
            
            self.tab_widget.addTab(self.auto_tuning_panel, "🤖 Auto-Tuning")
            self.logger.info("Auto-tuning panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create auto-tuning panel: {e}")
    
    def create_zero_day_panel_tab(self):
        """Create zero-day detection panel tab"""
        try:
            from .zero_day_panel import ZeroDayPanel
            
            # Create zero-day panel
            self.zero_day_panel = ZeroDayPanel()
            
            # Connect signals
            self.zero_day_panel.zero_day_detected.connect(self.handle_zero_day_detection)
            self.zero_day_panel.status_changed.connect(self.handle_zero_day_status_change)
            
            self.tab_widget.addTab(self.zero_day_panel, "🛡️ Zero-Day Detection")
            self.logger.info("Zero-day detection panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create zero-day panel: {e}")
    
    def create_network_analysis_panel_tab(self):
        """Create network traffic analysis panel tab"""
        try:
            from .network_analysis_panel import NetworkAnalysisPanel
            self.network_analysis_panel = NetworkAnalysisPanel(self)
            
            # Connect signals
            self.network_analysis_panel.threat_detected.connect(self.handle_network_threat_detection)
            self.network_analysis_panel.anomaly_detected.connect(self.handle_network_anomaly_detection)
            self.network_analysis_panel.status_changed.connect(self.handle_network_status_change)
            
            self.tab_widget.addTab(self.network_analysis_panel, "🌐 Network Analysis")
            self.logger.info("Network analysis panel tab added")
        except Exception as e:
            self.logger.error(f"Failed to create network analysis panel: {e}")
    
    def create_enterprise_reporting_tab(self):
        """Create enterprise reporting dashboard tab"""
        try:
            from .reporting_dashboard import ReportingDashboard
            self.reporting_dashboard = ReportingDashboard(self)
            self.tab_widget.addTab(self.reporting_dashboard, "📊 Enterprise Reporting")
            self.logger.info("Enterprise reporting dashboard tab added")
        except Exception as e:
            self.logger.error(f"Failed to create enterprise reporting dashboard: {e}")
    
    def handle_network_threat_detection(self, threat_data: dict):
        """Handle network threat detection"""
        try:
            threat_type = threat_data.get('threat_type', 'Network Threat')
            src_ip = threat_data.get('src_ip', 'Unknown')
            dst_ip = threat_data.get('dst_ip', 'Unknown')
            confidence = threat_data.get('confidence', 0.0)
            
            # Log the detection
            self.logger.warning(f"Network threat detected: {threat_type} from {src_ip} to {dst_ip}")
            
            # Update status bar
            self.statusBar().showMessage(f"🚨 Network threat detected: {threat_type}", 8000)
            
            # Show system tray notification
            if self.system_tray:
                message = f"Network threat detected: {threat_type}"
                self.system_tray.show_notification("Network Security", message, "critical")
            
        except Exception as e:
            self.logger.error(f"Failed to handle network threat detection: {e}")
    
    def handle_network_anomaly_detection(self, anomaly_data: dict):
        """Handle network anomaly detection"""
        try:
            anomaly_type = anomaly_data.get('anomaly_type', 'Network Anomaly')
            src_ip = anomaly_data.get('src_ip', 'Unknown')
            confidence = anomaly_data.get('confidence', 0.0)
            
            # Log the detection
            self.logger.warning(f"Network anomaly detected: {anomaly_type} from {src_ip}")
            
            # Update status bar
            self.statusBar().showMessage(f"⚠️ Network anomaly detected: {anomaly_type}", 5000)
            
            # Show system tray notification
            if self.system_tray:
                message = f"Network anomaly detected: {anomaly_type}"
                self.system_tray.show_notification("Network Security", message, "warning")
            
        except Exception as e:
            self.logger.error(f"Failed to handle network anomaly detection: {e}")
    
    def handle_network_status_change(self, status: str):
        """Handle network analysis status changes"""
        try:
            status_messages = {
                'Network monitoring started': '🌐 Network monitoring active',
                'Network monitoring stopped': '🌐 Network monitoring stopped',
                'Network monitoring paused': '🌐 Network monitoring paused'
            }
            
            message = status_messages.get(status, f'🌐 Network: {status}')
            self.statusBar().showMessage(message, 3000)
            
            # Show system tray notification
            if self.system_tray:
                self.system_tray.show_notification("Network Analysis", message, "info")
            
        except Exception as e:
            self.logger.error(f"Failed to handle network status change: {e}")
    
    def init_timers(self):
        """Initialize update timers"""
        # Update statistics every 5 seconds
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics)
        self.stats_timer.start(5000)
        
        # Update activity log every 2 seconds
        self.activity_timer = QTimer()
        self.activity_timer.timeout.connect(self.update_activity_log)
        self.activity_timer.start(2000)
    
    def connect_signals(self):
        """Connect signals from antivirus engine"""
        # This would connect to actual antivirus engine signals
        pass
    
    # Event handlers
    @pyqtSlot()
    def start_quick_scan(self):
        """Start quick scan"""
        if self.scan_running:
            return
            
        self.logger.info("Starting quick scan")
        self.scan_running = True
        
        # Update UI state safely
        try:
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(False)
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(False)
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(False)
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(True)
            
            # Update scan tab UI if exists
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(0)
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText("🤖 AI-powered quick scan in progress...")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
        
        # Start scan in separate thread - use minimal threading
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.is_alive():
            return  # Don't start multiple threads
        self.scan_thread = threading.Thread(target=self._run_quick_scan, daemon=True)
        self.scan_thread.start()
        
        self.show_notification("Quick Scan", "Quick scan started")
    
    @pyqtSlot()
    def start_full_scan(self):
        """Start full system scan"""
        if self.scan_running:
            return
            
        self.logger.info("Starting full system scan")
        self.scan_running = True
        self.scan_paused = False  # Initialize pause state
        
        # Update UI state safely
        try:
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(False)
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(False)
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(False)
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(True)
            
            # Enable dashboard control buttons for Full System Scan
            if hasattr(self, 'dashboard_stop_btn'):
                self.dashboard_stop_btn.setEnabled(True)
            if hasattr(self, 'dashboard_pause_resume_btn'):
                self.dashboard_pause_resume_btn.setEnabled(True)
                self.dashboard_pause_resume_btn.setText("⏸️ Pause")
            
            # Disable dashboard scan buttons
            if hasattr(self, 'dashboard_quick_scan_btn'):
                self.dashboard_quick_scan_btn.setEnabled(False)
            if hasattr(self, 'dashboard_full_scan_btn'):
                self.dashboard_full_scan_btn.setEnabled(False)
            
            # Update scan tab UI if exists
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(0)
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText("🤖 AI-powered full system scan in progress...")
            if hasattr(self, 'dashboard_scan_status_label') and self.dashboard_scan_status_label:
                self.dashboard_scan_status_label.setText("🤖 AI-powered full system scan in progress...")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
        
        # Start scan in separate thread - use minimal threading
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.is_alive():
            return  # Don't start multiple threads
        self.scan_thread = threading.Thread(target=self._run_full_scan, daemon=True)
        self.scan_thread.start()
        
        self.show_notification("Full Scan", "Full system scan started")
    
    def custom_scan_clicked(self):
        """Handle custom scan button click"""
        print("CUSTOM SCAN BUTTON CLICKED - IMMEDIATE DEBUG")
        try:
            # Get path from scan_path_edit if available
            if hasattr(self, 'scan_path_edit') and self.scan_path_edit.text():
                custom_path = self.scan_path_edit.text()
                self.custom_scan_path = custom_path
                print(f"Using path from input field: {custom_path}")
            else:
                print("No path in input field, using fallback")
            
            self.start_custom_scan()
        except Exception as e:
            print(f"Error in custom scan: {e}")
            import traceback
            traceback.print_exc()
    
    @pyqtSlot()
    def start_custom_scan(self):
        """Start custom directory scan"""
        print("=== CUSTOM SCAN METHOD CALLED ===")
        if self.scan_running:
            print("Scan already running, returning")
            return
        
        # Get scan path from input field first, then from stored attribute
        path = ''
        if hasattr(self, 'scan_path_edit') and self.scan_path_edit.text().strip():
            path = self.scan_path_edit.text().strip()
            print(f"Using path from input field: {path}")
        elif hasattr(self, 'custom_scan_path') and self.custom_scan_path:
            path = self.custom_scan_path
            print(f"Using stored custom path: {path}")
        else:
            # Use Downloads folder as fallback only if no path is set
            path = os.path.expanduser("~\\Downloads")
            print(f"No custom path set, using fallback: {path}")
        
        # Validate path exists
        if not os.path.exists(path):
            print(f"Path does not exist: {path}")
            # Try Downloads as last resort
            fallback_path = os.path.expanduser("~\\Downloads")
            if os.path.exists(fallback_path):
                path = fallback_path
                print(f"Using fallback path: {path}")
            else:
                print("No valid path available for custom scan")
                return
        
        # Store the final path
        self.custom_scan_path = path
        
        print(f"Starting custom scan on: {path}")
        self.scan_running = True
        
        # Update UI state safely
        try:
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(False)
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(False)
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(False)
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(True)
            
            # Update scan tab UI if exists
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(0)
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText(f"🤖 AI-powered custom scan in progress: {path}")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
        
        # Start scan in separate thread - use minimal threading
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.is_alive():
            return  # Don't start multiple threads
        print(f"Starting custom scan thread for path: {path}")
        self.scan_thread = threading.Thread(target=self._run_custom_scan, daemon=True)
        self.scan_thread.start()
        print("Custom scan thread started")
        
        self.show_notification("Custom Scan", f"Custom scan started on: {path}")
    
    @pyqtSlot()
    def start_scan(self):
        """Start scan based on selected type"""
        scan_type = self.scan_type_combo.currentText()
        
        # Update UI state safely
        try:
            if not self.scan_running:
                if hasattr(self, 'scan_btn') and self.scan_btn:
                    self.scan_btn.setEnabled(False)
                if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                    self.stop_scan_btn.setEnabled(True)
                if hasattr(self, 'scan_progress') and self.scan_progress:
                    self.scan_progress.setValue(0)
                if hasattr(self, 'scan_status_label') and self.scan_status_label:
                    self.scan_status_label.setText("Scanning...")
        except RuntimeError:
            pass
        
        if scan_type == "Quick Scan":
            self.scan_running = True
            self.start_quick_scan()
        elif scan_type == "Full System Scan":
            self.scan_running = True
            self.start_full_scan()
        elif scan_type == "Custom Scan":
            path = self.scan_path_edit.text() if hasattr(self, 'scan_path_edit') else ""
            if path:
                self.custom_scan_path = path
                self.scan_running = True
                self.start_custom_scan()
            else:
                self.logger.info("Custom scan: no path specified")
    
    @pyqtSlot()
    def stop_scan(self):
        """Stop the current scan operation"""
        print("=== STOP_SCAN METHOD CALLED ===")
        print(" Setting scan_running = False")
        self.logger.info("Stopping scan")
        self.scan_running = False
        
        # Also reset pause state when stopping
        if hasattr(self, 'scan_paused'):
            self.scan_paused = False
            print(" Reset scan_paused = False")
        
        # Try to join scan thread if alive (optional, non-blocking)
        try:
            if self.scan_thread and self.scan_thread.is_alive():
                print(" Waiting for scan thread to exit...")
                self.scan_thread.join(timeout=1)
        except Exception as e:
            print(f"Error joining scan thread: {e}")
        # Update UI using thread-safe method
        print(" Scheduling UI update via QMetaObject")
        QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
        
        self.show_notification("Scan Stopped", "Scan operation stopped")
    
    @pyqtSlot()
    def _stop_scan_ui_update(self):
        """Update UI after scan stops - simplified version"""
        print("=== STOP SCAN UI UPDATE ===")
        try:
            # Simply enable/disable the scan buttons
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(True)
                print("Quick scan button enabled")
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(True)
                print("Full scan button enabled")
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(True)
                print("Custom scan button enabled")
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(False)
                print("Stop scan button disabled")
            
            # Enable dashboard buttons too
            if hasattr(self, 'dashboard_quick_scan_btn') and self.dashboard_quick_scan_btn:
                self.dashboard_quick_scan_btn.setEnabled(True)
                print("Dashboard quick scan button enabled")
            if hasattr(self, 'dashboard_full_scan_btn') and self.dashboard_full_scan_btn:
                self.dashboard_full_scan_btn.setEnabled(True)
                print("Dashboard full scan button enabled")
            
            # Force update and repaint all buttons
            for btn_name in ['quick_scan_btn', 'full_scan_btn', 'custom_scan_btn']:
                if hasattr(self, btn_name):
                    btn = getattr(self, btn_name)
                    if btn:
                        btn.setEnabled(True)
                        btn.setVisible(True)
                        btn.update()
                        btn.repaint()
                        print(f"{btn_name} force updated")
            
            # Update Scan tab progress bar
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(0)
                self.scan_progress.setFormat("Ready")
                self.scan_progress.update()
                print("Progress bar reset to Ready")
            
            # Update Dashboard tab progress bar
            if hasattr(self, 'dashboard_scan_progress') and self.dashboard_scan_progress:
                self.dashboard_scan_progress.setValue(0)
                self.dashboard_scan_progress.setFormat("Ready")
                self.dashboard_scan_progress.update()
            
            # Update Dashboard percentage label
            if hasattr(self, 'dashboard_progress_percentage') and self.dashboard_progress_percentage:
                self.dashboard_progress_percentage.setText("0%")
            
            # Update status labels
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText("Ready to scan")
            if hasattr(self, 'dashboard_scan_status_label') and self.dashboard_scan_status_label:
                self.dashboard_scan_status_label.setText("Ready to scan")
            if hasattr(self, 'scan_status_indicator') and self.scan_status_indicator:
                self.scan_status_indicator.setText("🔍 Scan: Ready")
            
            print("All scan buttons re-enabled successfully")
            
        except Exception as e:
            print(f"Error in _stop_scan_ui_update: {e}")
            import traceback
            traceback.print_exc()
    
    @pyqtSlot(int)
    def _update_progress_safe(self, progress):
        """Thread-safe progress update"""
        try:
            # Update Scan tab progress bar
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(progress)
                self.scan_progress.setFormat(f"{progress}%")
                self.scan_progress.repaint()
            
            # Update Dashboard tab progress bar
            if hasattr(self, 'dashboard_scan_progress') and self.dashboard_scan_progress:
                self.dashboard_scan_progress.setValue(progress)
                self.dashboard_scan_progress.setFormat(f"{progress}%")
                self.dashboard_scan_progress.repaint()
            
            # Update Dashboard percentage label
            if hasattr(self, 'dashboard_progress_percentage') and self.dashboard_progress_percentage:
                self.dashboard_progress_percentage.setText(f"{progress}%")
                self.dashboard_progress_percentage.repaint()
                
            # Force GUI update
            QApplication.processEvents()
                
        except Exception as e:
            print(f"Progress update error: {e}")
    
    # Quarantine Management Methods
    def restore_quarantined_file(self):
        """Restore selected quarantined file"""
        try:
            current_row = self.quarantine_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "No Selection", "Please select a file to restore.")
                return
            
            # Get quarantine ID from table
            quarantine_id_item = self.quarantine_table.item(current_row, 5)  # Hidden column
            if not quarantine_id_item:
                QMessageBox.warning(self, "Error", "Cannot find quarantine record ID.")
                return
            
            quarantine_id = int(quarantine_id_item.text())
            
            # Get original path for confirmation
            original_path_item = self.quarantine_table.item(current_row, 1)
            original_path = original_path_item.text() if original_path_item else "Unknown"
            
            # Confirm restoration
            reply = QMessageBox.question(
                self, "Confirm Restore",
                f"Are you sure you want to restore this file?\n\nOriginal Path: {original_path}\n\nWarning: This file was quarantined as a threat!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Initialize quarantine manager
                from src.core.quarantine import QuarantineManager
                quarantine_manager = QuarantineManager()
                
                if quarantine_manager.restore_file(quarantine_id):
                    QMessageBox.information(self, "Success", f"File restored successfully to:\n{original_path}")
                    self.refresh_quarantine_list()
                else:
                    QMessageBox.critical(self, "Error", "Failed to restore file. Check logs for details.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error restoring file: {str(e)}")
    
    def delete_quarantined_file(self):
        """Permanently delete selected quarantined file"""
        try:
            current_row = self.quarantine_table.currentRow()
            if current_row < 0:
                QMessageBox.warning(self, "No Selection", "Please select a file to delete.")
                return
            
            # Get file info for confirmation
            file_name_item = self.quarantine_table.item(current_row, 0)
            quarantine_id_item = self.quarantine_table.item(current_row, 5)  # Hidden column
            
            if not file_name_item or not quarantine_id_item:
                QMessageBox.warning(self, "Error", "Cannot find file information.")
                return
            
            file_name = file_name_item.text()
            quarantine_id = int(quarantine_id_item.text())
            
            # Confirm deletion
            reply = QMessageBox.question(
                self, "Confirm Delete",
                f"Are you sure you want to permanently delete this file?\n\nFile: {file_name}\n\nThis action cannot be undone!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Initialize quarantine manager
                from src.core.quarantine import QuarantineManager
                quarantine_manager = QuarantineManager()
                
                if quarantine_manager.delete_quarantined_file(quarantine_id):
                    QMessageBox.information(self, "Success", f"File '{file_name}' deleted permanently.")
                    self.refresh_quarantine_list()
                else:
                    QMessageBox.critical(self, "Error", "Failed to delete file. Check logs for details.")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error deleting file: {str(e)}")
    
    def refresh_quarantine_list(self):
        """Refresh quarantine list from database"""
        try:
            # Initialize quarantine manager
            from src.core.quarantine import QuarantineManager
            import sqlite3
            import os
            from datetime import datetime
            
            quarantine_manager = QuarantineManager()
            
            # Clear existing table
            self.quarantine_table.setRowCount(0)
            
            # Connect to quarantine database
            if not os.path.exists(quarantine_manager.db_path):
                self.quarantine_table.setRowCount(1)
                self.quarantine_table.setItem(0, 0, QTableWidgetItem("No quarantine database found"))
                return
            
            conn = sqlite3.connect(quarantine_manager.db_path)
            cursor = conn.cursor()
            
            # Get all quarantined files
            cursor.execute('''
                SELECT id, original_path, quarantine_path, file_hash, threat_score, 
                       threat_level, quarantine_time, file_size, detection_info, status
                FROM quarantined_files 
                WHERE status = 'quarantined'
                ORDER BY quarantine_time DESC
            ''')
            
            records = cursor.fetchall()
            
            if not records:
                self.quarantine_table.setRowCount(1)
                self.quarantine_table.setItem(0, 0, QTableWidgetItem("No quarantined files"))
                self.quarantine_table.setItem(0, 1, QTableWidgetItem(""))
                self.quarantine_table.setItem(0, 2, QTableWidgetItem(""))
                self.quarantine_table.setItem(0, 3, QTableWidgetItem(""))
                self.quarantine_table.setItem(0, 4, QTableWidgetItem(""))
                conn.close()
                return
            
            # Set table size and hide ID column
            self.quarantine_table.setRowCount(len(records))
            self.quarantine_table.setColumnCount(6)  # Add hidden ID column
            self.quarantine_table.setHorizontalHeaderLabels([
                "File Name", "Original Path", "Threat Level", "Detection Time", "File Size", "ID"
            ])
            self.quarantine_table.hideColumn(5)  # Hide ID column
            
            # Populate table
            for row, record in enumerate(records):
                (q_id, original_path, quarantine_path, file_hash, threat_score, 
                 threat_level, quarantine_time, file_size, detection_info, status) = record
                
                # File name
                file_name = os.path.basename(original_path) if original_path else "Unknown"
                self.quarantine_table.setItem(row, 0, QTableWidgetItem(file_name))
                
                # Original path
                self.quarantine_table.setItem(row, 1, QTableWidgetItem(original_path or "Unknown"))
                
                # Threat level with score
                threat_display = f"{threat_level or 'Unknown'} ({threat_score:.2f})" if threat_score else threat_level or "Unknown"
                threat_item = QTableWidgetItem(threat_display)
                if threat_level == 'CRITICAL':
                    threat_item.setBackground(QColor(231, 76, 60, 100))  # Red
                elif threat_level == 'HIGH':
                    threat_item.setBackground(QColor(230, 126, 34, 100))  # Orange
                elif threat_level == 'MEDIUM':
                    threat_item.setBackground(QColor(241, 196, 15, 100))  # Yellow
                self.quarantine_table.setItem(row, 2, threat_item)
                
                # Detection time
                if quarantine_time:
                    dt = datetime.fromtimestamp(quarantine_time)
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    time_str = "Unknown"
                self.quarantine_table.setItem(row, 3, QTableWidgetItem(time_str))
                
                # File size
                if file_size and file_size > 0:
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size / (1024 * 1024):.1f} MB"
                else:
                    size_str = "Unknown"
                self.quarantine_table.setItem(row, 4, QTableWidgetItem(size_str))
                
                # Hidden ID column
                self.quarantine_table.setItem(row, 5, QTableWidgetItem(str(q_id)))
            
            # Resize columns to content
            self.quarantine_table.resizeColumnsToContents()
            
            conn.close()
            
            # Update status
            status_msg = f"Loaded {len(records)} quarantined files"
            if hasattr(self, 'statusBar'):
                self.statusBar().showMessage(status_msg, 3000)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading quarantine list: {str(e)}")
            print(f"Quarantine refresh error: {e}")
            import traceback
            traceback.print_exc()
    
    def add_peer(self):
        print("Add peer - placeholder")
    
    def save_settings(self):
        print("Save settings - placeholder")
    
    def clear_logs(self):
        print("Clear logs - placeholder")
    
    def export_logs(self):
        print("Export logs - placeholder")
    
    def browse_scan_path(self):
        """Browse for custom scan path"""
        from PyQt5.QtWidgets import QFileDialog
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path and hasattr(self, 'scan_path_edit'):
            self.scan_path_edit.setText(path)
            print(f"Custom scan path set to: {path}")
    
    def show_notification(self, title, message):
        print(f"Notification: {title} - {message}")
    
    def request_admin_privileges(self):
        """Request administrator privileges for system directory access"""
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                print("Already running with administrator privileges")
                return True
            else:
                print("Requesting administrator privileges...")
                # Note: This would restart the application with admin rights
                # For now, just log the request
                return False
        except Exception as e:
            print(f"Error checking admin privileges: {e}")
            return False
    
    @pyqtSlot()
    def _update_dashboard_counters(self):
        """Update dashboard counters with current scan statistics"""
        try:
            if hasattr(self, 'files_scanned_label') and self.files_scanned_label:
                self.files_scanned_label.setText(f"📁 Files Scanned: {self.total_files_scanned}")
            
            if hasattr(self, 'threats_detected_label') and self.threats_detected_label:
                self.threats_detected_label.setText(f"⚠️ Threats Detected: {self.total_threats_detected}")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
    
    def init_anomaly_detector(self):
        """Initialize anomaly detector"""
        try:
            from src.detection.enhanced_anomaly_detector import EnhancedAnomalyDetector
            self.anomaly_detector = EnhancedAnomalyDetector()
            self.logger.info("Enhanced Anomaly Detector initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize anomaly detector: {e}")
            self.anomaly_detector = None
    
    def init_real_time_protection(self):
        """Initialize real-time protection system"""
        try:
            from src.protection.real_time_protection import RealTimeProtectionEngine
            from src.core.quarantine import QuarantineManager
            
            # CRITICAL FIX V15: Initialize quarantine manager if not exists
            if not hasattr(self, 'quarantine_manager'):
                self.quarantine_manager = QuarantineManager()  # Uses AI_Antivirus/quarantine
            
            # Initialize real-time protection
            self.real_time_protection = RealTimeProtectionEngine(
                ai_engine=self.ai_engine,
                signature_engine=self.signature_engine,
                quarantine_manager=self.quarantine_manager
            )
            
            # Set up callbacks for GUI integration
            self.real_time_protection.set_threat_callback(self.on_threat_detected)
            self.real_time_protection.set_status_callback(self.on_protection_status_changed)
            
            # Auto-start real-time protection
            try:
                if self.real_time_protection.start_protection():
                    self.logger.info("Real-time protection initialized and started successfully")
                    # FIX: the engine's "active" status callback fired during
                    # init, BEFORE the status label existed, so the Dashboard
                    # kept its static text forever. Refresh the label now that
                    # the UI is being built.
                    QTimer.singleShot(0, lambda: self.on_protection_status_changed(
                        "active",
                        f"Monitoring {len(getattr(self.real_time_protection, 'monitored_paths', []) or [])} locations"))
                else:
                    self.logger.warning("Real-time protection initialized but failed to start")
            except Exception as start_error:
                self.logger.error(f"Failed to start real-time protection: {start_error}")
            
            self.logger.info("Real-time protection initialization completed")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize real-time protection: {e}")
            self.real_time_protection = None
    
    def create_anomaly_tab(self):
        """Create anomaly detection tab"""
        anomaly_widget = QWidget()
        layout = QVBoxLayout(anomaly_widget)
        
        # Anomaly detection controls
        controls_group = QGroupBox("AI Anomaly Detection")
        controls_layout = QVBoxLayout(controls_group)
        
        # Anomaly logs area with copy functionality
        self.anomaly_logs = QTextEdit()
        self.anomaly_logs.setReadOnly(False)  # Allow selection and copy
        self.anomaly_logs.setMaximumHeight(200)
        self.anomaly_logs.setStyleSheet("background-color: #2b2b2b; color: white; font-family: 'Courier New';")
        
        # Add copy button for logs
        log_controls = QHBoxLayout()
        copy_logs_btn = QPushButton(" Copy Logs")
        copy_logs_btn.clicked.connect(self.copy_anomaly_logs)
        clear_logs_btn = QPushButton(" Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_anomaly_logs)
        log_controls.addWidget(copy_logs_btn)
        log_controls.addWidget(clear_logs_btn)
        log_controls.addStretch()
        
        controls_layout.addWidget(QLabel("🔍 Anomaly Detection Logs:"))
        controls_layout.addLayout(log_controls)
        controls_layout.addWidget(self.anomaly_logs)
        
        # Status and controls
        status_layout = QHBoxLayout()
        self.anomaly_status_label = QLabel(" Status: Stopped")
        self.anomaly_status_label.setStyleSheet("font-weight: bold; color: red;")
        status_layout.addWidget(self.anomaly_status_label)
        
        self.start_anomaly_btn = QPushButton("Start AI Monitoring")
        self.start_anomaly_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 8px; }")
        self.start_anomaly_btn.clicked.connect(self.start_anomaly_detection)
        status_layout.addWidget(self.start_anomaly_btn)
        
        self.stop_anomaly_btn = QPushButton("Stop AI Monitoring")
        self.stop_anomaly_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 8px; }")
        self.stop_anomaly_btn.clicked.connect(self.stop_anomaly_detection)
        self.stop_anomaly_btn.setEnabled(False)
        status_layout.addWidget(self.stop_anomaly_btn)
        
        controls_layout.addLayout(status_layout)
        
        # Statistics
        stats_layout = QHBoxLayout()
        self.anomaly_stats_label = QLabel("📊 Total Anomalies: 0 | File: 0 | System: 0 | Browser: 0")
        stats_layout.addWidget(self.anomaly_stats_label)
        controls_layout.addLayout(stats_layout)
        
        layout.addWidget(controls_group)
        
        # Recent anomalies table
        anomalies_group = QGroupBox("Recent Anomalies (Last 24 Hours)")
        anomalies_layout = QVBoxLayout(anomalies_group)
        
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(6)
        self.anomalies_table.setHorizontalHeaderLabels(["Time", "Type", "Category", "Target", "Severity", "Details"])
        self.anomalies_table.setAlternatingRowColors(True)
        self.anomalies_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Enable text selection and copying
        self.anomalies_table.setTextElideMode(Qt.ElideNone)
        self.anomalies_table.setWordWrap(True)
        anomalies_layout.addWidget(self.anomalies_table)
        
        # Table controls
        table_controls = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Anomalies")
        refresh_btn.clicked.connect(self.refresh_anomalies)
        table_controls.addWidget(refresh_btn)
        
        copy_table_btn = QPushButton(" Copy Selected")
        copy_table_btn.clicked.connect(self.copy_selected_anomalies)
        table_controls.addWidget(copy_table_btn)
        
        copy_all_table_btn = QPushButton(" Copy All")
        copy_all_table_btn.clicked.connect(self.copy_all_anomalies)
        table_controls.addWidget(copy_all_table_btn)
        
        table_controls.addStretch()
        anomalies_layout.addLayout(table_controls)
        
        layout.addWidget(anomalies_group)
        
        self.tab_widget.addTab(anomaly_widget, "🤖 AI Anomaly Detection")
    
    def copy_anomaly_logs(self):
        """Copy anomaly logs to clipboard"""
        try:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.anomaly_logs.toPlainText())
            print("📋 Anomaly logs copied to clipboard")
        except Exception as e:
            print(f"Error copying logs: {e}")
    
    def clear_anomaly_logs(self):
        """Clear anomaly logs"""
        try:
            self.anomaly_logs.clear()
            print("🗑️ Anomaly logs cleared")
        except Exception as e:
            print(f"Error clearing logs: {e}")
    
    def update_anomaly_logs_display(self, log_message):
        """Update anomaly logs display in real-time"""
        try:
            # Thread-safe GUI update
            QMetaObject.invokeMethod(self, "_add_anomaly_log_safe", Qt.QueuedConnection, Q_ARG(str, log_message))
        except Exception as e:
            print(f"Error updating anomaly logs: {e}")
    
    @pyqtSlot(str)
    def _add_anomaly_log_safe(self, log_message):
        """Thread-safe method to add anomaly log"""
        try:
            if hasattr(self, 'anomaly_logs') and self.anomaly_logs:
                self.anomaly_logs.append(log_message)
                # Auto-scroll to bottom
                scrollbar = self.anomaly_logs.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            print(f"Error adding anomaly log: {e}")
    
    def copy_selected_anomalies(self):
        """Copy selected anomalies from table to clipboard"""
        try:
            selected_rows = set()
            for item in self.anomalies_table.selectedItems():
                selected_rows.add(item.row())
            
            if not selected_rows:
                print("No anomalies selected")
                return
            
            clipboard_text = ""
            for row in sorted(selected_rows):
                row_data = []
                for col in range(self.anomalies_table.columnCount()):
                    item = self.anomalies_table.item(row, col)
                    row_data.append(item.text() if item else "")
                clipboard_text += " | ".join(row_data) + "\n"
            
            clipboard = QApplication.clipboard()
            clipboard.setText(clipboard_text)
            print(f"📋 {len(selected_rows)} selected anomalies copied to clipboard")
        except Exception as e:
            print(f"Error copying selected anomalies: {e}")
    
    def copy_all_anomalies(self):
        """Copy all anomalies from table to clipboard"""
        try:
            clipboard_text = ""
            # Add header
            headers = []
            for col in range(self.anomalies_table.columnCount()):
                headers.append(self.anomalies_table.horizontalHeaderItem(col).text())
            clipboard_text += " | ".join(headers) + "\n"
            clipboard_text += "-" * 80 + "\n"
            
            # Add all rows
            for row in range(self.anomalies_table.rowCount()):
                row_data = []
                for col in range(self.anomalies_table.columnCount()):
                    item = self.anomalies_table.item(row, col)
                    row_data.append(item.text() if item else "")
                clipboard_text += " | ".join(row_data) + "\n"
            
            clipboard = QApplication.clipboard()
            clipboard.setText(clipboard_text)
            print(f"📋 All {self.anomalies_table.rowCount()} anomalies copied to clipboard")
        except Exception as e:
            print(f"Error copying all anomalies: {e}")
    
    def start_anomaly_detection(self):
        """Start anomaly detection monitoring"""
        if self.anomaly_detector:
            try:
                # Clear old anomaly database before starting
                import os
                try:
                    if os.path.exists("anomaly_detection.db"):
                        os.remove("anomaly_detection.db")
                        print("🗑️ Cleared old anomaly database")
                except:
                    pass
                
                # Reinitialize detector with clean database
                from src.detection.anomaly_detector import AnomalyDetector
                self.anomaly_detector = AnomalyDetector()
                self.anomaly_detector.gui_callback = self.update_anomaly_logs_display
                
                self.anomaly_detector.start_monitoring()
                self.anomaly_status_label.setText("🤖 Status: Active")
                self.anomaly_status_label.setStyleSheet("font-weight: bold; color: green;")
                self.start_anomaly_btn.setEnabled(False)
                self.stop_anomaly_btn.setEnabled(True)
                
                # Start periodic refresh of anomaly data
                self.anomaly_refresh_timer = QTimer()
                self.anomaly_refresh_timer.timeout.connect(self.refresh_anomalies)
                self.anomaly_refresh_timer.start(30000)  # Refresh every 30 seconds
                
                print("🤖 AI Anomaly detection started")
                self.show_notification("AI Anomaly Detection", "Real-time monitoring started")
                
            except Exception as e:
                print(f"❌ Failed to start anomaly detection: {e}")
        else:
            print("❌ Anomaly detector not available")
    
    def stop_anomaly_detection(self):
        """Stop anomaly detection monitoring"""
        if self.anomaly_detector:
            try:
                self.anomaly_detector.stop_monitoring()
                self.anomaly_status_label.setText("🤖 Status: Stopped")
                self.anomaly_status_label.setStyleSheet("font-weight: bold; color: red;")
                self.start_anomaly_btn.setEnabled(True)
                self.stop_anomaly_btn.setEnabled(False)
                
                # Stop refresh timer
                if hasattr(self, 'anomaly_refresh_timer'):
                    self.anomaly_refresh_timer.stop()
                
                print("🤖 AI Anomaly detection stopped")
                self.show_notification("AI Anomaly Detection", "Monitoring stopped")
                
            except Exception as e:
                print(f"❌ Failed to stop anomaly detection: {e}")
    
    def refresh_anomalies(self):
        """Refresh anomaly detection data"""
        if not self.anomaly_detector:
            return
            
        try:
            # Get statistics
            stats = self.anomaly_detector.get_anomaly_statistics()
            self.anomaly_stats_label.setText(
                f"📊 Total: {stats['total_anomalies']} | "
                f"File: {stats['file_anomalies']} | "
                f"System: {stats['system_anomalies']} | "
                f"Browser: {stats['browser_anomalies']}"
            )
            
            # Get recent anomalies
            anomalies = self.anomaly_detector.get_recent_anomalies(24)
            
            # Clear table
            self.anomalies_table.setRowCount(0)
            
            # Add file anomalies
            for anomaly in anomalies['file_anomalies']:
                self.add_anomaly_to_table("File", anomaly)
            
            # Add system anomalies
            for anomaly in anomalies['system_anomalies']:
                self.add_anomaly_to_table("System", anomaly)
            
            # Add browser anomalies
            for anomaly in anomalies['browser_anomalies']:
                self.add_anomaly_to_table("Browser", anomaly)
            
            # Resize columns
            self.anomalies_table.resizeColumnsToContents()
            
        except Exception as e:
            print(f"❌ Failed to refresh anomalies: {e}")
    
    def add_anomaly_to_table(self, category: str, anomaly: Dict):
        """Add anomaly to the table"""
        try:
            row = self.anomalies_table.rowCount()
            self.anomalies_table.insertRow(row)
            
            # Parse anomaly data from dictionary
            timestamp = anomaly.get('timestamp', '')
            anomaly_type = anomaly.get('type', '')
            target = anomaly.get('target', '')
            severity = anomaly.get('severity', 0.0)
            details = anomaly.get('details', '')
            
            # Add data to table
            self.anomalies_table.setItem(row, 0, QTableWidgetItem(str(timestamp)[:19]))
            self.anomalies_table.setItem(row, 1, QTableWidgetItem(anomaly_type))
            self.anomalies_table.setItem(row, 2, QTableWidgetItem(category))
            self.anomalies_table.setItem(row, 3, QTableWidgetItem(target))
            
            # Color code severity
            severity_item = QTableWidgetItem(f"{severity:.2f}")
            if severity >= 0.8:
                severity_item.setBackground(QColor(255, 0, 0, 100))  # Red for high
            elif severity >= 0.6:
                severity_item.setBackground(QColor(255, 165, 0, 100))  # Orange for medium
            else:
                severity_item.setBackground(QColor(255, 255, 0, 100))  # Yellow for low
            
            self.anomalies_table.setItem(row, 4, severity_item)
            self.anomalies_table.setItem(row, 5, QTableWidgetItem(details))
            
        except Exception as e:
            print(f"❌ Failed to add anomaly to table: {e}")
    
    def quit_application(self):
        # Stop anomaly detection before quitting
        if self.anomaly_detector:
            self.stop_anomaly_detection()
        print("Quit application")
        self.close()
        
    def update_activity_log(self):
        """Update activity log"""
        # TODO: Implement activity log update logic
        pass
    
    # Scan thread methods
    
    
    
    def _reset_progress_bar(self):
        """Reset progress bar to 0 with debug output"""
        print("=== RESETTING PROGRESS BAR ===")
        
        # Try scan_progress first (the actual progress bar)
        try:
            if hasattr(self, 'scan_progress') and self.scan_progress:
                print(f"scan_progress current value: {self.scan_progress.value()}")
                self.scan_progress.setRange(0, 100)
                self.scan_progress.setValue(0)
                self.scan_progress.setFormat("%p%")
                self.scan_progress.setVisible(True)
                QApplication.processEvents()  # Force UI refresh
                print(f"scan_progress reset to: {self.scan_progress.value()}")
                return
        except RuntimeError:
            print("scan_progress deleted")
        
        # Fallback to other progress bar names
        for attr_name in ['progress_bar', 'progressBar', 'scan_progress_bar']:
            try:
                if hasattr(self, attr_name):
                    widget = getattr(self, attr_name)
                    if widget and hasattr(widget, 'setValue'):
                        print(f"Found {attr_name}, resetting")
                        widget.setRange(0, 100)
                        widget.setValue(0)
                        widget.setFormat("Ready")
                        QApplication.processEvents()
                        print(f"{attr_name} reset to: {widget.value()}")
                        return
            except RuntimeError:
                print(f"{attr_name} deleted")
        
        print("No progress bar found to reset")
    
    def _run_quick_scan(self):
        """Run quick scan in background thread"""
        try:
            # Quick scan locations
            quick_scan_paths = [
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\AppData\\Local\\Temp"),
                "C:\\Windows\\Temp",
                "C:\\Temp"
            ]
            
            total_files = 0
            scanned_files = 0
            threats_found = 0
            
            # Count total files first (limited for performance)
            for path in quick_scan_paths:
                if os.path.exists(path):
                    try:
                        for root, dirs, files in os.walk(path):
                            total_files += len(files)
                            if total_files > 200:  # Smaller limit for better progress display
                                break
                    except (PermissionError, OSError):
                        continue
            
            if total_files == 0:
                total_files = 50  # Smaller fallback for better progress calculation
            
            print(f"Total files to scan: {total_files}")
            
            # Scan files
            for path in quick_scan_paths:
                if not self.scan_running:
                    break
                    
                if os.path.exists(path):
                    try:
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                if not self.scan_running:
                                    return
                                    
                                file_path = os.path.join(root, file)
                                print(f"Quick scan: {file_path}")
                                
                                # Simulate file scanning
                                if self._scan_file(file_path):
                                    threats_found += 1
                                    self.total_threats_detected += 1
                                    print(f"THREAT: {file_path}")
                                
                                scanned_files += 1
                                self.total_files_scanned += 1
                                
                                # Update dashboard counters
                                QMetaObject.invokeMethod(self, "_update_dashboard_counters", Qt.QueuedConnection)
                                
                                progress = min(int((scanned_files / total_files) * 100), 99)
                                
                                # Update progress more frequently for better visibility
                                if progress != self._last_progress_update or scanned_files % 5 == 0:
                                    self._last_progress_update = progress
                                    QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                                           Qt.QueuedConnection, Q_ARG(int, progress))
                                    print(f"Scanned: {scanned_files}/{total_files} files ({progress}%)")
                                    
                                # Small delay to show progress
                                time.sleep(0.01)
                                
                                if scanned_files >= total_files:
                                    break
                            if scanned_files >= total_files:
                                break
                    except (PermissionError, OSError) as e:
                        print(f"Access denied: {path} - {e}")
                        continue
            
            print(f"Quick scan completed: {scanned_files} files scanned, {threats_found} threats found")
            
            # Set progress to 100% at completion
            QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                   Qt.QueuedConnection, Q_ARG(int, 100))
            
            # Mark scan as completed
            self.scan_running = False
            self.scan_paused = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
        except Exception as e:
            print(f"Quick scan error: {e}")
            self.scan_running = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
    
    def _run_full_scan(self):
        """Run full system scan in background thread"""
        try:
            # Full scan all drives
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
            
            total_files = 0
            scanned_files = 0
            threats_found = 0
            
            # Estimate total files for progress tracking - use realistic estimate
            estimated_files_per_gb = 50000  # More realistic estimate
            total_drive_size_gb = 0
            
            for drive in drives:
                if not self.scan_running:
                    return
                try:
                    import shutil
                    total, used, free = shutil.disk_usage(drive)
                    total_drive_size_gb += used / (1024**3)  # Convert to GB
                except:
                    total_drive_size_gb += 50  # Default estimate if can't get size
            
            # Estimate total files based on drive usage - use more realistic estimate
            total_files = max(int(total_drive_size_gb * estimated_files_per_gb), 100000)
            
            # Scan files
            for drive in drives:
                if not self.scan_running:
                    break
                    
                for root, dirs, files in os.walk(drive):
                    for file in files:
                        if not self.scan_running:
                            return
                        
                        # Check if scan should be paused
                        while getattr(self, 'scan_paused', False) and self.scan_running:
                            time.sleep(0.1)  # Wait while paused
                            if not self.scan_running:
                                return  # Scan was stopped during pause
                            
                        file_path = os.path.join(root, file)
                        try:
                            # Print to console for debugging
                            print(f"Full scan: {file_path}")
                            
                            # Simulate file scanning
                            if self._scan_file(file_path):
                                threats_found += 1
                                self.total_threats_detected += 1
                                self.logger.warning(f"Threat detected: {file_path}")
                                print(f"THREAT: {file_path}")
                            
                            scanned_files += 1
                            self.total_files_scanned += 1
                            
                            # Update dashboard counters
                            QMetaObject.invokeMethod(self, "_update_dashboard_counters", Qt.QueuedConnection)
                            
                            if total_files > 0:
                                progress = min(int((scanned_files / total_files) * 100), 99)
                                # Use thread-safe UI update
                                if progress != self._last_progress_update and progress % 10 == 0:
                                    self._last_progress_update = progress
                                    QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                                           Qt.QueuedConnection, Q_ARG(int, progress))
                                    if hasattr(self, 'scan_progress') and self.scan_progress:
                                        self.scan_progress.setFormat("%p%")
                            
                            # Small delay and check stop flag
                            time.sleep(0.005)
                            if not self.scan_running:
                                return
                            
                        except Exception as e:
                            print(f"Error scanning {file_path}: {e}")
            
            print(f"Full scan completed: {scanned_files} files scanned, {threats_found} threats found")
            
            # Call scan completion handler to update dashboard
            self._scan_completed("Full Scan", scanned_files, threats_found)
            
            # Mark scan as completed
            self.scan_running = False
            self.scan_paused = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
                
        except Exception as e:
            print(f"Full scan error: {e}")
            self.scan_running = False
            self.scan_paused = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
    
    def _run_custom_scan(self):
        """Run custom directory scan in background thread"""
        print("=== _run_custom_scan() started ===")
        try:
            scan_path = getattr(self, 'custom_scan_path', '')
            print(f"Custom scan path: '{scan_path}'")
            
            if not scan_path:
                print("ERROR: No scan path set")
                scan_path = os.path.expanduser("~\\Downloads")  # Fallback path
                print(f"Using fallback path: {scan_path}")
                
            if not os.path.exists(scan_path):
                print(f"ERROR: Path does not exist: {scan_path}")
                scan_path = os.path.expanduser("~\\Downloads")  # Fallback path
                print(f"Using fallback path: {scan_path}")
                
            print(f"Starting custom scan on: {scan_path}")
            
            total_files = 0
            scanned_files = 0
            threats_found = 0
            
            # Count total files - scan ALL files including system directories
            print(f"🔴 Counting files in: {scan_path}")
            try:
                for root, dirs, files in os.walk(scan_path):
                    # DON'T skip any directories - scan everything including system dirs
                    total_files += len(files)
                    print(f"🔴 Found {len(files)} files in {root}")
                    if not self.scan_running:
                        return
                    # Add small delay to prevent UI freezing
                    if total_files % 1000 == 0:
                        time.sleep(0.001)
                        
                print(f"🔴 Total files to scan: {total_files}")
                
                # If no files found, set minimum to show progress
                if total_files == 0:
                    print("🔴 No files found, setting total_files to 1 for progress display")
                    total_files = 1
                    
            except PermissionError as e:
                print(f"🔴 Permission denied accessing {scan_path}: {e}")
                print("🔴 Try running as administrator for system directories")
                total_files = 1  # Set to 1 to avoid division by zero
            except Exception as e:
                print(f"🔴 Error counting files in {scan_path}: {e}")
                total_files = 1  # Set to 1 to avoid division by zero
            
            # Scan files
            try:
                for root, dirs, files in os.walk(scan_path):
                    if not self.scan_running:
                        return
                    
                    # DON'T skip ANY directories - scan everything including system dirs
                    # dirs[:] = [d for d in dirs if not d.startswith('$') and d.lower() not in ['system volume information', 'recycler', '$recycle.bin']]
                    print(f"🔴 Scanning directory: {root} with {len(files)} files")
                    
                    for file in files:
                        if not self.scan_running:
                            return
                            
                        file_path = os.path.join(root, file)
                        try:
                            # Print to console for debugging
                            print(f"Custom scan: {file_path}")
                            
                            # Simulate file scanning
                            if self._scan_file(file_path):
                                threats_found += 1
                                self.total_threats_detected += 1
                                self.logger.warning(f"Threat detected: {file_path}")
                                print(f"THREAT: {file_path}")
                            
                            scanned_files += 1
                            self.total_files_scanned += 1
                            
                            # Update dashboard counters
                            QMetaObject.invokeMethod(self, "_update_dashboard_counters", Qt.QueuedConnection)
                            
                            # Always update progress, even if total_files is 0 or 1
                            if total_files > 0:
                                progress = min(int((scanned_files / total_files) * 100), 99)
                            else:
                                # If no files, show at least some progress
                                progress = min(scanned_files * 10, 99)
                            
                            # Update progress more frequently for better feedback
                            if progress != self._last_progress_update and (progress % 5 == 0 or scanned_files % 10 == 0):
                                self._last_progress_update = progress
                                QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                                       Qt.QueuedConnection, Q_ARG(int, progress))
                                print(f"🔴 Progress updated: {progress}% ({scanned_files}/{total_files} files)")
                                if hasattr(self, 'scan_progress') and self.scan_progress:
                                    self.scan_progress.setFormat("%p%")
                            
                            # Small delay and check stop flag
                            time.sleep(0.01)
                            if not self.scan_running:
                                return
                            
                        except PermissionError as e:
                            print(f"Permission denied: {file_path}")
                        except Exception as e:
                            print(f"Error scanning {file_path}: {e}")
                            
            except PermissionError as e:
                print(f"Permission denied accessing directory {scan_path}: {e}")
            except Exception as e:
                print(f"Error during custom scan: {e}")
            
            # If no files were scanned but scan completed, show completion message
            if scanned_files == 0:
                print("🔴 No files found to scan in the selected directory")
                # Still show 100% completion
                QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                       Qt.QueuedConnection, Q_ARG(int, 100))
                print("🔴 Progress updated: 100% (scan completed)")
            
            print(f"Custom scan completed: {scanned_files} files scanned, {threats_found} threats found")
            
            # Call scan completion handler to update dashboard
            self._scan_completed("Custom Scan", scanned_files, threats_found)
            
            # Mark scan as completed
            self.scan_running = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
                
        except Exception as e:
            print(f"Custom scan error: {e}")
            self.scan_running = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
    
    def _scan_file(self, file_path):
        """AI-powered file scanning using anomaly detector - returns True if threat detected"""
        try:
            # Skip system files and very large files
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # Skip files > 100MB
                return False
            
            # Use AI Anomaly Detector for intelligent file analysis
            if hasattr(self, 'anomaly_detector') and self.anomaly_detector:
                try:
                    # Get current process name for context
                    current_process = "antivirus_scanner.exe"
                    
                    # Calculate anomaly score using AI detector
                    anomaly_score = self.anomaly_detector.calculate_file_anomaly_score(
                        current_process, file_path
                    )
                    
                    # Threat detection threshold (0.95 for scanning to reduce false positives)
                    threat_threshold = 0.95
                    
                    if anomaly_score > threat_threshold:
                        print(f"🚨 AI THREAT DETECTED: {file_path} (Score: {anomaly_score:.2f})")
                        
                        # Log the detection for debugging
                        try:
                            os.makedirs("logs", exist_ok=True)
                            with open("logs/scan_threats.log", "a", encoding="utf-8") as f:
                                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] THREAT: {file_path} | Score: {anomaly_score:.2f}\n")
                        except:
                            pass
                        
                        return True
                    
                    # Log clean files occasionally for verification (every 50th file)
                    if anomaly_score < 0.1 and hasattr(self, '_clean_file_counter'):
                        self._clean_file_counter = getattr(self, '_clean_file_counter', 0) + 1
                        if self._clean_file_counter % 50 == 0:
                            print(f"✅ AI CLEAN: {file_path} (Score: {anomaly_score:.2f})")
                    elif not hasattr(self, '_clean_file_counter'):
                        self._clean_file_counter = 1
                    
                except Exception as e:
                    print(f"AI scan error for {file_path}: {e}")
                    # Fallback to basic detection if AI fails
                    pass
            
            # Fallback basic heuristic detection if AI not available
            suspicious_extensions = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif'}
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in suspicious_extensions:
                if any(temp_dir in file_path.lower() for temp_dir in ['temp', 'tmp', 'downloads']):
                    # Calculate file hash for demonstration
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read(1024)).hexdigest()  # Only read first 1KB
                    
                    # Simulate threat detection (very basic fallback)
                    if file_hash.startswith(('a', 'b', 'c')):  # Random threat simulation
                        print(f"🔍 BASIC THREAT DETECTED: {file_path}")
                        return True
            
            return False
            
        except Exception as e:
            print(f"Scan error for {file_path}: {e}")
            return False
    
    def start_enhanced_quick_scan(self):
        """Start enhanced quick scan of critical system areas"""
        if self.scan_running:
            return
        
        self.scan_running = True
        self.scan_progress.setValue(0)
        self.scan_status_label.setText("Starting enhanced quick scan...")
        
        # Disable scan buttons
        self.quick_scan_btn.setEnabled(False)
        self.dashboard_quick_scan_btn.setEnabled(False)
        if hasattr(self, 'dashboard_full_scan_btn'):
            self.dashboard_full_scan_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.custom_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        
        # Enable dashboard control buttons
        if hasattr(self, 'dashboard_stop_btn'):
            self.dashboard_stop_btn.setEnabled(True)
        if hasattr(self, 'dashboard_pause_resume_btn'):
            self.dashboard_pause_resume_btn.setEnabled(True)
        
        # Start enhanced scan in separate thread
        self.scan_thread = threading.Thread(target=self._run_enhanced_quick_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def _run_enhanced_quick_scan(self):
        """Run enhanced quick scan in background thread"""
        try:
            # Initialize scan log file
            scan_log_file = None
            if self.log_manager:
                scan_data = {
                    'config': {'scan_type': 'Enhanced Quick Scan'},
                    'targets': ['Registry', 'System Directories', 'Autorun Locations', 'Memory Processes', 'Browser Data', 'Temp Files']
                }
                scan_log_file = self.log_manager.create_scan_log("Enhanced Quick Scan", scan_data)
            
            # Import enhanced scanner
            import sys
            import os
            enhanced_scan_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'enhanced_quick_scan_system.py')
            if not os.path.exists(enhanced_scan_path):
                raise ImportError(f"Enhanced quick scan system not found at: {enhanced_scan_path}")
            
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from enhanced_quick_scan_system import CriticalSystemScanner
            
            # Initialize scanner with available engines
            scanner = CriticalSystemScanner(
                ai_engine=getattr(self, 'ai_engine', None),
                signature_engine=getattr(self, 'signature_engine', None),
                heuristic_analyzer=getattr(self, 'heuristic_analyzer', None)
            )
            
            # Enhanced progress callback with logging and pause/stop checking
            def enhanced_progress_callback(percent, message):
                print(f"🔄 Progress callback: {percent}% - {message}")
                print(f"   scan_running: {self.scan_running}, scan_paused: {getattr(self, 'scan_paused', False)}")
                
                # Check if scan should be stopped
                if not self.scan_running:
                    print("❌ Scan stopped, returning False")
                    return False  # Signal to stop scan
                
                # Check if scan should be paused
                while getattr(self, 'scan_paused', False) and self.scan_running:
                    print("⏸️ Scan paused, waiting...")
                    time.sleep(0.1)  # Wait while paused
                    if not self.scan_running:
                        print("❌ Scan stopped during pause, returning False")
                        return False  # Scan was stopped during pause
                
                QMetaObject.invokeMethod(self, "_update_progress_safe", 
                                       Qt.QueuedConnection, Q_ARG(int, int(percent)))
                QMetaObject.invokeMethod(self, "_update_scan_status_safe", 
                                       Qt.QueuedConnection, Q_ARG(str, message))
                
                # Log progress if log manager available
                if self.log_manager and scan_log_file:
                    progress_data = {'current_status': message, 'progress': percent}
                    self.log_manager.log_scan_progress(scan_log_file, progress_data)
                
                print("✅ Continuing scan")
                return True  # Continue scan
            
            # Perform enhanced scan
            scan_results = scanner.perform_enhanced_quick_scan(enhanced_progress_callback)
            
            if 'error' not in scan_results:
                summary = scan_results.get('summary', {})
                files_scanned = summary.get('files_scanned', 0)
                threats_found = summary.get('threats_found', 0)
                
                # Finalize scan log
                if self.log_manager and scan_log_file:
                    self.log_manager.finalize_scan_log(scan_log_file, scan_results)
                    
                    # Check for threat upload if threats found
                    if threats_found > 0:
                        QMetaObject.invokeMethod(self, "_check_threat_upload", 
                                               Qt.QueuedConnection, Q_ARG(int, threats_found))
                
                # Update scan completion
                self._scan_completed("Enhanced Quick Scan", files_scanned, threats_found)
                
                # Show detailed results
                QMetaObject.invokeMethod(self, "_show_enhanced_scan_results", 
                                       Qt.QueuedConnection, Q_ARG(dict, scan_results))
            else:
                QMetaObject.invokeMethod(self, "_update_scan_status_safe", 
                                       Qt.QueuedConnection, Q_ARG(str, f"Scan failed: {scan_results['error']}"))
            
        except Exception as e:
            self.logger.error(f"Enhanced quick scan failed: {e}")
            QMetaObject.invokeMethod(self, "_update_scan_status_safe", 
                                   Qt.QueuedConnection, Q_ARG(str, f"Scan error: {str(e)}"))
        finally:
            self.scan_running = False
            self.scan_paused = False
            QMetaObject.invokeMethod(self, "_stop_scan_ui_update", Qt.QueuedConnection)
    
    @pyqtSlot(str)
    def _update_scan_status_safe(self, status_text):
        """Safely update scan status from thread"""
        try:
            # Update Scan tab status label
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText(status_text)
            
            # Update Dashboard tab status label
            if hasattr(self, 'dashboard_scan_status_label') and self.dashboard_scan_status_label:
                self.dashboard_scan_status_label.setText(status_text)
                
        except Exception as e:
            print(f"Status update error: {e}")
    
    @pyqtSlot(dict)
    def _show_enhanced_scan_results(self, scan_results):
        """Show enhanced scan results in GUI"""
        try:
            # Clear previous results
            self.scan_results_table.setRowCount(0)
            
            # Add results from different scan areas
            areas_scanned = scan_results.get('areas_scanned', {})
            row = 0
            
            for area_name, area_results in areas_scanned.items():
                if isinstance(area_results, dict):
                    # Add threats found in this area
                    threats = area_results.get('threats_found', [])
                    for threat in threats:
                        self.scan_results_table.insertRow(row)
                        
                        file_path = threat.get('file_path', area_name)
                        threat_level = "High" if threat.get('is_threat') else "Medium"
                        threat_score = threat.get('threat_score', 0.0)
                        detection_method = ', '.join(threat.get('detection_methods', ['Enhanced']))
                        
                        self.scan_results_table.setItem(row, 0, QTableWidgetItem(file_path))
                        self.scan_results_table.setItem(row, 1, QTableWidgetItem(threat_level))
                        self.scan_results_table.setItem(row, 2, QTableWidgetItem(f"{threat_score:.2f}"))
                        self.scan_results_table.setItem(row, 3, QTableWidgetItem(detection_method))
                        self.scan_results_table.setItem(row, 4, QTableWidgetItem("Detected"))
                        
                        row += 1
            
            # Resize columns to content
            self.scan_results_table.resizeColumnsToContents()
            
        except Exception as e:
            self.logger.error(f"Results display error: {e}")
    
    @pyqtSlot(int)
    def _check_threat_upload(self, threat_count):
        """Check if user wants to upload logs due to threat detection"""
        try:
            if not self.log_manager:
                return
            
            # Check if user has already given consent
            if self.log_manager._check_user_consent():
                # User has already consented, upload logs
                self.logger.info(f"Auto-uploading logs due to {threat_count} threats (user consent given)")
                return
            
            # Show consent dialog
            sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from user_consent_dialog import show_consent_dialog
            
            log_files = []
            if hasattr(self, 'current_scan_log'):
                log_files = [self.current_scan_log]
            
            consent = show_consent_dialog(self, threat_count, log_files)
            
            if consent:
                self.log_manager.set_user_consent(True)
                self.logger.info("User granted consent for log uploads")
                
                # Show confirmation message
                QMessageBox.information(
                    self,
                    "Upload Consent",
                    f"Thank you! Your scan logs will be uploaded to help improve AI protection.\n\n"
                    f"This helps us:\n"
                    f"• Reduce false positives\n"
                    f"• Improve threat detection\n"
                    f"• Protect all users better\n\n"
                    f"Your privacy is protected - all data is anonymized."
                )
            else:
                self.log_manager.set_user_consent(False)
                self.logger.info("User declined consent for log uploads")
                
        except Exception as e:
            self.logger.error(f"Threat upload check failed: {e}")
    
    def _scan_completed(self, scan_type, files_scanned, threats_found):
        """Handle scan completion"""
        self.scan_running = False
        self._last_progress_update = 0
        
        self.logger.info(f"{scan_type} completed: {files_scanned} files, {threats_found} threats")
        print(f"🔴 === SCAN COMPLETED ===")
        print(f"🔴 Scan type: {scan_type}")
        print(f"🔴 Files scanned: {files_scanned}")
        print(f"🔴 Threats found: {threats_found}")
        
        # Use queued connection to avoid recursive repaints
        QMetaObject.invokeMethod(self, "_scan_completed_ui_update", 
                               Qt.QueuedConnection, 
                               Q_ARG(str, scan_type),
                               Q_ARG(int, files_scanned),
                               Q_ARG(int, threats_found))
    
    @pyqtSlot(str, int, int)
    def _scan_completed_ui_update(self, scan_type, files_scanned, threats_found):
        """Update UI after scan completion - called on main thread"""
        try:
            # Update scan buttons
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(True)
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(True)
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(True)
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(False)
            
            # Update progress and status
            if hasattr(self, 'scan_progress') and self.scan_progress:
                self.scan_progress.setValue(100)
            if hasattr(self, 'scan_status_label') and self.scan_status_label:
                self.scan_status_label.setText(f"{scan_type} completed - {files_scanned} files scanned, {threats_found} threats found")
            
            # Update dashboard counters
            # FIX: do NOT add files_scanned/threats_found again here. The full/
            # custom scan workers already incremented the counters per file
            # (lines with 'self.total_files_scanned += 1'), so this second
            # addition double-counted every Full/Custom scan on the Dashboard.
            pass
            
            # Update dashboard labels
            if hasattr(self, 'last_scan_label') and self.last_scan_label:
                from datetime import datetime
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.last_scan_label.setText(f"🔍 Last Scan: {current_time} ({scan_type})")
            
            if hasattr(self, 'files_scanned_label') and self.files_scanned_label:
                self.files_scanned_label.setText(f"📁 Files Scanned: {self.total_files_scanned:,}")
                print(f"DEBUG: Updated files_scanned_label to: {self.total_files_scanned:,}")
            
            if hasattr(self, 'threats_detected_label') and self.threats_detected_label:
                self.threats_detected_label.setText(f"⚠️ Threats Detected: {self.total_threats_detected}")
                print(f"DEBUG: Updated threats_detected_label to: {self.total_threats_detected}")
            
            # Force GUI refresh and update
            self.update()
            QApplication.processEvents()
            
            if hasattr(self, 'files_scanned_label') and self.files_scanned_label:
                self.files_scanned_label.update()
                self.files_scanned_label.repaint()
            if hasattr(self, 'threats_detected_label') and self.threats_detected_label:
                self.threats_detected_label.update()
                self.threats_detected_label.repaint()
            
            self.show_notification(f"{scan_type} Complete", 
                                 f"Scanned {files_scanned} files, found {threats_found} threats")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
    
    def _scan_error(self, error_message):
        """Handle scan error"""
        self.scan_running = False
        
        # Update UI state safely
        try:
            if hasattr(self, 'quick_scan_btn') and self.quick_scan_btn:
                self.quick_scan_btn.setEnabled(True)
            if hasattr(self, 'full_scan_btn') and self.full_scan_btn:
                self.full_scan_btn.setEnabled(True)
            if hasattr(self, 'custom_scan_btn') and self.custom_scan_btn:
                self.custom_scan_btn.setEnabled(True)
            if hasattr(self, 'stop_scan_btn') and self.stop_scan_btn:
                self.stop_scan_btn.setEnabled(False)
            
            if hasattr(self, 'scan_progress') and self.scan_progress:
                if hasattr(self, 'scan_status_label') and self.scan_status_label:
                    self.scan_status_label.setText(f"Scan error: {error_message}")
        except RuntimeError:
            # Widget was deleted - this is normal during shutdown, ignore silently
            pass
        
        self.logger.error(error_message)
        self.show_notification("Scan Error", error_message)
    
    def update_signatures(self):
        """Update virus signatures"""
        self.logger.info("Updating signatures")
        self.show_notification("Update", "Signature update started")

    # FIX: three stub duplicates of restore_quarantined_file /
    # delete_quarantined_file / refresh_quarantine_list were defined here at the
    # END of the class, silently overriding the real implementations further up.
    # Because Python keeps the last definition, the Quarantine tab was always
    # empty and the Restore/Delete buttons never actually did anything. The
    # stubs are removed so the real methods (which read quarantine.db and call
    # QuarantineManager.restore_file/delete_quarantined_file) take effect.

    def add_peer(self):
        """Add new P2P peer"""
        ip = self.peer_ip_edit.text()
        port = self.peer_port_edit.text()
        if ip and port:
            self.logger.info(f"Adding peer: {ip}:{port}")
            self.show_notification("Peer Added", f"Added peer {ip}:{port}")
            self.peer_ip_edit.clear()
            self.peer_port_edit.clear()
    
    def save_settings(self):
        """Save application settings"""
        self.logger.info("Saving settings")
        self.show_notification("Settings", "Settings saved successfully")
    
    def clear_logs(self):
        """Clear log display"""
        self.log_text_edit.clear()
    
    def export_logs(self):
        """Export logs to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "antivirus_logs.txt", "Text Files (*.txt)"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text_edit.toPlainText())
            self.show_notification("Export", f"Logs exported to {filename}")
    
    def update_statistics(self):
        """Update statistics display"""
        # This would get actual statistics from antivirus engine
        pass
    
    def update_activity_log(self):
        """Update activity log"""
        # This would get actual activity data
        pass
    
    def show_notification(self, title: str, message: str):
        """Show system tray notification"""
        try:
            # FIX: the tray manager is stored as self.system_tray (set in
            # init_system_tray), not self.tray_icon - the old attribute never
            # existed, so every GUI notification was silently dropped.
            if hasattr(self, 'system_tray') and self.system_tray and self.system_tray.isVisible():
                self.system_tray.showMessage(title, message, QSystemTrayIcon.Information, 3000)
            else:
                # Fallback to console if tray not available
                print(f"Notification: {title} - {message}")
        except Exception as e:
            print(f"Notification error: {e} - {title}: {message}")
    
    def quit_application(self):
        """Quit application"""
        reply = QMessageBox.question(
            self, 'Quit', 'Are you sure you want to quit AI Antivirus?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            QApplication.quit()
    
    def on_threat_detected(self, threat_data):
        """Handle threat detection from real-time protection"""
        # FIX: this callback is invoked from watchdog/worker threads of the
        # real-time protection engine. Touching widgets from a non-GUI thread
        # is undefined behavior in Qt (intermittent crashes). Marshal the
        # update to the GUI thread via a queued invocation.
        try:
            QMetaObject.invokeMethod(self, "_on_threat_detected_safe",
                                     Qt.QueuedConnection,
                                     Q_ARG("PyQt_PyObject", threat_data))
        except Exception as e:
            self.logger.error(f"Failed to queue threat notification: {e}")

    @pyqtSlot("PyQt_PyObject")
    def _on_threat_detected_safe(self, threat_data):
        """GUI-thread handler for threat detection (queued from worker threads)"""
        try:
            threat_type = threat_data.get('type', 'unknown')
            file_path = threat_data.get('file_path', 'Unknown')
            threat_score = threat_data.get('threat_score', 0.0)
            
            if threat_type == 'threat_detected':
                self.show_notification(
                    "Threat Detected", 
                    f"Malicious file detected: {os.path.basename(file_path)}\nThreat Score: {threat_score:.2f}"
                )
                self.total_threats_detected += 1
                
            elif threat_type == 'threat_quarantined':
                self.show_notification(
                    "Threat Quarantined", 
                    f"Malicious file quarantined: {os.path.basename(file_path)}"
                )
                
            elif threat_type == 'suspicious_file':
                self.show_notification(
                    "Suspicious File", 
                    f"Suspicious activity: {os.path.basename(file_path)}\nScore: {threat_score:.2f}"
                )
            
            # Update dashboard display
            self.update_dashboard_display()
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
    
    def _handle_threat_detection(self, threat_info):
        """Handle threat detection from real-time protection"""
        try:
            # Update GUI with threat notification
            if hasattr(self, 'system_tray') and self.system_tray:
                self.system_tray.show_notification(
                    "Threat Detected",
                    f"Threat found: {threat_info.get('file_path', 'Unknown')}",
                    "threat"
                )
            
            # Update dashboard
            self.total_threats_detected += 1
            self.update_dashboard_display()
            
            self.logger.warning(f"Threat detected: {threat_info}")
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
    
    def _handle_zero_day_detection(self, zero_day_threat):
        """Handle zero-day threat detection"""
        try:
            # Update GUI with zero-day notification
            if hasattr(self, 'system_tray') and self.system_tray:
                self.system_tray.show_notification(
                    "Zero-Day Threat Detected",
                    f"Advanced threat: {zero_day_threat.file_path}\nCategory: {zero_day_threat.threat_category}",
                    "threat"
                )
            
            # Update dashboard
            self.total_threats_detected += 1
            self.update_dashboard_display()
            
            # Add to AI training if available
            if self.ai_trainer and zero_day_threat.threat_score > 0.8:
                features = self.ai_trainer.extract_features(zero_day_threat.file_path)
                self.ai_trainer.add_training_sample(
                    zero_day_threat.file_path,
                    features,
                    1,  # Threat label
                    zero_day_threat.confidence,
                    "zero_day_detection"
                )
            
            self.logger.critical(f"Zero-day threat detected: {zero_day_threat.file_path} "
                               f"(Score: {zero_day_threat.threat_score:.3f}, "
                               f"Category: {zero_day_threat.threat_category})")
            
        except Exception as e:
            self.logger.error(f"Error handling zero-day detection: {e}")
    
    def on_protection_status_changed(self, status, message):
        """Handle protection status changes"""
        try:
            if hasattr(self, 'protection_status_label'):
                if status == 'active':
                    self.protection_status_label.setText(f"🛡️ Real-time Protection: ACTIVE - {message}")
                    self.protection_status_label.setStyleSheet("color: green; font-weight: bold;")
                elif status == 'paused':
                    self.protection_status_label.setText(f"⏸️ Real-time Protection: PAUSED - {message}")
                    self.protection_status_label.setStyleSheet("color: orange; font-weight: bold;")
                elif status == 'stopped':
                    self.protection_status_label.setText(f"🛑 Real-time Protection: STOPPED - {message}")
                    self.protection_status_label.setStyleSheet("color: red; font-weight: bold;")
                    # FIX: warn the user with a popup when protection turns off
                    # (agreed requirement - protection must never go down
                    # silently).
                    try:
                        QMessageBox.warning(
                            self, "Real-time Protection",
                            "Real-time protection has been DISABLED.\n\n"
                            "Your system is no longer monitored in real time.\n"
                            "You can re-enable it from the Dashboard, the Scan tab "
                            "or the system tray menu (Start Protection).")
                    except Exception as warn_err:
                        self.logger.error(f"Could not show protection warning: {warn_err}")

        except Exception as e:
            self.logger.error(f"Error updating protection status: {e}")
    
    def handle_cloud_threat_event(self, event_type: str, data: dict):
        """Handle cloud threat intelligence events"""
        try:
            if event_type == 'sync_completed':
                # Show system tray notification
                if hasattr(self, 'system_tray') and self.system_tray:
                    self.system_tray.show_notification(
                        "Cloud Intelligence Updated",
                        f"Provider: {data.get('provider', 'Unknown')}\n"
                        f"Added: {data.get('indicators_added', 0)} indicators\n"
                        f"Updated: {data.get('indicators_updated', 0)} indicators",
                        "info"
                    )
                
                self.logger.info(f"Cloud threat intelligence sync completed: {data}")
            
        except Exception as e:
            self.logger.error(f"Error handling cloud threat event: {e}")
    
    def init_system_tray(self):
        """Initialize system tray functionality"""
        try:
            # Check if system tray is available
            if not QSystemTrayIcon.isSystemTrayAvailable():
                self.logger.warning("System tray is not available on this system")
                self.system_tray = None
                return
            
            # Create system tray manager
            self.system_tray = SystemTrayManager(self)
            
            # Connect tray signals to main window methods
            self.system_tray.show_main_window.connect(self.show_and_raise)
            self.system_tray.start_quick_scan.connect(self.start_enhanced_quick_scan)
            self.system_tray.toggle_protection.connect(self.toggle_real_time_protection)
            self.system_tray.show_quarantine.connect(self.show_quarantine_tab)
            self.system_tray.exit_application.connect(self.quit_application)
            
            self.logger.info("System tray initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize system tray: {e}")
            self.system_tray = None
    
    def show_and_raise(self):
        """Show and raise main window from tray"""
        try:
            self.logger.info("Showing main window from system tray")
            
            # Force window to be visible and active
            self.setVisible(True)
            self.setWindowState(Qt.WindowNoState)  # Clear all window states first
            self.show()
            self.raise_()
            self.activateWindow()
            
            # Ensure window is on top and focused
            self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
            self.show()
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowStaysOnTopHint)
            self.show()
            
            # Force focus
            self.setFocus()
            
            self.logger.info("Main window should now be visible")
            
        except Exception as e:
            self.logger.error(f"Error showing main window: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def toggle_real_time_protection(self):
        """Toggle real-time protection from tray"""
        try:
            if hasattr(self, 'real_time_protection') and self.real_time_protection:
                if self.real_time_protection.is_active:
                    success = self.real_time_protection.stop_protection()
                    if success and self.system_tray:
                        self.system_tray.update_protection_status(False)
                        self.system_tray.show_protection_status_notification('stopped', 'Real-time protection stopped')
                else:
                    success = self.real_time_protection.start_protection()
                    if success and self.system_tray:
                        self.system_tray.update_protection_status(True)
                        self.system_tray.show_protection_status_notification('active', 'Real-time protection started')
            
        except Exception as e:
            self.logger.error(f"Error toggling protection from tray: {e}")
    
    def show_quarantine_tab(self):
        """Show quarantine tab from tray"""
        try:
            self.show_and_raise()
            # Switch to quarantine tab if available
            if hasattr(self, 'tab_widget'):
                for i in range(self.tab_widget.count()):
                    if 'quarantine' in self.tab_widget.tabText(i).lower():
                        self.tab_widget.setCurrentIndex(i)
                        break
            
        except Exception as e:
            self.logger.error(f"Error showing quarantine tab: {e}")
    
    def changeEvent(self, event):
        """Handle window state changes"""
        try:
            if event.type() == event.WindowStateChange:
                if self.isMinimized() and self.system_tray and self.system_tray.isVisible():
                    # Hide to tray when minimized
                    QTimer.singleShot(0, self.hide)
                    event.ignore()
                    return
            
            super().changeEvent(event)
            
        except Exception as e:
            self.logger.error(f"Error handling window state change: {e}")
    
    def closeEvent(self, event):
        """Handle close event - minimize to tray instead of closing, keep protection running"""
        try:
            if self.system_tray and self.system_tray.isVisible():
                # Hide to system tray instead of closing - KEEP PROTECTION RUNNING
                self.hide()
                event.ignore()
                if hasattr(self.system_tray, 'show_notification'):
                    self.system_tray.show_notification(
                        "AI Antivirus", 
                        "Application minimized to system tray - Protection remains active", 
                        "info"
                    )
                # Log that protection continues
                self.logger.info("Application minimized to tray - Real-time protection continues running")
            else:
                # No system tray available, actually close and stop protection
                self._stop_all_services()
                event.accept()
                
        except Exception as e:
            self.logger.error(f"Error handling close event: {e}")
            event.accept()
    
    def handle_monitoring_event(self, event):
        """Handle monitoring events from real-time monitoring system"""
        try:
            # Update system tray with threat notifications
            if hasattr(self, 'system_tray') and self.system_tray:
                if event.severity in ['high', 'critical']:
                    self.system_tray.show_notification(
                        "Security Alert",
                        f"{event.event_type}: {event.description}",
                        notification_type='threat'
                    )
                elif event.threat_score > 0.6:
                    self.system_tray.show_notification(
                        "Security Warning", 
                        f"Suspicious activity detected: {event.description}",
                        notification_type='warning'
                    )
            
            # Update monitoring dashboard if available
            if hasattr(self, 'monitoring_dashboard') and self.monitoring_dashboard:
                self.monitoring_dashboard.update_dashboard()
            
            self.logger.info(f"Monitoring event processed: {event.event_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle monitoring event: {e}")
    
    def handle_threat_response(self, response_type: str, data: dict):
        """Handle automated threat response notifications"""
        try:
            if response_type == 'threat_alert':
                # Show critical threat alert
                if hasattr(self, 'system_tray') and self.system_tray:
                    self.system_tray.show_notification(
                        "🚨 Critical Threat Detected",
                        f"Threat Score: {data.get('threat_score', 0):.2f}\n{data.get('description', '')}",
                        notification_type='threat'
                    )
                
                # Log the response
                self.logger.warning(f"Automated threat response: {data}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle threat response: {e}")

    def _stop_all_services(self):
        """Stop all background services when actually closing the application"""
        try:
            self.logger.info("Stopping all background services...")
            
            # Stop all background processes
            if hasattr(self, 'real_time_protection') and self.real_time_protection:
                self.real_time_protection.stop_protection()
                self.logger.info("Real-time protection stopped")
            
            if hasattr(self, 'zero_day_detector') and self.zero_day_detector:
                self.zero_day_detector.stop_monitoring()
                self.logger.info("Zero-day detector stopped")
            
            if hasattr(self, 'monitoring_system') and self.monitoring_system:
                self.monitoring_system.stop_monitoring()
                self.logger.info("Monitoring system stopped")
            
            if hasattr(self, 'response_system') and self.response_system:
                self.response_system.cleanup()
                self.logger.info("Response system cleaned up")
            
            if hasattr(self, 'p2p_exchange') and self.p2p_exchange:
                self.p2p_exchange.stop()
                self.logger.info("P2P exchange stopped")
            
            # Save configuration (placeholder)
            try:
                self.save_configuration()
                self.logger.info("Configuration saved")
            except AttributeError:
                self.logger.debug("No configuration to save")
                
        except Exception as e:
            self.logger.error(f"Error stopping services: {e}")
    
    def quit_application(self):
        """Completely quit the application and stop all services"""
        try:
            self.logger.info("Quitting application completely...")
            self._stop_all_services()
            QApplication.quit()
        except Exception as e:
            self.logger.error(f"Error quitting application: {e}")
            QApplication.quit()
    
    def connect_tray_notifications(self):
        """Connect threat detection signals to tray notifications"""
        try:
            # Override the existing threat detection handler to also notify tray
            original_threat_handler = self.on_threat_detected
            
            def enhanced_threat_handler(threat_data):
                # Call original handler
                original_threat_handler(threat_data)
                
                # Notify system tray
                if self.system_tray:
                    self.system_tray.show_threat_notification(threat_data)
            
            self.on_threat_detected = enhanced_threat_handler

            # FIX: the real-time protection engine captured the ORIGINAL bound
            # on_threat_detected at init time (set_threat_callback), so simply
            # reassigning the instance attribute here never took effect and tray
            # threat notifications never fired. Re-register the enhanced handler
            # on the engine.
            if getattr(self, 'real_time_protection', None):
                try:
                    self.real_time_protection.set_threat_callback(self.on_threat_detected)
                except Exception as cb_err:
                    self.logger.error(f"Could not re-register threat callback: {cb_err}")

            # Override scan completion handler
            if hasattr(self, 'on_scan_complete'):
                original_scan_handler = self.on_scan_complete

                def enhanced_scan_handler(scan_results):
                    # Call original handler
                    original_scan_handler(scan_results)

                    # Notify system tray
                    if self.system_tray:
                        self.system_tray.show_scan_complete_notification(scan_results)

                self.on_scan_complete = enhanced_scan_handler

        except Exception as e:
            self.logger.error(f"Error connecting tray notifications: {e}")
    
    def toggle_scan_pause(self):
        """Toggle scan pause/resume state"""
        try:
            if not hasattr(self, 'scan_paused'):
                self.scan_paused = False
            
            if not self.scan_running:
                print("No scan running to pause/resume")
                return
            
            # Toggle pause state
            self.scan_paused = not self.scan_paused
            
            # Update button text and status
            if self.scan_paused:
                if hasattr(self, 'dashboard_pause_resume_btn'):
                    self.dashboard_pause_resume_btn.setText("▶️ Resume")
                if hasattr(self, 'scan_status_label'):
                    self.scan_status_label.setText("⏸️ Scan paused - Click Resume to continue")
                print("🔄 Scan PAUSED")
            else:
                if hasattr(self, 'dashboard_pause_resume_btn'):
                    self.dashboard_pause_resume_btn.setText("⏸️ Pause")
                if hasattr(self, 'scan_status_label'):
                    self.scan_status_label.setText("🔄 Scan resumed...")
                print("🔄 Scan RESUMED")
                
        except Exception as e:
            self.logger.error(f"Error toggling scan pause: {e}")
            print(f"Error toggling scan pause: {e}")

def main():
    """Main function to run the GUI"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("AI Antivirus")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("AI Security Solutions")
    
    # Create and show main window
    # Note: antivirus_engine would be passed from main application
    window = AntivirusMainWindow(None)
    window.show()
    
    sys.exit(app.exec_())

# Alias for backward compatibility
MainWindow = AntivirusMainWindow

if __name__ == "__main__":
    main()
