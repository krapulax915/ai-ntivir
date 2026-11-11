#!/usr/bin/env python3
"""
System Tray Integration for AI Antivirus
Provides background operation and quick access functionality
"""

import os
import sys
from PyQt5.QtWidgets import (QSystemTrayIcon, QMenu, QAction, QApplication, 
                            QMessageBox, QWidget, QVBoxLayout, QLabel, 
                            QPushButton, QHBoxLayout)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt5.QtGui import QIcon, QPixmap, QFont, QCursor
import logging
from datetime import datetime

class TrayNotificationWidget(QWidget):
    """Custom notification widget for tray notifications"""
    
    def __init__(self, title, message, notification_type="info"):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(350, 100)
        
        # Position in bottom right corner
        screen = QApplication.desktop().screenGeometry()
        self.move(screen.width() - 370, screen.height() - 120)
        
        self.init_ui(title, message, notification_type)
        
        # Auto-hide timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.close)
        self.timer.start(5000)  # Hide after 5 seconds
    
    def init_ui(self, title, message, notification_type):
        """Initialize notification UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Set background color based on type
        if notification_type == "threat":
            bg_color = "#ff4444"
            icon = "🚨"
        elif notification_type == "warning":
            bg_color = "#ff8800"
            icon = "⚠️"
        elif notification_type == "success":
            bg_color = "#44aa44"
            icon = "✅"
        else:
            bg_color = "#4488ff"
            icon = "ℹ️"
        
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {bg_color};
                border-radius: 10px;
                color: white;
            }}
            QLabel {{
                color: white;
                border: none;
            }}
        """)
        
        # Title
        title_layout = QHBoxLayout()
        title_label = QLabel(f"{icon} {title}")
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        # Close button
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(20, 20)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,255,255,0.3);
                border: none;
                border-radius: 10px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255,255,255,0.5);
            }
        """)
        close_btn.clicked.connect(self.close)
        title_layout.addWidget(close_btn)
        
        layout.addLayout(title_layout)
        
        # Message
        message_label = QLabel(message)
        message_label.setFont(QFont("Arial", 10))
        message_label.setWordWrap(True)
        layout.addWidget(message_label)

class SystemTrayManager(QSystemTrayIcon):
    """System tray manager for AI Antivirus"""
    
    # Signals
    show_main_window = pyqtSignal()
    start_quick_scan = pyqtSignal()
    toggle_protection = pyqtSignal()
    show_quarantine = pyqtSignal()
    exit_application = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        try:
            # FIX: the module lives in src/core, not next to this file
            from ..core.comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.system_tray')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # State tracking
        self.protection_active = True  # Start with protection active
        self.last_scan_time = None
        self.threat_count = 0
        self.notification_widgets = []
        
        self.init_tray()
        self.init_timer()
        
        # Connect signals
        self.activated.connect(self.on_tray_activated)
    
    def init_tray(self):
        """Initialize system tray icon and menu"""
        try:
            # Create tray icon
            self.create_tray_icon()
            
            # Create context menu
            self.create_context_menu()
            
            # Set tooltip
            self.update_tooltip()
            
            # Show tray icon
            self.show()
            
            self.logger.info("System tray initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize system tray: {e}")
    
    def create_tray_icon(self):
        """Create system tray icon"""
        try:
            # Try to load custom icon
            icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "tray_icon.png")
            
            if os.path.exists(icon_path):
                icon = QIcon(icon_path)
            else:
                # Create a green icon for active protection
                pixmap = QPixmap(16, 16)
                pixmap.fill(Qt.green)
                icon = QIcon(pixmap)
            
            self.setIcon(icon)
            
        except Exception as e:
            self.logger.error(f"Error creating tray icon: {e}")
            # Fallback to default icon
            self.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
    
    def create_context_menu(self):
        """Create context menu for system tray"""
        try:
            # FIX: the menu needs a parent. setContextMenu does NOT take
            # ownership - without a parent the local QMenu was garbage-collected
            # right after this method returned and the tray right-click menu
            # (with Start Protection) disappeared/crashed.
            menu = QMenu(self)
            
            # Main window action
            show_action = QAction("🖥️ Show AI Antivirus", self)
            show_action.triggered.connect(self.show_main_window.emit)
            menu.addAction(show_action)
            
            menu.addSeparator()
            
            # Protection toggle
            self.protection_action = QAction("🛡️ Start Protection", self)
            self.protection_action.triggered.connect(self.toggle_protection.emit)
            menu.addAction(self.protection_action)
            
            # Quick scan
            scan_action = QAction("🔍 Quick Scan", self)
            scan_action.triggered.connect(self.start_quick_scan.emit)
            menu.addAction(scan_action)
            
            menu.addSeparator()
            
            # Quarantine
            quarantine_action = QAction("📦 View Quarantine", self)
            quarantine_action.triggered.connect(self.show_quarantine.emit)
            menu.addAction(quarantine_action)
            
            # Statistics submenu
            stats_menu = menu.addMenu("📊 Statistics")
            
            self.files_scanned_action = QAction("Files Scanned: 0", self)
            self.files_scanned_action.setEnabled(False)
            stats_menu.addAction(self.files_scanned_action)
            
            self.threats_detected_action = QAction("Threats Detected: 0", self)
            self.threats_detected_action.setEnabled(False)
            stats_menu.addAction(self.threats_detected_action)
            
            self.last_scan_action = QAction("Last Scan: Never", self)
            self.last_scan_action.setEnabled(False)
            stats_menu.addAction(self.last_scan_action)
            
            menu.addSeparator()

            # Exit
            exit_action = QAction("❌ Exit", self)
            exit_action.triggered.connect(self.exit_application.emit)
            menu.addAction(exit_action)

            # FIX (v1.0.2): do NOT rely on QSystemTrayIcon.setContextMenu - on
            # some frozen/hidden-window setups Windows never shows it (right
            # and left click did nothing). Keep a strong reference and show the
            # menu explicitly from on_tray_activated().
            self._context_menu = menu
            self.logger.info("Tray context menu created (explicit-popup mode)")

        except Exception as e:
            self.logger.error(f"Error creating context menu: {e}")
    
    def init_timer(self):
        """Initialize update timer"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def on_tray_activated(self, reason):
        """Handle tray icon activation"""
        try:
            if reason in (QSystemTrayIcon.DoubleClick, QSystemTrayIcon.Trigger):
                # Single left click or double click - open the dashboard
                self.show_main_window.emit()
            elif reason == QSystemTrayIcon.Context:
                # Right click - show the menu explicitly at the cursor.
                # (FIX v1.0.2: setContextMenu alone proved unreliable here.)
                menu = getattr(self, '_context_menu', None)
                if menu is not None:
                    menu.exec_(QCursor.pos())

        except Exception as e:
            self.logger.error(f"Error handling tray activation: {e}")
    
    def update_protection_status(self, is_active):
        """Update protection status in tray"""
        try:
            self.protection_active = is_active
            
            # Update icon color - default to active on startup
            if is_active:
                self.update_tray_icon_color(Qt.green)
                self.setToolTip("AI Antivirus - Protection Active")
                # FIX: keep the tray action label in sync - the toggle STOPS
                # protection when it is already active, a static "Start
                # Protection" label made users disable protection by accident.
                if hasattr(self, 'protection_action'):
                    self.protection_action.setText("🛑 Stop Protection")
            else:
                self.update_tray_icon_color(Qt.red)
                # FIX: tooltip said "Protection Active" even when stopped
                self.setToolTip("AI Antivirus - Protection Stopped")
                if hasattr(self, 'protection_action'):
                    self.protection_action.setText("🛡️ Start Protection")
            
            self.update_tooltip()
            
        except Exception as e:
            self.logger.error(f"Error updating protection status: {e}")
    
    def update_tray_icon_color(self, color):
        """Update tray icon color based on protection status"""
        try:
            pixmap = QPixmap(32, 32)
            pixmap.fill(color)
            self.setIcon(QIcon(pixmap))
            
        except Exception as e:
            self.logger.error(f"Error updating tray icon color: {e}")
    
    def update_tooltip(self):
        """Update tray icon tooltip"""
        try:
            status = "Active" if self.protection_active else "Stopped"
            tooltip = f"AI Antivirus - Protection {status}\nThreats Detected: {self.threat_count}"
            
            if self.last_scan_time:
                tooltip += f"\nLast Scan: {self.last_scan_time}"
            
            self.setToolTip(tooltip)
            
        except Exception as e:
            self.logger.error(f"Error updating tooltip: {e}")
    
    def update_status(self):
        """Update tray status and statistics"""
        try:
            if hasattr(self.parent, 'real_time_protection') and self.parent.real_time_protection:
                status = self.parent.real_time_protection.get_protection_status()
                stats = status.get('stats', {})
                
                # Update statistics in menu
                files_scanned = stats.get('files_scanned', 0)
                threats_detected = stats.get('threats_detected', 0)
                
                self.files_scanned_action.setText(f"Files Scanned: {files_scanned}")
                self.threats_detected_action.setText(f"Threats Detected: {threats_detected}")
                
                self.threat_count = threats_detected
                self.update_tooltip()
            
        except Exception as e:
            self.logger.error(f"Error updating status: {e}")
    
    def show_notification(self, title, message, notification_type="info"):
        """Show system tray notification"""
        try:
            # FIX: this class IS the tray icon (extends QSystemTrayIcon) - the
            # self.tray_icon attribute never existed, so every call was a no-op.
            self.showMessage(title, message, QSystemTrayIcon.Information, 3000)
        except Exception as e:
            print(f"Notification error: {e}")
    
    def update_threat_intelligence(self, data):
        """Stub for threat intelligence updates"""
        pass
    
    def show_threat_notification(self, threat_data):
        """Show threat detection notification"""
        try:
            threat_type = threat_data.get('type', 'unknown')
            file_path = threat_data.get('file_path', 'Unknown')
            threat_score = threat_data.get('threat_score', 0.0)
            
            if threat_type == 'threat_detected':
                title = "🚨 Threat Detected!"
                message = f"Malicious file detected:\n{os.path.basename(file_path)}\nThreat Score: {threat_score:.2f}"
                notification_type = "threat"
                
            elif threat_type == 'threat_quarantined':
                title = "🛡️ Threat Quarantined"
                message = f"Malicious file quarantined:\n{os.path.basename(file_path)}"
                notification_type = "success"
                
            elif threat_type == 'suspicious_file':
                title = "⚠️ Suspicious Activity"
                message = f"Suspicious file detected:\n{os.path.basename(file_path)}\nScore: {threat_score:.2f}"
                notification_type = "warning"
            else:
                return
            
            # Show custom notification
            self.show_custom_notification(title, message, notification_type)
            
            # Also show system tray message
            self.showMessage(title, message, QSystemTrayIcon.Warning, 5000)
            
        except Exception as e:
            self.logger.error(f"Error showing threat notification: {e}")
    
    def show_custom_notification(self, title, message, notification_type="info"):
        """Show custom notification widget"""
        try:
            # Clean up old notifications
            self.cleanup_notifications()
            
            # Create new notification
            notification = TrayNotificationWidget(title, message, notification_type)
            notification.show()
            
            self.notification_widgets.append(notification)
            
        except Exception as e:
            self.logger.error(f"Error showing custom notification: {e}")
    
    def cleanup_notifications(self):
        """Clean up closed notification widgets"""
        try:
            self.notification_widgets = [w for w in self.notification_widgets if w.isVisible()]
            
        except Exception as e:
            self.logger.error(f"Error cleaning up notifications: {e}")
    
    def show_scan_complete_notification(self, scan_results):
        """Show scan completion notification"""
        try:
            threats_found = scan_results.get('threats_found', 0)
            files_scanned = scan_results.get('files_scanned', 0)
            
            if threats_found > 0:
                title = "🚨 Scan Complete - Threats Found"
                message = f"Scanned {files_scanned} files\nFound {threats_found} threats"
                notification_type = "threat"
            else:
                title = "✅ Scan Complete - System Clean"
                message = f"Scanned {files_scanned} files\nNo threats detected"
                notification_type = "success"
            
            self.show_custom_notification(title, message, notification_type)
            self.showMessage(title, message, QSystemTrayIcon.Information, 3000)
            
            # Update last scan time
            self.last_scan_time = datetime.now().strftime("%H:%M")
            self.last_scan_action.setText(f"Last Scan: {self.last_scan_time}")
            self.update_tooltip()
            
        except Exception as e:
            self.logger.error(f"Error showing scan complete notification: {e}")
    
    def show_protection_status_notification(self, status, message):
        """Show protection status change notification"""
        try:
            if status == 'active':
                title = "🛡️ Protection Started"
                notification_type = "success"
            elif status == 'stopped':
                title = "🛑 Protection Stopped"
                notification_type = "warning"
            elif status == 'paused':
                title = "⏸️ Protection Paused"
                notification_type = "warning"
            else:
                return
            
            self.show_custom_notification(title, message, notification_type)
            
        except Exception as e:
            self.logger.error(f"Error showing protection status notification: {e}")
    
    def is_available(self):
        """Check if system tray is available"""
        return QSystemTrayIcon.isSystemTrayAvailable()
    
    def cleanup(self):
        """Cleanup tray resources"""
        try:
            # Clean up notifications
            for widget in self.notification_widgets:
                widget.close()
            self.notification_widgets.clear()
            
            # Stop timer
            if hasattr(self, 'update_timer'):
                self.update_timer.stop()
            
            # Hide tray icon
            self.hide()
            
        except Exception as e:
            self.logger.error(f"Error during tray cleanup: {e}")
