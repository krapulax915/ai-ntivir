#!/usr/bin/env python3
"""
AI Antivirus - Main Application Entry Point
Beépített AI-val rendelkező vírusvédelmi rendszer Windows operációs rendszerekre
"""

import gc
import sys
import os
import time
import signal
import logging
import traceback
from pathlib import Path

# Force garbage collection and memory optimization at startup
gc.collect()
gc.set_threshold(700, 10, 10)  # More aggressive garbage collection

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Initialize comprehensive logging system FIRST
try:
    from src.core.logging_initializer import initialize_comprehensive_logging, setup_startup_logging, setup_shutdown_logging
    from src.core.comprehensive_logger import get_comprehensive_logger
    
    # Initialize comprehensive logging
    comp_logger = initialize_comprehensive_logging()
    
    # Setup startup and shutdown logging
    startup_logger = setup_startup_logging()
    shutdown_logger = setup_shutdown_logging()
    
    logger = startup_logger
    logger.info("Comprehensive logging system initialized successfully")
    
except Exception as e:
    # Fallback to basic logging if comprehensive logging fails
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('aintivirus_debug.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)
    logger.info(f"Using basic logging system: {e}")

def check_dependencies():
    """Check if critical dependencies are available"""
    missing_deps = []
    optional_deps = []
    
    try:
        import PyQt5
        pass  # Silent dependency check
    except ImportError:
        missing_deps.append("PyQt5")
    
    try:
        import numpy
        pass  # Silent dependency check
    except ImportError:
        missing_deps.append("numpy")
    
    try:
        import onnxruntime
        pass  # Silent dependency check
    except ImportError:
        optional_deps.append("onnxruntime")
        pass  # Silent dependency check
    
    try:
        import aiohttp
        pass  # Silent dependency check
    except ImportError:
        optional_deps.append("aiohttp")
        pass  # Silent dependency check
    
    if missing_deps:
        # Silent error - log only
        logger.error(f"Critical dependencies missing: {', '.join(missing_deps)}")
        return False
    
    if optional_deps:
        # Silent warning - log only
        logger.warning(f"Optional dependencies missing: {', '.join(optional_deps)}")
    
    return True

# Import monitoring service
try:
    from src.monitoring.monitoring_service import MonitoringService
    logger.info("Monitoring service imported")
except ImportError as e:
    logger.warning(f"Monitoring service not available: {e}")
    MonitoringService = None

# Optional package auto-installer
def install_missing_optional_packages():
    """Attempt to install missing optional packages"""
    try:
        import subprocess
        import os
        
        # Check if optional installer exists
        installer_path = os.path.join(os.path.dirname(__file__), 'install_optional_packages.py')
        if os.path.exists(installer_path):
            logger.info("Running optional package installer...")
            result = subprocess.run([sys.executable, installer_path], 
                                  capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                logger.info("Optional packages installed successfully")
            else:
                logger.warning(f"Optional package installation had issues: {result.stderr}")
        else:
            logger.info("Optional package installer not found, continuing with available packages")
    except Exception as e:
        logger.warning(f"Could not run optional package installer: {e}")

# Run optional package installer if needed
try:
    # Check for critical missing packages
    missing_critical = []
    try:
        import onnxruntime
    except ImportError:
        missing_critical.append('onnxruntime')
    
    try:
        import cryptography
    except ImportError:
        missing_critical.append('cryptography')
    
    if missing_critical:
        logger.info(f"Missing critical optional packages: {missing_critical}")
        install_missing_optional_packages()
except Exception as e:
    logger.warning(f"Package check failed: {e}")

# GUI imports
try:
    logger.info("Importing PyQt5...")
    from PyQt5.QtWidgets import QApplication
    logger.info("Importing main window...")
    from src.gui.main_window import AntivirusMainWindow
    GUI_AVAILABLE = True
    logger.info("GUI imports successful")
except ImportError as e:
    logger.error(f"GUI import error: {e}")
    logger.error(traceback.format_exc())
    GUI_AVAILABLE = False

from src.core.ai_engine import AIEngine
from src.core.file_monitor import FileMonitor
from src.core.quarantine import QuarantineManager

# Import enhanced quick scan system
try:
    from enhanced_quick_scan_system import CriticalSystemScanner
    logger.info("Enhanced quick scan system imported successfully")
except ImportError as e:
    logger.error(f"Enhanced quick scan import error: {e}")
    CriticalSystemScanner = None
from src.detection.signature_engine import SignatureEngine
from src.detection.heuristic_analyzer import HeuristicAnalyzer
from log_management_system import LogManagementSystem
from src.network.p2p_communication import P2PNetworkManager
from src.dlp.data_loss_prevention import DLPEngine
from src.updater.auto_updater import AutoUpdater
from src.config.config_manager import ConfigManager

# Browser protection imports
try:
    from src.protection.browser_protection import BrowserProtection
    BROWSER_PROTECTION_AVAILABLE = True
    logger.info("Browser protection module imported successfully")
except ImportError as e:
    logger.warning(f"Browser protection not available: {e}")
    BROWSER_PROTECTION_AVAILABLE = False

# Real-time protection imports
try:
    from src.protection.real_time_protection import RealTimeProtectionEngine
    REALTIME_PROTECTION_AVAILABLE = True
    logger.info("Real-time protection module imported successfully")
except ImportError as e:
    logger.warning(f"Real-time protection not available: {e}")
    REALTIME_PROTECTION_AVAILABLE = False

class AIAntivirusEngine:
    """Main AI Antivirus Engine"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.config_manager = ConfigManager()
        self.is_running = False
        
        # Initialize components
        self.ai_engine = None
        self.browser_protection = None
        self.realtime_protection = None
        self.file_monitor = None
        self.quarantine_manager = None
        self.signature_engine = None
        self.log_management = None
        
        # Load ultra-low performance config if available
        self._load_performance_config()
        self.heuristic_analyzer = None
        self.p2p_network = None
        self.dlp_engine = None
        self.auto_updater = None
        self.gui_app = None
        
        self.logger.info("AI Antivirus Engine initialized")
    
    def _load_performance_config(self):
        """Load ultra-low performance configuration"""
        try:
            # Ultra-minimal performance configuration
            self.perf_config = {
                "component_settings": {
                    "disable_heavy_components": True,
                    "minimal_memory_mode": True,
                    "max_threads": 1,
                    "disable_ml_models": True
                }
            }
            self.logger.info("Ultra-minimal performance configuration loaded")
        except Exception as e:
            self.logger.error(f"Failed to load performance config: {e}")
            self.perf_config = {"component_settings": {}}
    
    def _setup_logging(self):
        """Setup logging configuration using comprehensive logging system"""
        try:
            from src.core.comprehensive_logger import setup_module_logging
            return setup_module_logging('ai_antivirus.engine')
        except ImportError:
            # Fallback to basic logging
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(os.path.join(log_dir, 'aintivirus.log')),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            
            return logging.getLogger(__name__)
    
    def initialize_components(self):
        """Initialize all antivirus components"""
        try:
            self.logger.info("Initializing AI Antivirus components...")
            
            # Log module initialization
            from src.core.logging_integration import log_module_startup
            log_module_startup('ai_antivirus.engine', '2.0.0', ['PyQt5', 'scikit-learn', 'numpy'])
            
            # CRITICAL FIX V15: Initialize quarantine manager (uses AI_Antivirus/quarantine)
            self.quarantine_manager = QuarantineManager()
            self.logger.info("Quarantine manager initialized")
            
            # Initialize AI engine
            model_path = self.config_manager.get('core.ai_engine.model_path')
            self.ai_engine = AIEngine(model_path)
            self.logger.info("AI engine initialized")
            
            # Initialize signature engine
            signature_db_path = self.config_manager.get('detection.signature_engine.signature_db_path')
            self.signature_engine = SignatureEngine(signature_db_path)
            self.logger.info("Signature engine initialized")
            
            # Initialize log management system
            self.log_management = LogManagementSystem()
            self.logger.info("Log management system initialized")
            
            # Initialize heuristic analyzer
            self.heuristic_analyzer = HeuristicAnalyzer()
            self.logger.info("Heuristic analyzer initialized")
            
            # Initialize file monitor
            self.file_monitor = FileMonitor(self.ai_engine, self.quarantine_manager)
            self.logger.info("File monitor initialized")
            
            # Initialize P2P network
            self.p2p_network = P2PNetworkManager(self.ai_engine, self.quarantine_manager)
            self.logger.info("P2P network initialized")
            
            # Initialize browser protection
            if BROWSER_PROTECTION_AVAILABLE:
                self.browser_protection = BrowserProtection()
                self.logger.info("Browser protection initialized")
            
            # Initialize real-time protection
            if REALTIME_PROTECTION_AVAILABLE:
                self.realtime_protection = RealTimeProtectionEngine(
                    ai_engine=self.ai_engine,
                    quarantine_manager=self.quarantine_manager,
                    log_management=self.log_management
                )
                # Set signature engine reference
                if hasattr(self.realtime_protection, 'signature_engine'):
                    self.realtime_protection.signature_engine = self.signature_engine
                self.logger.info("Real-time protection initialized")
            
            # Initialize DLP engine
            self.dlp_engine = DLPEngine()
            self.logger.info("DLP engine initialized")
            
            # Initialize auto updater
            self.auto_updater = AutoUpdater(self.config_manager)
            self.logger.info("Auto updater initialized")
            
            self.logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Component initialization failed: {e}")
            # Log exception with comprehensive logging
            try:
                from src.core.comprehensive_logger import get_comprehensive_logger
                get_comprehensive_logger().log_exception('ai_antivirus.engine', e, 'Component initialization')
            except:
                pass
            return False
    
    def start_services(self):
        """Start all antivirus services"""
        try:
            self.logger.info("Starting AI Antivirus services...")
            
            # Log service startup
            from src.core.logging_integration import SecurityEventLogger
            SecurityEventLogger.log_user_action("SERVICE_START", "system", {"services": "all"})
            
            # Start AI engine
            if self.ai_engine:
                self.ai_engine.start()
                self.logger.info("AI engine started")
            
            # Start real-time monitoring (only if not disabled)
            if (hasattr(self, 'real_time_monitor') and self.real_time_monitor and 
                not self.perf_config.get("component_settings", {}).get("disable_real_time_monitoring", False)):
                self.real_time_monitor.start_monitoring()
                self.logger.info("Real-time monitoring started")
            else:
                self.logger.info("Real-time monitoring disabled for performance")
            
            # Start browser protection
            if self.browser_protection and BROWSER_PROTECTION_AVAILABLE:
                self.browser_protection.start_monitoring()
                self.logger.info("Browser protection started")
            
            # Start real-time protection
            if self.realtime_protection and REALTIME_PROTECTION_AVAILABLE:
                self.realtime_protection.start_protection()
                self.logger.info("Real-time protection started")
            
            # Start P2P network
            if self.p2p_network:
                self.p2p_network.start()
                self.logger.info("P2P network started")
            
            # Start DLP engine
            if self.dlp_engine:
                self.dlp_engine.start()
                self.logger.info("DLP engine started")
            
            # Start auto updater
            if self.auto_updater:
                self.auto_updater.start()
                self.logger.info("Auto updater started")
            
            self.is_running = True
            self.logger.info("All services started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start services: {e}")
            self.stop_services()
    
    def stop_services(self):
        """Stop all antivirus services"""
        try:
            self.logger.info("Stopping AI Antivirus services...")
            self.is_running = False
            
            # Stop services in reverse order
            if self.auto_updater:
                self.auto_updater.stop()
                self.logger.info("Auto updater stopped")
            
            if self.dlp_engine:
                self.dlp_engine.stop()
                self.logger.info("DLP engine stopped")
            
            if self.p2p_network:
                self.p2p_network.stop()
                self.logger.info("P2P network stopped")
            
            # Stop browser protection
            if self.browser_protection and BROWSER_PROTECTION_AVAILABLE:
                self.browser_protection.stop_monitoring()
                self.logger.info("Browser protection stopped")
            
            # Stop real-time protection
            if self.realtime_protection and REALTIME_PROTECTION_AVAILABLE:
                self.realtime_protection.stop_protection()
                self.logger.info("Real-time protection stopped")
            
            if self.file_monitor:
                self.file_monitor.stop()
                self.logger.info("File monitor stopped")
            
            if self.ai_engine:
                self.ai_engine.stop()
                self.logger.info("AI engine stopped")
            
            self.logger.info("All services stopped")
            
        except Exception as e:
            self.logger.error(f"Service shutdown error: {e}")
    
    def run_gui_mode(self):
        """Run with GUI interface"""
        try:
            from PyQt5.QtWidgets import QApplication
            
            app = QApplication(sys.argv)
            app.setApplicationName("AI Antivirus")
            app.setApplicationVersion(self.config_manager.get('version', '1.0.0'))
            
            # Create main window
            self.gui_app = AntivirusMainWindow(self)
            self.gui_app.show()
            
            self.logger.info("GUI mode started")
            
            # Run application
            sys.exit(app.exec_())
            
        except ImportError:
            self.logger.error("PyQt5 not available, cannot start GUI mode")
            self.run_console_mode()
        except Exception as e:
            self.logger.error(f"GUI startup failed: {e}")
            self.run_console_mode()
    
    def run_console_mode(self):
        """Run in console mode"""
        try:
            self.logger.info("Running in console mode")
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Main loop
            while self.is_running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        except Exception as e:
            self.logger.error(f"Console mode error: {e}")
        finally:
            self.stop_services()
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.is_running = False
    
    def perform_scan(self, path: str, scan_type: str = "quick") -> dict:
        """Perform antivirus scan"""
        try:
            self.logger.info(f"Starting {scan_type} scan: {path}")
            
            scan_results = {
                'scan_type': scan_type,
                'path': path,
                'files_scanned': 0,
                'threats_found': 0,
                'threats': [],
                'start_time': time.time(),
                'end_time': None
            }
            
            # Scan files in path
            if os.path.isfile(path):
                files_to_scan = [path]
            else:
                files_to_scan = []
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        files_to_scan.append(file_path)
                        
                        # Limit for quick scan
                        if scan_type == "quick" and len(files_to_scan) > 1000:
                            break
            
            # Analyze each file
            for file_path in files_to_scan:
                try:
                    scan_results['files_scanned'] += 1
                    
                    # AI analysis
                    ai_result = self.ai_engine.analyze_file(file_path)
                    
                    # Signature check
                    sig_result = self.signature_engine.check_file_signature(file_path)
                    
                    # Heuristic analysis
                    heur_result = self.heuristic_analyzer.analyze_file_behavior(file_path)
                    
                    # Combine results
                    threat_score = max(
                        ai_result.get('threat_score', 0),
                        1.0 if sig_result.get('is_threat', False) else 0.0,
                        heur_result.get('heuristic_score', 0)
                    )
                    
                    if threat_score > 0.3:  # Threat threshold
                        threat_info = {
                            'file_path': file_path,
                            'threat_score': threat_score,
                            'ai_result': ai_result,
                            'signature_result': sig_result,
                            'heuristic_result': heur_result
                        }
                        
                        scan_results['threats'].append(threat_info)
                        scan_results['threats_found'] += 1
                        
                        # Auto-quarantine high threats
                        if threat_score > 0.7:
                            self.quarantine_manager.quarantine_file(file_path, threat_info)
                            self.logger.warning(f"High threat quarantined: {file_path}")
                
                except Exception as e:
                    self.logger.error(f"File scan error {file_path}: {e}")
                    continue
            
            scan_results['end_time'] = time.time()
            scan_duration = scan_results['end_time'] - scan_results['start_time']
            
            self.logger.info(
                f"Scan completed: {scan_results['files_scanned']} files, "
                f"{scan_results['threats_found']} threats, "
                f"{scan_duration:.2f} seconds"
            )
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return {'error': str(e)}
    
    def get_system_status(self) -> dict:
        """Get system status information"""
        return {
            'version': self.config_manager.get('version'),
            'is_running': self.is_running,
            'components': {
                'ai_engine': self.ai_engine is not None,
                'file_monitor': self.file_monitor is not None,
                'signature_engine': self.signature_engine is not None,
                'p2p_network': self.p2p_network is not None,
                'dlp_engine': self.dlp_engine is not None,
                'auto_updater': self.auto_updater is not None
            },
            'quarantine_stats': self.quarantine_manager.get_quarantine_stats() if self.quarantine_manager else {},
            'network_stats': self.p2p_network.get_network_stats() if self.p2p_network else {},
            'dlp_stats': self.dlp_engine.get_stats() if self.dlp_engine else {}
        }

def main():
    """Main entry point"""
    # Silent mode - no console output for hidden GUI
    pass
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='AI Antivirus System')
    parser.add_argument('--mode', choices=['gui', 'console'], default='gui',
                       help='Run mode (default: gui)')
    parser.add_argument('--gui', action='store_true', 
                       help='Start in GUI mode (same as --mode gui)')
    parser.add_argument('--scan', type=str, help='Scan path')
    parser.add_argument('--scan-type', choices=['quick', 'full'], default='quick',
                       help='Scan type (default: quick)')
    parser.add_argument('--config', type=str, help='Configuration file path')
    
    args = parser.parse_args()
    
    # Handle --gui flag
    if args.gui:
        args.mode = 'gui'
    
    try:
        # Initialize antivirus engine
        antivirus = AIAntivirusEngine()
        
        # Load custom config if specified
        if args.config:
            antivirus.config_manager.config_file = args.config
            antivirus.config_manager.load_config()
        
        # Initialize components
        if not antivirus.initialize_components():
            logger.error("Component initialization failed")
            sys.exit(1)
        
        # Start services
        antivirus.start_services()
        
        # Handle scan command
        if args.scan:
            logger.info(f"Starting {args.scan_type} scan: {args.scan}")
            scan_result = antivirus.perform_scan(args.scan, args.scan_type)
            
            if 'error' in scan_result:
                logger.error(f"Scan failed: {scan_result['error']}")
            else:
                logger.info(f"Scan completed - Files: {scan_result['files_scanned']}, Threats: {scan_result['threats_found']}")
                
                if scan_result['threats']:
                    for threat in scan_result['threats']:
                        logger.warning(f"Threat detected: {threat['file_path']} (Score: {threat['threat_score']:.2f})")
            
            antivirus.stop_services()
            return
        
        # Run in specified mode
        if args.mode == 'gui':
            if not GUI_AVAILABLE:
                logger.error("GUI not available. PyQt5 not installed.")
                logger.error("GUI not available. PyQt5 not installed.")
                sys.exit(1)
            
            logger.info("Starting GUI mode...")
            
            try:
                app = QApplication(sys.argv)
                app.setQuitOnLastWindowClosed(False)  # Keep running in system tray
                logger.info("QApplication created successfully")
                
                # Create main window (start hidden in system tray)
                main_window = AntivirusMainWindow()
                
                # Check if --show-gui argument is provided
                if '--show-gui' in sys.argv:
                    logger.info("--show-gui argument detected, showing main window")
                    main_window.show()
                else:
                    logger.info("Starting in hidden mode (system tray only)")
                    # Don't show main window - start hidden in system tray
                
                logger.info("AI Antivirus GUI started successfully")
                
                # Start event loop
                return app.exec_()
                
            except Exception as e:
                logger.error(f"Failed to create QApplication: {e}")
                logger.error(traceback.format_exc())
                # Silent exit - no input prompt for hidden mode
                pass
                return 1
        else:
            # Console mode
            logger.info("Starting console mode...")
            logger.info("Console mode - AI Antivirus engine running...")
            
            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Console mode interrupted by user")
                logger.info("Shutting down...")
            
            antivirus.stop_services()
            return 0
            
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        logger.error(traceback.format_exc())
        # Silent exit - no input prompt for hidden mode
        pass
        return 1

if __name__ == "__main__":
    sys.exit(main())
