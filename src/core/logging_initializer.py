#!/usr/bin/env python3
"""
Logging System Initializer
Automatically initializes comprehensive logging for the entire AI Antivirus system
"""

import os
import sys
import logging
from pathlib import Path
from .comprehensive_logger import get_comprehensive_logger, setup_module_logging
from .logging_integration import integrate_logging_into_existing_modules, log_module_startup

def initialize_comprehensive_logging():
    """Initialize comprehensive logging system for the entire application"""
    
    # Get the comprehensive logger instance
    comp_logger = get_comprehensive_logger()
    
    # Setup main application logger
    main_logger = setup_module_logging('ai_antivirus.main')
    
    # Log system startup
    main_logger.info("=" * 80)
    main_logger.info("AI ANTIVIRUS - COMPREHENSIVE LOGGING SYSTEM INITIALIZED")
    main_logger.info("=" * 80)
    
    # Log environment information
    environment = 'production' if getattr(sys, 'frozen', False) else 'development'
    main_logger.info(f"Environment: {environment}")
    main_logger.info(f"Log Directory: {comp_logger.log_dir}")
    main_logger.info(f"Python Version: {sys.version}")
    main_logger.info(f"Working Directory: {os.getcwd()}")
    
    # Integrate logging into existing modules
    integrate_logging_into_existing_modules()
    
    # Setup module-specific loggers
    setup_all_module_loggers()
    
    main_logger.info("Comprehensive logging system ready")
    return comp_logger

def setup_all_module_loggers():
    """Setup loggers for all AI Antivirus modules"""
    
    modules_to_setup = [
        # Core modules
        'ai_antivirus.core.ai_engine',
        'ai_antivirus.core.file_monitor', 
        'ai_antivirus.core.quarantine',
        'ai_antivirus.core.performance_manager',
        
        # Detection modules
        'ai_antivirus.detection.signature_engine',
        'ai_antivirus.detection.heuristic_analyzer',
        'ai_antivirus.detection.anomaly_detector',
        'ai_antivirus.detection.advanced_behavioral_analyzer',
        'ai_antivirus.detection.zero_day_detector',
        
        # Network modules
        'ai_antivirus.network.p2p_communication',
        'ai_antivirus.network.deep_packet_inspector',
        'ai_antivirus.network.network_anomaly_detector',
        'ai_antivirus.network.traffic_pattern_analyzer',
        'ai_antivirus.network.botnet_detector',
        
        # Protection modules
        'ai_antivirus.protection.browser_protection',
        'ai_antivirus.protection.real_time_protection',
        
        # Intelligence modules
        'ai_antivirus.intelligence.threat_intelligence_engine',
        'ai_antivirus.intelligence.threat_classifier',
        
        # AI modules
        'ai_antivirus.ai.model_optimizer',
        'ai_antivirus.ai.model_retraining_pipeline',
        'ai_antivirus.ai.zero_day_classifier',
        'ai_antivirus.ai.auto_tuning_system',
        
        # Reporting modules
        'ai_antivirus.reporting.analytics_engine',
        'ai_antivirus.reporting.executive_dashboard',
        'ai_antivirus.reporting.compliance_reporting',
        'ai_antivirus.reporting.trend_analysis',
        
        # GUI modules
        'ai_antivirus.gui.main_window',
        'ai_antivirus.gui.system_tray',
        'ai_antivirus.gui.reporting_dashboard',
        
        # Updater modules
        'ai_antivirus.updater.auto_updater',
        
        # DLP modules
        'ai_antivirus.dlp.data_loss_prevention',
        
        # Config modules
        'ai_antivirus.config.config_manager'
    ]
    
    for module_name in modules_to_setup:
        try:
            logger = setup_module_logging(module_name)
            logger.debug(f"Logger initialized for {module_name}")
        except Exception as e:
            # Use fallback logging if module logger setup fails
            logging.getLogger(__name__).warning(f"Failed to setup logger for {module_name}: {e}")

def patch_existing_loggers():
    """Patch existing module loggers to use comprehensive logging"""
    
    # List of modules that might already have loggers
    modules_with_loggers = [
        'src.core.ai_engine',
        'src.core.file_monitor',
        'src.core.quarantine',
        'src.detection.signature_engine',
        'src.detection.heuristic_analyzer',
        'src.gui.main_window',
        'src.network.p2p_communication',
        'src.protection.browser_protection',
        'src.updater.auto_updater'
    ]
    
    patched_count = 0
    
    for module_name in modules_with_loggers:
        try:
            if module_name in sys.modules:
                module = sys.modules[module_name]
                
                # Replace module-level logger
                if hasattr(module, 'logger'):
                    module.logger = setup_module_logging(module_name)
                    patched_count += 1
                
                # Look for class instances with loggers
                for attr_name in dir(module):
                    try:
                        attr = getattr(module, attr_name)
                        if hasattr(attr, 'logger') and hasattr(attr, '__class__'):
                            class_logger_name = f"{module_name}.{attr.__class__.__name__}"
                            attr.logger = setup_module_logging(class_logger_name)
                            patched_count += 1
                    except:
                        continue
                        
        except Exception as e:
            logging.getLogger(__name__).debug(f"Could not patch logger for {module_name}: {e}")
    
    if patched_count > 0:
        logging.getLogger(__name__).info(f"Patched {patched_count} existing loggers")

def setup_startup_logging():
    """Setup logging specifically for application startup"""
    
    startup_logger = setup_module_logging('ai_antivirus.startup')
    
    startup_logger.info("AI Antivirus Application Starting...")
    startup_logger.info(f"Working Directory: {os.getcwd()}")
    startup_logger.info(f"Python: {sys.version}")
    startup_logger.info(f"Platform: {sys.platform}")
    
    # Log command line arguments
    if len(sys.argv) > 1:
        startup_logger.info(f"Command Line Args: {' '.join(sys.argv[1:])}")
    
    return startup_logger

def setup_shutdown_logging():
    """Setup logging for application shutdown"""
    
    shutdown_logger = setup_module_logging('ai_antivirus.shutdown')
    
    def log_shutdown():
        shutdown_logger.info("AI Antivirus Application Shutting Down...")
        
        # Log final statistics
        comp_logger = get_comprehensive_logger()
        try:
            stats = comp_logger.get_log_statistics()
            shutdown_logger.info(f"Log Statistics: {stats['total_log_files']} files, {stats['total_log_size_mb']:.2f} MB")
        except:
            pass
        
        shutdown_logger.info("Shutdown Complete")
    
    # Register shutdown handler
    import atexit
    atexit.register(log_shutdown)
    
    return shutdown_logger

def create_debug_log_viewer():
    """Create a simple debug log viewer for development"""
    
    if getattr(sys, 'frozen', False):
        return  # Skip in production
    
    debug_script_path = Path(__file__).parent.parent.parent / 'debug_log_viewer.py'
    
    debug_script_content = '''#!/usr/bin/env python3
"""
Debug Log Viewer for AI Antivirus
Simple tool to view and filter log files during development
"""

import os
import sys
from pathlib import Path
import argparse
from datetime import datetime

def view_logs(log_dir, filter_level=None, filter_module=None, tail_lines=None):
    """View and filter log files"""
    
    log_files = list(Path(log_dir).glob('*.log'))
    
    if not log_files:
        print(f"No log files found in {log_dir}")
        return
    
    # Get the most recent main log file
    main_log = Path(log_dir) / 'aintivirus_main.log'
    
    if main_log.exists():
        print(f"📋 Viewing: {main_log}")
        print("=" * 80)
        
        with open(main_log, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
            # Apply filters
            filtered_lines = lines
            
            if filter_level:
                filtered_lines = [line for line in filtered_lines if filter_level.upper() in line]
            
            if filter_module:
                filtered_lines = [line for line in filtered_lines if filter_module in line]
            
            # Show tail if requested
            if tail_lines:
                filtered_lines = filtered_lines[-tail_lines:]
            
            for line in filtered_lines:
                print(line.rstrip())
    
    print("\\n" + "=" * 80)
    print(f"📁 Available log files in {log_dir}:")
    for log_file in sorted(log_files):
        size_mb = log_file.stat().st_size / (1024 * 1024)
        modified = datetime.fromtimestamp(log_file.stat().st_mtime)
        print(f"  📄 {log_file.name} ({size_mb:.2f} MB, modified: {modified.strftime('%Y-%m-%d %H:%M:%S')})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AI Antivirus Debug Log Viewer')
    parser.add_argument('--log-dir', default='logs', help='Log directory path')
    parser.add_argument('--level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Filter by log level')
    parser.add_argument('--module', help='Filter by module name')
    parser.add_argument('--tail', type=int, help='Show last N lines')
    
    args = parser.parse_args()
    
    view_logs(args.log_dir, args.level, args.module, args.tail)
'''
    
    try:
        with open(debug_script_path, 'w', encoding='utf-8') as f:
            f.write(debug_script_content)
        
        # Make executable on Unix systems
        if sys.platform != 'win32':
            os.chmod(debug_script_path, 0o755)
        
        logging.getLogger(__name__).info(f"Created debug log viewer: {debug_script_path}")
        
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to create debug log viewer: {e}")

# Auto-initialize when module is imported
if __name__ != "__main__":
    # Only auto-initialize if not running as script
    try:
        initialize_comprehensive_logging()
    except Exception as e:
        # Fallback to basic logging if comprehensive logging fails
        logging.basicConfig(level=logging.INFO)
        logging.getLogger(__name__).error(f"Failed to initialize comprehensive logging: {e}")
