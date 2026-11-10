#!/usr/bin/env python3
"""
Comprehensive Logging System for AI Antivirus
Centralized logging with automatic environment detection and log rotation
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import json
import threading
from typing import Dict, Any, Optional
import traceback

class ComprehensiveLogger:
    """Centralized logging system with environment detection"""
    
    def __init__(self, app_name: str = "AI-Antivirus"):
        self.app_name = app_name
        self.loggers: Dict[str, logging.Logger] = {}
        self.log_dir = self._determine_log_directory()
        self.setup_complete = False
        self._lock = threading.Lock()
        
        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Setup main logger
        self.setup_comprehensive_logging()
    
    def _determine_log_directory(self) -> str:
        """Determine appropriate log directory based on environment"""
        try:
            # Check if running from executable (production)
            if getattr(sys, 'frozen', False):
                # Running as executable
                program_files = os.environ.get('PROGRAMFILES', 'C:\\Program Files')
                log_dir = os.path.join(program_files, self.app_name, 'logs')
                
                # Try to create directory, fallback if no permissions
                try:
                    os.makedirs(log_dir, exist_ok=True)
                    # Test write permissions
                    test_file = os.path.join(log_dir, 'test_write.tmp')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
                    return log_dir
                except (PermissionError, OSError):
                    # Fallback to user directory
                    user_dir = os.path.expanduser('~')
                    log_dir = os.path.join(user_dir, 'AppData', 'Local', self.app_name, 'logs')
                    os.makedirs(log_dir, exist_ok=True)
                    return log_dir
            else:
                # Development environment - use project root
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = current_dir
                
                # Navigate up to find project root (look for main.py or setup.py)
                while project_root and project_root != os.path.dirname(project_root):
                    if (os.path.exists(os.path.join(project_root, 'main.py')) or 
                        os.path.exists(os.path.join(project_root, 'setup.py')) or
                        os.path.exists(os.path.join(project_root, 'README.md'))):
                        break
                    project_root = os.path.dirname(project_root)
                
                # Use project root or fallback to current directory
                if not project_root or project_root == os.path.dirname(project_root):
                    project_root = os.path.dirname(os.path.dirname(current_dir))
                
                log_dir = os.path.join(project_root, 'logs')
                os.makedirs(log_dir, exist_ok=True)
                return log_dir
                
        except Exception as e:
            # Ultimate fallback
            fallback_dir = os.path.join(os.getcwd(), 'logs')
            os.makedirs(fallback_dir, exist_ok=True)
            return fallback_dir
    
    def setup_comprehensive_logging(self):
        """Setup comprehensive logging configuration"""
        with self._lock:
            if self.setup_complete:
                return
            
            # Clear any existing handlers
            logging.getLogger().handlers.clear()
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)-30s | %(funcName)-20s:%(lineno)-4d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            simple_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            console_formatter = logging.Formatter(
                '%(levelname)-8s | %(name)-20s | %(message)s'
            )
            
            # Setup file handlers with rotation
            self._setup_file_handlers(detailed_formatter, simple_formatter)
            
            # Setup console handler
            self._setup_console_handler(console_formatter)
            
            # Setup error handler
            self._setup_error_handler(detailed_formatter)
            
            # Setup performance handler
            self._setup_performance_handler(simple_formatter)
            
            # Setup security handler
            self._setup_security_handler(detailed_formatter)
            
            # Create system info log
            self._log_system_info()
            
            self.setup_complete = True
    
    def _setup_file_handlers(self, detailed_formatter, simple_formatter):
        """Setup rotating file handlers"""
        # Main application log
        main_log_file = os.path.join(self.log_dir, 'aintivirus_main.log')
        main_handler = logging.handlers.RotatingFileHandler(
            main_log_file, maxBytes=50*1024*1024, backupCount=10, encoding='utf-8'
        )
        main_handler.setLevel(logging.DEBUG)
        main_handler.setFormatter(detailed_formatter)
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(main_handler)
        
        # Daily log file
        daily_log_file = os.path.join(self.log_dir, f'daily_{datetime.now().strftime("%Y%m%d")}.log')
        daily_handler = logging.handlers.TimedRotatingFileHandler(
            daily_log_file, when='midnight', interval=1, backupCount=30, encoding='utf-8'
        )
        daily_handler.setLevel(logging.INFO)
        daily_handler.setFormatter(simple_formatter)
        root_logger.addHandler(daily_handler)
    
    def _setup_console_handler(self, console_formatter):
        """Setup console handler for development"""
        if not getattr(sys, 'frozen', False):  # Only in development
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(console_formatter)
            logging.getLogger().addHandler(console_handler)
    
    def _setup_error_handler(self, detailed_formatter):
        """Setup dedicated error log handler"""
        error_log_file = os.path.join(self.log_dir, 'errors.log')
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        logging.getLogger().addHandler(error_handler)
    
    def _setup_performance_handler(self, simple_formatter):
        """Setup performance monitoring log"""
        perf_log_file = os.path.join(self.log_dir, 'performance.log')
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log_file, maxBytes=20*1024*1024, backupCount=3, encoding='utf-8'
        )
        perf_handler.setLevel(logging.WARNING)
        perf_handler.setFormatter(simple_formatter)
        
        # Create performance logger
        perf_logger = logging.getLogger('performance')
        perf_logger.addHandler(perf_handler)
        perf_logger.setLevel(logging.WARNING)
        perf_logger.propagate = False
    
    def _setup_security_handler(self, detailed_formatter):
        """Setup security events log"""
        security_log_file = os.path.join(self.log_dir, 'security_events.log')
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file, maxBytes=100*1024*1024, backupCount=10, encoding='utf-8'
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(detailed_formatter)
        
        # Create security logger
        security_logger = logging.getLogger('security')
        security_logger.addHandler(security_handler)
        security_logger.setLevel(logging.INFO)
        security_logger.propagate = False
    
    def _log_system_info(self):
        """Log system information at startup"""
        try:
            import platform
            import psutil
            
            system_info = {
                'timestamp': datetime.now().isoformat(),
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'memory_total': f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
                'log_directory': self.log_dir,
                'environment': 'production' if getattr(sys, 'frozen', False) else 'development'
            }
            
            system_log_file = os.path.join(self.log_dir, 'system_info.json')
            with open(system_log_file, 'w', encoding='utf-8') as f:
                json.dump(system_info, f, indent=2, ensure_ascii=False)
            
            # Log to main logger
            logger = logging.getLogger(__name__)
            logger.info(f"AI Antivirus logging system initialized")
            logger.info(f"Log directory: {self.log_dir}")
            logger.info(f"Environment: {system_info['environment']}")
            logger.info(f"Platform: {system_info['platform']}")
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to log system info: {e}")
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the given name"""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        return self.loggers[name]
    
    def log_exception(self, logger_name: str, exception: Exception, context: str = ""):
        """Log exception with full traceback"""
        logger = self.get_logger(logger_name)
        error_msg = f"Exception in {context}: {str(exception)}"
        logger.error(error_msg)
        logger.error(f"Traceback: {traceback.format_exc()}")
    
    def log_performance_warning(self, component: str, metric: str, value: float, threshold: float):
        """Log performance warnings"""
        perf_logger = logging.getLogger('performance')
        perf_logger.warning(f"{component} - {metric}: {value:.2f} exceeds threshold {threshold:.2f}")
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security events"""
        security_logger = logging.getLogger('security')
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        log_method = getattr(security_logger, severity.lower(), security_logger.info)
        log_method(f"SECURITY_EVENT: {json.dumps(event_data, ensure_ascii=False)}")
    
    def log_threat_detection(self, file_path: str, threat_score: float, detection_method: str, action_taken: str):
        """Log threat detection events"""
        self.log_security_event(
            event_type="THREAT_DETECTION",
            details={
                'file_path': file_path,
                'threat_score': threat_score,
                'detection_method': detection_method,
                'action_taken': action_taken
            },
            severity="WARNING" if threat_score > 0.7 else "INFO"
        )
    
    def log_scan_results(self, scan_type: str, files_scanned: int, threats_found: int, duration: float):
        """Log scan completion results"""
        logger = self.get_logger('scan_results')
        logger.info(f"SCAN_COMPLETE: {scan_type} - Files: {files_scanned}, Threats: {threats_found}, Duration: {duration:.2f}s")
    
    def log_module_initialization(self, module_name: str, success: bool, details: str = ""):
        """Log module initialization"""
        logger = self.get_logger('initialization')
        if success:
            logger.info(f"MODULE_INIT_SUCCESS: {module_name} - {details}")
        else:
            logger.error(f"MODULE_INIT_FAILED: {module_name} - {details}")
    
    def log_configuration_change(self, setting: str, old_value: Any, new_value: Any, user: str = "system"):
        """Log configuration changes"""
        self.log_security_event(
            event_type="CONFIGURATION_CHANGE",
            details={
                'setting': setting,
                'old_value': str(old_value),
                'new_value': str(new_value),
                'changed_by': user
            },
            severity="INFO"
        )
    
    def cleanup_old_logs(self, days_to_keep: int = 30):
        """Clean up old log files"""
        try:
            cutoff_time = datetime.now().timestamp() - (days_to_keep * 24 * 3600)
            
            for file_path in Path(self.log_dir).glob('*.log*'):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    logging.getLogger(__name__).info(f"Deleted old log file: {file_path}")
                    
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to cleanup old logs: {e}")
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        try:
            stats = {
                'log_directory': self.log_dir,
                'total_log_files': 0,
                'total_log_size_mb': 0.0,
                'log_files': []
            }
            
            for file_path in Path(self.log_dir).glob('*.log*'):
                file_size = file_path.stat().st_size
                stats['total_log_files'] += 1
                stats['total_log_size_mb'] += file_size / (1024 * 1024)
                stats['log_files'].append({
                    'name': file_path.name,
                    'size_mb': file_size / (1024 * 1024),
                    'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                })
            
            return stats
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to get log statistics: {e}")
            return {'error': str(e)}

# Global logger instance
_global_logger_instance: Optional[ComprehensiveLogger] = None

def get_comprehensive_logger() -> ComprehensiveLogger:
    """Get global comprehensive logger instance"""
    global _global_logger_instance
    if _global_logger_instance is None:
        _global_logger_instance = ComprehensiveLogger()
    return _global_logger_instance

def setup_module_logging(module_name: str) -> logging.Logger:
    """Setup logging for a specific module"""
    comprehensive_logger = get_comprehensive_logger()
    return comprehensive_logger.get_logger(module_name)

# Convenience functions
def log_exception(module_name: str, exception: Exception, context: str = ""):
    """Convenience function to log exceptions"""
    get_comprehensive_logger().log_exception(module_name, exception, context)

def log_security_event(event_type: str, details: Dict[str, Any], severity: str = "INFO"):
    """Convenience function to log security events"""
    get_comprehensive_logger().log_security_event(event_type, details, severity)

def log_threat_detection(file_path: str, threat_score: float, detection_method: str, action_taken: str):
    """Convenience function to log threat detections"""
    get_comprehensive_logger().log_threat_detection(file_path, threat_score, detection_method, action_taken)

def log_performance_warning(component: str, metric: str, value: float, threshold: float):
    """Convenience function to log performance warnings"""
    get_comprehensive_logger().log_performance_warning(component, metric, value, threshold)
