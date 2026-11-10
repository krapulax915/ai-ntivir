#!/usr/bin/env python3
"""
Logging Integration Module
Integrates comprehensive logging into existing AI Antivirus modules
"""

import logging
import functools
import time
from typing import Any, Callable, Dict, Optional
from .comprehensive_logger import get_comprehensive_logger, setup_module_logging

def logged_method(log_entry: bool = True, log_exit: bool = True, log_duration: bool = True):
    """Decorator to add comprehensive logging to methods"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get logger for the module
            if args and hasattr(args[0], '__class__'):
                module_name = f"{args[0].__class__.__module__}.{args[0].__class__.__name__}"
            else:
                module_name = func.__module__
            
            logger = setup_module_logging(module_name)
            
            # Log method entry
            if log_entry:
                logger.debug(f"ENTER: {func.__name__}() with args={len(args)}, kwargs={list(kwargs.keys())}")
            
            start_time = time.time() if log_duration else None
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful exit
                if log_exit:
                    duration = f" (Duration: {time.time() - start_time:.3f}s)" if log_duration else ""
                    logger.debug(f"EXIT: {func.__name__}() completed successfully{duration}")
                
                return result
                
            except Exception as e:
                # Log exception
                duration = f" (Duration: {time.time() - start_time:.3f}s)" if log_duration else ""
                logger.error(f"EXCEPTION: {func.__name__}() failed{duration}: {str(e)}")
                get_comprehensive_logger().log_exception(module_name, e, f"{func.__name__}()")
                raise
        
        return wrapper
    return decorator

def performance_monitor(threshold_seconds: float = 1.0):
    """Decorator to monitor method performance"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if duration > threshold_seconds:
                    module_name = f"{args[0].__class__.__module__}.{args[0].__class__.__name__}" if args and hasattr(args[0], '__class__') else func.__module__
                    get_comprehensive_logger().log_performance_warning(
                        component=module_name,
                        metric=f"{func.__name__}_duration",
                        value=duration,
                        threshold=threshold_seconds
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                module_name = f"{args[0].__class__.__module__}.{args[0].__class__.__name__}" if args and hasattr(args[0], '__class__') else func.__module__
                logger = setup_module_logging(module_name)
                logger.error(f"Performance monitor: {func.__name__} failed after {duration:.3f}s: {str(e)}")
                raise
        
        return wrapper
    return decorator

class LoggedClass:
    """Base class that provides comprehensive logging for all methods"""
    
    def __init__(self):
        self._logger = setup_module_logging(f"{self.__class__.__module__}.{self.__class__.__name__}")
        self._logger.info(f"Initializing {self.__class__.__name__}")
    
    def log_info(self, message: str, **kwargs):
        """Log info message with optional context"""
        if kwargs:
            message = f"{message} | Context: {kwargs}"
        self._logger.info(message)
    
    def log_warning(self, message: str, **kwargs):
        """Log warning message with optional context"""
        if kwargs:
            message = f"{message} | Context: {kwargs}"
        self._logger.warning(message)
    
    def log_error(self, message: str, exception: Optional[Exception] = None, **kwargs):
        """Log error message with optional exception and context"""
        if kwargs:
            message = f"{message} | Context: {kwargs}"
        self._logger.error(message)
        
        if exception:
            get_comprehensive_logger().log_exception(
                f"{self.__class__.__module__}.{self.__class__.__name__}",
                exception,
                message
            )
    
    def log_debug(self, message: str, **kwargs):
        """Log debug message with optional context"""
        if kwargs:
            message = f"{message} | Context: {kwargs}"
        self._logger.debug(message)

def integrate_logging_into_existing_modules():
    """Integrate comprehensive logging into existing modules"""
    
    # Patch existing loggers to use comprehensive logging
    import sys
    
    # Get all loaded modules
    for module_name, module in sys.modules.items():
        if module and module_name.startswith('src.'):
            try:
                # Replace module logger if it exists
                if hasattr(module, 'logger'):
                    module.logger = setup_module_logging(module_name)
                
                # Look for classes with logger attributes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if hasattr(attr, '__class__') and hasattr(attr, 'logger'):
                        attr.logger = setup_module_logging(f"{module_name}.{attr.__class__.__name__}")
                        
            except Exception:
                # Ignore errors during integration
                pass

# Context managers for logging
class LoggedOperation:
    """Context manager for logging operations"""
    
    def __init__(self, operation_name: str, logger_name: str = None):
        self.operation_name = operation_name
        self.logger = setup_module_logging(logger_name or __name__)
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        self.logger.info(f"OPERATION_START: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        
        if exc_type is None:
            self.logger.info(f"OPERATION_SUCCESS: {self.operation_name} completed in {duration:.3f}s")
        else:
            self.logger.error(f"OPERATION_FAILED: {self.operation_name} failed after {duration:.3f}s: {exc_val}")
            get_comprehensive_logger().log_exception(
                self.logger.name,
                exc_val,
                f"Operation: {self.operation_name}"
            )
        
        return False  # Don't suppress exceptions

class SecurityEventLogger:
    """Helper class for logging security events"""
    
    @staticmethod
    def log_file_scan(file_path: str, threat_score: float, detection_method: str, scan_duration: float):
        """Log file scan event"""
        get_comprehensive_logger().log_security_event(
            event_type="FILE_SCAN",
            details={
                'file_path': file_path,
                'threat_score': threat_score,
                'detection_method': detection_method,
                'scan_duration': scan_duration
            },
            severity="DEBUG"
        )
    
    @staticmethod
    def log_quarantine_action(file_path: str, reason: str, success: bool):
        """Log quarantine action"""
        get_comprehensive_logger().log_security_event(
            event_type="QUARANTINE_ACTION",
            details={
                'file_path': file_path,
                'reason': reason,
                'success': success
            },
            severity="WARNING"
        )
    
    @staticmethod
    def log_network_event(event_type: str, source_ip: str, destination: str, blocked: bool):
        """Log network security event"""
        get_comprehensive_logger().log_security_event(
            event_type="NETWORK_EVENT",
            details={
                'network_event_type': event_type,
                'source_ip': source_ip,
                'destination': destination,
                'blocked': blocked
            },
            severity="WARNING" if blocked else "INFO"
        )
    
    @staticmethod
    def log_user_action(action: str, user: str, details: Dict[str, Any]):
        """Log user action"""
        get_comprehensive_logger().log_security_event(
            event_type="USER_ACTION",
            details={
                'action': action,
                'user': user,
                **details
            },
            severity="INFO"
        )

# Module initialization logging
def log_module_startup(module_name: str, version: str = None, dependencies: list = None):
    """Log module startup information"""
    logger = setup_module_logging(module_name)
    
    startup_info = {
        'module': module_name,
        'version': version,
        'dependencies': dependencies or []
    }
    
    logger.info(f"MODULE_STARTUP: {module_name}")
    if version:
        logger.info(f"MODULE_VERSION: {version}")
    if dependencies:
        logger.info(f"MODULE_DEPENDENCIES: {', '.join(dependencies)}")
    
    get_comprehensive_logger().log_module_initialization(module_name, True, f"Version: {version}")

# Performance tracking
class PerformanceTracker:
    """Track and log performance metrics"""
    
    def __init__(self, component_name: str):
        self.component_name = component_name
        self.logger = setup_module_logging(f"performance.{component_name}")
        self.metrics = {}
    
    def track_metric(self, metric_name: str, value: float, threshold: float = None):
        """Track a performance metric"""
        self.metrics[metric_name] = value
        
        if threshold and value > threshold:
            get_comprehensive_logger().log_performance_warning(
                component=self.component_name,
                metric=metric_name,
                value=value,
                threshold=threshold
            )
        
        self.logger.debug(f"METRIC: {metric_name} = {value}")
    
    def log_summary(self):
        """Log performance summary"""
        self.logger.info(f"PERFORMANCE_SUMMARY: {self.component_name} - {self.metrics}")
