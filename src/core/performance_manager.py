#!/usr/bin/env python3
"""
Minimal Performance Manager - Ultra-low resource usage
"""

import logging
import psutil
import time
from PyQt5.QtCore import QObject, QTimer, pyqtSignal

class PerformanceManager(QObject):
    """Minimal performance manager for ultra-low resource usage"""
    
    performance_alert = pyqtSignal(str, str)
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.performance_mode = "battery"
        
        # Realistic limits for AI Antivirus
        self.resource_limits = {
            "max_cpu_percent": 25.0,
            "max_memory_mb": 1024,  # 1GB reasonable for AI antivirus
            "max_threads": 50,      # Allow more threads for scanning
            "monitor_interval": 60.0  # Check every 60 seconds
        }
        
        # Create timer but don't start automatically
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self._check_resources)
        
        self.logger.info("Minimal performance manager initialized")
    
    def start_monitoring(self):
        """Start minimal resource monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            # Start with very slow monitoring interval
            self.monitor_timer.start(int(self.resource_limits["monitor_interval"] * 1000))
            self.logger.info("Minimal performance monitoring started")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        if self.is_monitoring:
            self.is_monitoring = False
            self.monitor_timer.stop()
            self.logger.info("Performance monitoring stopped")
    
    def _check_resources(self):
        """Accurate resource checking for current process only"""
        try:
            # Get accurate metrics for current process
            current_process = psutil.Process()
            cpu_percent = current_process.cpu_percent(interval=0.1)
            memory_mb = current_process.memory_info().rss / (1024 * 1024)
            thread_count = len(current_process.threads())
            
            # Only log if significantly over limits and trigger optimization
            if memory_mb > self.resource_limits["max_memory_mb"] * 2:
                self.logger.warning(f"Process memory usage {memory_mb:.1f}MB exceeds limit {self.resource_limits['max_memory_mb']}MB")
                # Trigger automatic memory optimization
                self.optimize_memory_usage()
            
            if thread_count > self.resource_limits["max_threads"] * 3:
                self.logger.warning(f"Process thread count {thread_count} exceeds limit {self.resource_limits['max_threads']}")
                # Trigger thread reduction
                self._reduce_thread_usage()
                
        except Exception as e:
            self.logger.error(f"Resource check error: {e}")
    
    def set_performance_mode(self, mode):
        """Set performance mode"""
        self.performance_mode = mode
        self.logger.info(f"Performance mode set to {mode}")
    
    def start(self):
        """Start performance monitoring"""
        self.start_monitoring()
    
    def get_current_limits(self):
        """Get current resource limits"""
        return self.resource_limits
    
    def get_system_metrics(self):
        """Get accurate system metrics for current process"""
        try:
            current_process = psutil.Process()
            return {
                'cpu_percent': current_process.cpu_percent(interval=0.1),
                'memory_mb': current_process.memory_info().rss / (1024 * 1024),
                'thread_count': len(current_process.threads())
            }
        except:
            return {'cpu_percent': 0, 'memory_mb': 0, 'thread_count': 0}
    
    def add_performance_callback(self, callback):
        """Add performance callback - minimal stub implementation"""
        self.logger.debug(f"Performance callback registered: {callback.__name__}")
        # Store callback for future use if needed
        if not hasattr(self, '_callbacks'):
            self._callbacks = []
        self._callbacks.append(callback)
    
    def add_throttling_callback(self, callback):
        """Add throttling callback - minimal stub implementation"""
        self.logger.debug(f"Throttling callback registered: {callback.__name__}")
        # Store callback for future use if needed
        if not hasattr(self, '_throttling_callbacks'):
            self._throttling_callbacks = []
        self._throttling_callbacks.append(callback)
    
    def get_performance_status(self):
        """Get current performance status"""
        try:
            metrics = self.get_system_metrics()
            return {
                'cpu_usage': metrics.get('cpu_percent', 0),
                'memory_usage': metrics.get('memory_mb', 0),
                'thread_count': metrics.get('thread_count', 0),
                'performance_mode': self.performance_mode,
                'monitoring_active': self.is_monitoring,
                'resource_limits': self.resource_limits
            }
        except Exception as e:
            self.logger.error(f"Error getting performance status: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'thread_count': 0,
                'performance_mode': self.performance_mode,
                'monitoring_active': False,
                'resource_limits': self.resource_limits
            }
    
    def optimize_memory_usage(self):
        """Optimize memory usage - minimal stub implementation"""
        try:
            import gc
            # Force garbage collection
            collected = gc.collect()
            self.logger.info(f"Memory optimization: garbage collected {collected} objects")
            
            # Log current memory usage
            metrics = self.get_system_metrics()
            memory_mb = metrics.get('memory_mb', 0)
            self.logger.info(f"Current memory usage: {memory_mb:.1f}MB")
            
            return {
                'objects_collected': collected,
                'current_memory_mb': memory_mb,
                'optimization_performed': True
            }
        except Exception as e:
            self.logger.error(f"Memory optimization error: {e}")
            return {
                'objects_collected': 0,
                'current_memory_mb': 0,
                'optimization_performed': False
            }
    
    def _reduce_thread_usage(self):
        """Reduce thread usage by notifying scan optimizer"""
        try:
            # Notify callbacks about thread reduction need
            if hasattr(self, '_throttling_callbacks'):
                for callback in self._throttling_callbacks:
                    try:
                        callback('reduce_threads')
                    except Exception as e:
                        self.logger.error(f"Thread reduction callback error: {e}")
            
            self.logger.info("Thread reduction requested")
        except Exception as e:
            self.logger.error(f"Thread reduction error: {e}")
