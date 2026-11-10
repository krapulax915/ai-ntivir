#!/usr/bin/env python3
"""
Scan Optimization System for AI Antivirus
Optimizes scan performance based on system resources and priorities
"""

import os
import time
import threading
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import queue
from datetime import datetime
import psutil

class ScanOptimizer:
    """Optimizes scan operations based on performance constraints"""
    
    def __init__(self, performance_manager):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.core.scan_optimizer')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.performance_manager = performance_manager
        
        # Scan queues by priority
        self.scan_queues = {
            'critical': queue.PriorityQueue(),
            'high': queue.PriorityQueue(),
            'normal': queue.PriorityQueue(),
            'low': queue.PriorityQueue(),
            'idle': queue.PriorityQueue()
        }
        
        # Worker threads
        self.worker_threads = []
        self.is_running = False
        
        # Performance tracking
        self.scan_stats = {
            'files_scanned': 0,
            'scan_time_total': 0.0,
            'avg_scan_time': 0.0,
            'throttle_events': 0
        }
        
        # Adaptive delays
        self.current_delay = 0.05
        self.min_delay = 0.01
        self.max_delay = 2.0
        
    def start(self):
        """Start scan optimization"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start minimal worker threads for ultra-low resource usage
        limits = self.performance_manager.get_current_limits()
        thread_count = min(limits.get('max_threads', 1), 1)  # Force maximum 1 thread
        
        for i in range(thread_count):
            worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            worker.start()
            self.worker_threads.append(worker)
        
        self.logger.info(f"Scan optimizer started with {thread_count} worker threads")
    
    def stop(self):
        """Stop scan optimization"""
        self.is_running = False
        
        # Clear all queues
        for queue_obj in self.scan_queues.values():
            while not queue_obj.empty():
                try:
                    queue_obj.get_nowait()
                except:
                    break
        
        self.worker_threads.clear()
        self.logger.info("Scan optimizer stopped")
    
    def queue_scan(self, file_path: str, priority: str = 'normal', callback: Callable = None):
        """Queue a file for scanning with specified priority"""
        try:
            if priority not in self.scan_queues:
                priority = 'normal'
            
            # Check if we should throttle based on performance
            from src.core.performance_manager import ScanPriority
            scan_priority = getattr(ScanPriority, priority.upper(), ScanPriority.NORMAL)
            
            if self.performance_manager.should_throttle_operation(scan_priority):
                # Downgrade priority or delay
                if priority != 'idle':
                    priority_order = ['critical', 'high', 'normal', 'low', 'idle']
                    current_index = priority_order.index(priority)
                    if current_index < len(priority_order) - 1:
                        priority = priority_order[current_index + 1]
                        self.scan_stats['throttle_events'] += 1
            
            # Add to appropriate queue
            scan_item = {
                'file_path': file_path,
                'priority': priority,
                'callback': callback,
                'queued_time': time.time()
            }
            
            self.scan_queues[priority].put((time.time(), scan_item))
            
        except Exception as e:
            self.logger.error(f"Error queuing scan for {file_path}: {e}")
    
    def _worker_loop(self, worker_id: int):
        """Main worker loop for processing scan queue"""
        while self.is_running:
            try:
                scan_item = self._get_next_scan_item()
                
                if scan_item:
                    self._process_scan_item(scan_item, worker_id)
                else:
                    # No items to process, wait a bit
                    time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in worker {worker_id}: {e}")
                time.sleep(1.0)
    
    def _get_next_scan_item(self):
        """Get next scan item based on priority"""
        # Check queues in priority order
        for priority in ['critical', 'high', 'normal', 'low', 'idle']:
            queue_obj = self.scan_queues[priority]
            
            if not queue_obj.empty():
                try:
                    _, scan_item = queue_obj.get_nowait()
                    return scan_item
                except queue.Empty:
                    continue
        
        return None
    
    def _process_scan_item(self, scan_item: Dict, worker_id: int):
        """Process a single scan item"""
        try:
            file_path = scan_item['file_path']
            priority = scan_item['priority']
            callback = scan_item['callback']
            
            # Calculate optimal delay
            from src.core.performance_manager import ScanPriority
            scan_priority = getattr(ScanPriority, priority.upper(), ScanPriority.NORMAL)
            delay = self.performance_manager.get_optimal_delay(scan_priority)
            
            # Apply delay before scanning
            if delay > 0:
                time.sleep(delay)
            
            # Perform the actual scan
            start_time = time.time()
            scan_result = self._perform_scan(file_path, priority)
            scan_time = time.time() - start_time
            
            # Update statistics
            self._update_scan_stats(scan_time)
            
            # Call callback if provided
            if callback:
                try:
                    callback(scan_result)
                except Exception as e:
                    self.logger.error(f"Error in scan callback: {e}")
            
            self.logger.debug(f"Worker {worker_id} scanned {file_path} in {scan_time:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Error processing scan item: {e}")
    
    def _perform_scan(self, file_path: str, priority: str) -> Dict:
        """Perform the actual file scan"""
        try:
            # This would integrate with the actual scanning engines
            # For now, return a placeholder result
            
            scan_result = {
                'file_path': file_path,
                'priority': priority,
                'scan_time': time.time(),
                'is_threat': False,
                'threat_score': 0.0,
                'scan_engines': ['placeholder'],
                'status': 'clean'
            }
            
            # Simulate scan time based on file size and priority
            try:
                file_size = os.path.getsize(file_path)
                base_time = min(file_size / 1000000, 0.1)  # Max 0.1s for large files
                
                # Adjust based on priority
                priority_multipliers = {
                    'critical': 1.0,
                    'high': 1.0,
                    'normal': 0.8,
                    'low': 0.5,
                    'idle': 0.3
                }
                
                scan_time = base_time * priority_multipliers.get(priority, 1.0)
                time.sleep(scan_time)
                
            except (OSError, IOError):
                # File doesn't exist or can't be accessed
                scan_result['status'] = 'error'
                scan_result['error'] = 'File access error'
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            return {
                'file_path': file_path,
                'priority': priority,
                'scan_time': time.time(),
                'status': 'error',
                'error': str(e)
            }
    
    def _update_scan_stats(self, scan_time: float):
        """Update scan statistics"""
        try:
            self.scan_stats['files_scanned'] += 1
            self.scan_stats['scan_time_total'] += scan_time
            
            # Calculate average scan time
            if self.scan_stats['files_scanned'] > 0:
                self.scan_stats['avg_scan_time'] = (
                    self.scan_stats['scan_time_total'] / self.scan_stats['files_scanned']
                )
            
        except Exception as e:
            self.logger.error(f"Error updating scan stats: {e}")
    
    def get_queue_status(self) -> Dict:
        """Get current queue status"""
        try:
            status = {}
            
            for priority, queue_obj in self.scan_queues.items():
                status[priority] = queue_obj.qsize()
            
            status['total_queued'] = sum(status.values())
            status['worker_threads'] = len(self.worker_threads)
            status['is_running'] = self.is_running
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error getting queue status: {e}")
            return {}
    
    def get_scan_statistics(self) -> Dict:
        """Get scan performance statistics"""
        try:
            stats = self.scan_stats.copy()
            
            # Add current performance metrics
            if self.performance_manager:
                performance_status = self.performance_manager.get_performance_status()
                stats.update({
                    'current_cpu': performance_status.get('current_metrics', {}).get('cpu_usage', 0),
                    'current_memory': performance_status.get('current_metrics', {}).get('memory_usage_mb', 0),
                    'performance_mode': performance_status.get('mode', 'unknown')
                })
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting scan statistics: {e}")
            return {}
    
    def adjust_worker_count(self, new_count: int):
        """Dynamically adjust worker thread count"""
        try:
            current_count = len(self.worker_threads)
            
            if new_count > current_count:
                # Add more workers
                for i in range(current_count, new_count):
                    worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
                    worker.start()
                    self.worker_threads.append(worker)
                
                self.logger.info(f"Increased worker count from {current_count} to {new_count}")
            
            elif new_count < current_count:
                # Remove workers (they will stop when is_running becomes False)
                # For now, just log the change - actual thread reduction would happen
                # when threads check is_running flag
                self.logger.info(f"Worker count will be reduced from {current_count} to {new_count}")
            
        except Exception as e:
            self.logger.error(f"Error adjusting worker count: {e}")
    
    def clear_low_priority_queues(self):
        """Clear low priority queues to free up resources"""
        try:
            cleared_count = 0
            
            for priority in ['low', 'idle']:
                queue_obj = self.scan_queues[priority]
                
                while not queue_obj.empty():
                    try:
                        queue_obj.get_nowait()
                        cleared_count += 1
                    except queue.Empty:
                        break
            
            if cleared_count > 0:
                self.logger.info(f"Cleared {cleared_count} low priority scan items")
            
        except Exception as e:
            self.logger.error(f"Error clearing low priority queues: {e}")
    
    def get_estimated_completion_time(self) -> float:
        """Estimate time to complete all queued scans"""
        try:
            total_items = sum(q.qsize() for q in self.scan_queues.values())
            
            if total_items == 0:
                return 0.0
            
            # Estimate based on average scan time and worker count
            avg_scan_time = self.scan_stats.get('avg_scan_time', 0.1)
            worker_count = len(self.worker_threads)
            
            if worker_count == 0:
                return float('inf')
            
            # Add current delay to scan time
            current_delay = self.performance_manager.get_optimal_delay() if self.performance_manager else 0.05
            estimated_time_per_item = avg_scan_time + current_delay
            
            # Estimate completion time
            estimated_time = (total_items * estimated_time_per_item) / worker_count
            
            return estimated_time
            
        except Exception as e:
            self.logger.error(f"Error estimating completion time: {e}")
            return 0.0
