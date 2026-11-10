#!/usr/bin/env python3
"""
Real-Time Protection System for AI Antivirus
Enhanced file system monitoring with immediate threat response
"""

import os
import time
import threading
import logging
import queue
import json
from datetime import datetime
from typing import Dict, List, Set, Optional, Callable
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileMovedEvent

class PrioritizedScanItem:
    """Wrapper for scan items to make them comparable in priority queue"""
    def __init__(self, priority: int, scan_item: Dict, timestamp: float):
        self.priority = priority
        self.scan_item = scan_item
        self.timestamp = timestamp
    
    def __lt__(self, other):
        # Lower priority number = higher priority
        if self.priority != other.priority:
            return self.priority < other.priority
        # If same priority, use timestamp (older first)
        return self.timestamp < other.timestamp
    
    def __eq__(self, other):
        return self.priority == other.priority and self.timestamp == other.timestamp

class RealTimeProtectionHandler(FileSystemEventHandler):
    """Enhanced file system event handler for real-time protection"""
    
    def __init__(self, protection_engine):
        super().__init__()
        self.protection_engine = protection_engine
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.real_time_protection')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Critical file extensions that require immediate scanning
        self.critical_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.com', '.pif', '.application', '.gadget', '.msi',
            '.cpl', '.hta', '.ins', '.isp', '.jse', '.lib', '.lnk',
            '.mde', '.msc', '.msp', '.mst', '.pcd', '.reg',
            '.scf', '.sct', '.shb', '.shs', '.url', '.vb', '.vbe',
            '.wsc', '.wsf', '.wsh', '.zip', '.rar', '.7z', '.tar'
        }
        
        # Recently processed files to avoid duplicate scans
        self.recent_files = {}
        self.recent_files_lock = threading.Lock()
        
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._queue_file_for_scan(event.src_path, 'created')
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._queue_file_for_scan(event.src_path, 'modified')
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if not event.is_directory:
            self._queue_file_for_scan(event.dest_path, 'moved')
    
    def _queue_file_for_scan(self, file_path: str, event_type: str):
        """Queue file for scanning with deduplication"""
        try:
            # Skip if file doesn't exist or is too large
            if not os.path.exists(file_path):
                return
                
            file_size = os.path.getsize(file_path)
            if file_size > 500 * 1024 * 1024:  # Skip files > 500MB
                return
            
            # Check if we should scan this file
            if not self._should_scan_file(file_path):
                return
            
            # Deduplication - avoid scanning same file multiple times quickly
            with self.recent_files_lock:
                current_time = time.time()
                file_key = f"{file_path}:{file_size}"
                
                if file_key in self.recent_files:
                    if current_time - self.recent_files[file_key] < 5:  # 5 second cooldown
                        return
                
                self.recent_files[file_key] = current_time
                
                # Clean old entries
                old_keys = [k for k, v in self.recent_files.items() if current_time - v > 60]
                for key in old_keys:
                    del self.recent_files[key]
            
            # Queue for scanning
            self.protection_engine.queue_file_scan(file_path, event_type, file_size)
            
        except Exception as e:
            self.logger.error(f"Error queuing file {file_path}: {e}")
    
    def _should_scan_file(self, file_path: str) -> bool:
        """Determine if file should be scanned"""
        try:
            file_path_lower = file_path.lower()
            file_ext = Path(file_path).suffix.lower()
            
            # Always scan critical extensions
            if file_ext in self.critical_extensions:
                return True
            
            # Skip system files and trusted locations
            trusted_paths = [
                'windows\\system32', 'windows\\syswow64', 'windows\\winsxs',
                'program files\\windows defender', 'program files\\microsoft',
                'programdata\\microsoft\\windows defender'
            ]
            
            for trusted_path in trusted_paths:
                if trusted_path in file_path_lower:
                    return False
            
            # Scan files in suspicious locations
            suspicious_paths = [
                'downloads', 'desktop', 'temp', 'tmp', 'appdata\\local\\temp',
                'users\\public', 'documents\\downloads'
            ]
            
            for suspicious_path in suspicious_paths:
                if suspicious_path in file_path_lower:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking file scan criteria: {e}")
            return True  # Default to scanning on error
            

class RealTimeProtectionEngine:
    """Main real-time protection engine"""
    
    def __init__(self, ai_engine=None, quarantine_manager=None, threat_callback=None, log_management=None, signature_engine=None):
        """Initialize real-time protection system"""
        self.logger = logging.getLogger(__name__)
        self.protection_logger = logging.getLogger('real_time_protection')
        self.log_management = log_management
        self.ai_engine = ai_engine
        self.quarantine_manager = quarantine_manager
        self.threat_callback = threat_callback
        self.signature_engine = signature_engine
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.real_time_protection')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Protection state
        self.is_active = False
        self.is_paused = False
        
        # File system monitoring
        self.observers = []
        self.monitored_paths = set()
        # Scanning queue and workers
        self.scan_queue = queue.PriorityQueue()
        self.worker_threads = []
        self.max_workers = 3
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'files_quarantined': 0,
            'start_time': None,
            'last_threat_time': None
        }
        
        # Callbacks for GUI integration (threat_callback already set in line 162)
        # CRITICAL FIX: Don't overwrite threat_callback!
        if self.threat_callback is None:
            self.threat_callback = None
        self.status_callback = None
        
        # Protection settings
        self.settings = {
            'auto_quarantine': True,
            'scan_archives': True,
            'scan_network_drives': False,
            'threat_threshold': 0.6,
            'suspicious_threshold': 0.3
        }
        
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup protection-specific logging"""
        try:
            os.makedirs('logs/protection', exist_ok=True)
            
            # Create protection log handler
            log_file = f'logs/protection/real_time_protection_{datetime.now().strftime("%Y%m%d")}.log'
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            
            self.protection_logger = logging.getLogger('real_time_protection')
            # FIX: a new FileHandler was added on every engine construction,
            # duplicating every log line after restarts. Add only if none present.
            if not self.protection_logger.handlers:
                self.protection_logger.addHandler(handler)
            self.protection_logger.setLevel(logging.INFO)
            
        except Exception as e:
            self.logger.error(f"Failed to setup protection logging: {e}")
    
    def start_protection(self, monitored_paths: List[str] = None):
        """Start real-time protection"""
        try:
            if self.is_active:
                self.logger.warning("Real-time protection already active")
                return True
            
            self.logger.info("🛡️ Starting real-time protection...")
            
            # Set default paths if none provided
            if monitored_paths is None:
                monitored_paths = self._get_default_protection_paths()
            
            # Start worker threads
            self._start_worker_threads()
            
            # Start file system monitoring
            self._start_file_monitoring(monitored_paths)
            
            # Update state
            self.is_active = True
            self.is_paused = False
            self.stats['start_time'] = datetime.now()
            
            self.logger.info(f"✅ Real-time protection started - monitoring {len(self.monitored_paths)} paths")
            self.protection_logger.info(f"Real-time protection started - {len(self.monitored_paths)} paths monitored")
            
            # Notify GUI
            if self.status_callback:
                self.status_callback("active", f"Monitoring {len(self.monitored_paths)} locations")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start real-time protection: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop real-time protection monitoring (alias for stop_protection)"""
        return self.stop_protection()
    
    def stop_protection(self):
        """Stop real-time protection"""
        try:
            if not self.is_active:
                return True
            
            self.logger.info("🛑 Stopping real-time protection...")
            
            # Stop file monitoring
            self._stop_file_monitoring()
            
            # Stop worker threads
            self._stop_worker_threads()
            
            # Update state
            self.is_active = False
            self.is_paused = False
            
            self.logger.info("✅ Real-time protection stopped")
            self.protection_logger.info("Real-time protection stopped")
            
            # Notify GUI
            if self.status_callback:
                self.status_callback("stopped", "Protection disabled")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop real-time protection: {e}")
            return False
    
    def pause_protection(self):
        """Pause real-time protection"""
        if self.is_active:
            self.is_paused = True
            self.logger.info("⏸️ Real-time protection paused")
            if self.status_callback:
                self.status_callback("paused", "Protection paused")
    
    def resume_protection(self):
        """Resume real-time protection"""
        if self.is_active and self.is_paused:
            self.is_paused = False
            self.logger.info("▶️ Real-time protection resumed")
            if self.status_callback:
                self.status_callback("active", f"Monitoring {len(self.monitored_paths)} locations")
    
    def queue_file_scan(self, file_path: str, event_type: str, file_size: int):
        """Queue file for scanning with priority"""
        if self.is_paused:
            return
        
        # Determine priority (lower number = higher priority)
        priority = self._calculate_scan_priority(file_path, event_type, file_size)
        
        scan_item = {
            'file_path': file_path,
            'event_type': event_type,
            'file_size': file_size,
            'timestamp': time.time(),
            'priority': priority
        }
        
        try:
            # Use PrioritizedScanItem wrapper to fix comparison error
            prioritized_item = PrioritizedScanItem(priority, scan_item, time.time())
            self.scan_queue.put(prioritized_item)
            self.logger.debug(f"Queued for scan: {file_path} (priority: {priority})")
        except Exception as e:
            self.logger.error(f"Failed to queue file scan: {e}")
    
    def _calculate_scan_priority(self, file_path: str, event_type: str, file_size: int) -> int:
        """Calculate scan priority based on file characteristics"""
        priority = 5  # Default priority
        
        file_path_lower = file_path.lower()
        file_ext = Path(file_path).suffix.lower()
        
        # Higher priority for executable files
        if file_ext in {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1'}:
            priority = 1
        
        # Higher priority for suspicious locations
        if any(path in file_path_lower for path in ['downloads', 'temp', 'desktop']):
            priority = max(1, priority - 1)
        
        # Higher priority for newly created files
        if event_type == 'created':
            priority = max(1, priority - 1)
        
        # Lower priority for very large files
        if file_size > 50 * 1024 * 1024:  # > 50MB
            priority += 2
        
        return priority
    
    def _start_worker_threads(self):
        """Start worker threads for file scanning"""
        self.worker_threads = []
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._scan_worker, daemon=True, name=f"ScanWorker-{i}")
            worker.start()
            self.worker_threads.append(worker)
        
        self.logger.info(f"Started {self.max_workers} scan worker threads")
    
    def _stop_worker_threads(self):
        """Stop worker threads"""
        # Signal workers to stop by putting None items in queue
        # FIX: use the LOWEST priority (999) for stop sentinels. With priority 0
        # the sentinels jumped ahead of every queued threat scan and queued
        # detections were silently dropped on stop.
        for _ in range(self.max_workers):
            stop_item = PrioritizedScanItem(999, None, time.time())
            self.scan_queue.put(stop_item)
        
        # Wait for workers to finish
        for worker in self.worker_threads:
            worker.join(timeout=5)
        
        self.worker_threads = []
    
    def _scan_worker(self):
        """Worker thread for scanning files"""
        while True:
            try:
                # Get scan item from queue
                prioritized_item = self.scan_queue.get(timeout=1)
                scan_item = prioritized_item.scan_item
                
                # Check for stop signal
                if scan_item is None:
                    break
                
                # Skip if protection is paused
                # FIX: re-queue the item instead of dropping it. The item was
                # already consumed from the queue here, so dropping it meant
                # files queued just before pause were never scanned.
                if self.is_paused:
                    self.scan_queue.put(prioritized_item)
                    time.sleep(0.2)
                    continue
                
                # Scan the file
                self._scan_file(scan_item)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Scan worker error: {e}")
    
    def _scan_file(self, scan_item: Dict):
        """Scan individual file for threats"""
        file_path = scan_item['file_path']
        event_type = scan_item['event_type']
        
        try:
            # Skip if file no longer exists
            if not os.path.exists(file_path):
                return
            
            self.logger.debug(f"Scanning file: {file_path}")
            self.stats['files_scanned'] += 1
            
            # Perform multi-engine analysis
            scan_results = self._analyze_file(file_path)
            
            # Handle results based on threat level
            self._handle_scan_results(scan_results, event_type)
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
    
    def _analyze_file(self, file_path: str) -> Dict:
        """Analyze file using available engines"""
        results = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'threat_score': 0.0,
            'is_threat': False,
            'threat_type': 'unknown',
            'engine_results': {}
        }
        
        max_threat_score = 0.0
        
        try:
            # AI Engine analysis
            if self.ai_engine:
                ai_result = self.ai_engine.analyze_file(file_path)
                if ai_result:
                    ai_score = ai_result.get('threat_score', 0.0)
                    results['engine_results']['ai'] = ai_result
                    max_threat_score = max(max_threat_score, ai_score)
            
            # Signature Engine analysis
            if self.signature_engine:
                sig_result = self.signature_engine.check_file_signature(file_path)
                if sig_result:
                    sig_score = 1.0 if sig_result.get('is_threat', False) else 0.0
                    results['engine_results']['signature'] = sig_result
                    max_threat_score = max(max_threat_score, sig_score)
                    
                    if sig_result.get('is_threat'):
                        results['threat_type'] = sig_result.get('threat_name', 'malware')
            
            # Update final results
            results['threat_score'] = max_threat_score
            results['is_threat'] = max_threat_score >= self.settings['threat_threshold']
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return results
    
    def _handle_scan_results(self, results: Dict, event_type: str):
        """Handle scan results and take appropriate action"""
        file_path = results['file_path']
        threat_score = results['threat_score']
        is_threat = results['is_threat']
        
        # Log the result
        self.protection_logger.info(
            f"Scan result: {file_path} | Score: {threat_score:.2f} | "
            f"Threat: {is_threat} | Event: {event_type}"
        )
        
        if is_threat:
            self._handle_threat_detected(results, event_type)
        elif threat_score >= self.settings['suspicious_threshold']:
            self._handle_suspicious_file(results, event_type)
    
    def _handle_threat_detected(self, results: Dict, event_type: str):
        """Handle detected threats"""
        file_path = results['file_path']
        threat_score = results['threat_score']
        
        self.stats['threats_detected'] += 1
        self.stats['last_threat_time'] = datetime.now()
        
        self.logger.warning(f"THREAT DETECTED: {file_path} (Score: {threat_score:.2f})")
        self.protection_logger.warning(f"THREAT DETECTED: {file_path} | Score: {threat_score:.2f}")
        
        # Log to threat management system
        if self.log_management:
            threat_data = {
                'file_path': file_path,
                'threat_level': 'HIGH' if threat_score > 0.8 else 'MEDIUM',
                'threat_type': results.get('threat_type', 'Unknown'),
                'detection_method': results.get('detection_method', 'Real-time Protection'),
                'threat_score': threat_score,
                'action': 'Detected',
                'event_type': event_type
            }
            self.log_management.log_threat_detection(threat_data)
        
        # ENHANCED AUTO-QUARANTINE RULES
        quarantine_required = False
        quarantine_reason = ""
        
        
        # EMERGENCY RULE: Score 1.00 threats - ALWAYS quarantine
        if threat_score >= 1.0:
            quarantine_required = True
            quarantine_reason = f"EMERGENCY: Perfect threat score: {threat_score:.2f}"
        
        # EMERGENCY RULE: Score 0.9+ threats - ALWAYS quarantine
        elif threat_score >= 0.9:
            quarantine_required = True
            quarantine_reason = f"EMERGENCY: Very high threat score: {threat_score:.2f}"
        
        # Rule 1: High threat score (>0.7) - MANDATORY quarantine
        elif threat_score >= 0.7:
            quarantine_required = True
            quarantine_reason = f"High threat score: {threat_score:.2f}"
        
        # Rule 2: EICAR test files - MANDATORY quarantine
        elif 'eicar' in file_path.lower():
            quarantine_required = True
            quarantine_reason = "EICAR test file detected"
        
        # Rule 3: Suspicious file extensions - MANDATORY quarantine
        elif any(file_path.lower().endswith(ext) for ext in ['.com', '.scr', '.pif', '.bat', '.cmd']):
            if threat_score >= 0.4:  # Lower threshold for dangerous extensions
                quarantine_required = True
                quarantine_reason = f"Dangerous extension + threat score: {threat_score:.2f}"
        
        # Rule 4: Download folder threats - MANDATORY quarantine
        elif 'downloads' in file_path.lower() and threat_score >= 0.3:
            quarantine_required = True
            quarantine_reason = f"Download folder threat: {threat_score:.2f}"
        
        # Rule 5: Partial/temporary files with threats - MANDATORY quarantine
        elif any(ext in file_path.lower() for ext in ['.part', '.tmp', '.temp']) and threat_score >= 0.5:
            quarantine_required = True
            quarantine_reason = f"Temporary/partial file threat: {threat_score:.2f}"
        
        
        # Execute quarantine if required
        # FIX: log clearly if the quarantine manager is missing instead of
        # silently skipping the emergency quarantine.
        if quarantine_required and not self.quarantine_manager:
            self.logger.error("❌ QUARANTINE SKIPPED: no quarantine_manager configured")
            self.protection_logger.error("QUARANTINE SKIPPED: no quarantine_manager configured")
        if quarantine_required and self.quarantine_manager:
            # CRITICAL FIX: Log IMMEDIATELY when quarantine is triggered
            self.logger.info(f"🔄 ATTEMPTING QUARANTINE: {file_path} - {quarantine_reason}")
            self.protection_logger.info(f"ATTEMPTING QUARANTINE: {file_path}")
            
            try:
                # CRITICAL FIX: Ensure quarantine_manager is not None
                if self.quarantine_manager is None:
                    self.logger.error("❌ CRITICAL: quarantine_manager is None!")
                    self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - quarantine_manager is None")
                    return
                
                # Enhanced threat info for quarantine
                enhanced_results = results.copy()
                enhanced_results['quarantine_reason'] = quarantine_reason
                enhanced_results['auto_quarantine'] = True
                enhanced_results['threat_level'] = 'CRITICAL' if threat_score >= 0.8 else 'HIGH'
                
                # CRITICAL FIX V14: Enhanced file tracking with rename detection
                original_file_path = file_path
                if not os.path.exists(file_path):
                    self.logger.warning(f"⚠️ Original file not found: {file_path}")
                    self.logger.info(f"🔍 Searching for renamed file (browser may have completed download)...")
                    
                    # Try to find renamed file
                    file_dir = os.path.dirname(file_path)
                    file_basename = os.path.basename(file_path)
                    
                    # Remove common download extensions
                    base_name = file_basename.replace('.part', '').replace('.tmp', '').replace('.download', '')
                    
                    possible_files = []
                    if os.path.exists(file_dir):
                        try:
                            for f in os.listdir(file_dir):
                                # FIX: require an exact name match (ignoring the
                                # temp extensions). The previous substring match
                                # ('base_name in f') could quarantine an unrelated
                                # file such as 'myinvoice.pdf2' for a detected
                                # 'invoice.pdf.part'.
                                if f == base_name or os.path.splitext(f)[0] == os.path.splitext(base_name)[0]:
                                    possible_path = os.path.join(file_dir, f)
                                    if os.path.isfile(possible_path):
                                        possible_files.append(possible_path)
                        except Exception as scan_err:
                            self.logger.error(f"Error scanning directory: {scan_err}")
                    
                    if possible_files:
                        self.logger.info(f"✅ Found {len(possible_files)} possible renamed file(s):")
                        for pf in possible_files:
                            pf_size = os.path.getsize(pf) if os.path.exists(pf) else 0
                            self.logger.info(f"   - {os.path.basename(pf)} ({pf_size} bytes)")
                        
                        # Use the first valid file (non-zero size)
                        for pf in possible_files:
                            if os.path.exists(pf) and os.path.getsize(pf) > 0:
                                file_path = pf
                                self.logger.info(f"🎯 Using renamed file for quarantine: {os.path.basename(pf)}")
                                break
                    
                    # Final check
                    if not os.path.exists(file_path):
                        self.logger.error(f"❌ File not found for quarantine: {original_file_path}")
                        self.logger.error(f"   File disappeared between detection and quarantine (RACE CONDITION)")
                        self.logger.error(f"   No renamed files found in directory")
                        self.protection_logger.error(f"QUARANTINE FAILED: {original_file_path} - file not found (race condition)")
                        return
                
                # Check file size WITH RETRY LOGIC (race condition fix)
                try:
                    file_size = os.path.getsize(file_path)
                    
                    # CRITICAL FIX: If zero-byte, wait and retry (file might be downloading)
                    if file_size == 0:
                        self.logger.info(f"⏳ Zero-byte file detected, waiting for download to complete: {file_path}")
                        
                        # Wait up to 10 seconds for file to grow
                        max_retries = 10
                        for retry in range(max_retries):
                            time.sleep(1)
                            
                            if not os.path.exists(file_path):
                                self.logger.warning(f"File disappeared during wait: {file_path}")
                                self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - file disappeared during retry")
                                return
                            
                            file_size = os.path.getsize(file_path)
                            if file_size > 0:
                                self.logger.info(f"✅ File ready after {retry+1}s: {file_path} ({file_size} bytes)")
                                break
                        
                        # After 10 retries, still zero-byte
                        if file_size == 0:
                            self.logger.warning(f"Skipping zero-byte file after {max_retries}s wait: {file_path}")
                            self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - zero-byte file after retry")
                            return
                    
                except Exception as size_error:
                    self.logger.error(f"Error checking file size: {file_path} - {size_error}")
                    self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - size check error: {size_error}")
                    return
                
                # CRITICAL FIX: Call quarantine IMMEDIATELY
                quarantine_success = self.quarantine_manager.quarantine_file(file_path, enhanced_results)
                
                if quarantine_success:
                    self.stats['threats_blocked'] += 1
                    self.stats['files_quarantined'] += 1
                    # Track quarantine success statistics
                    if 'quarantine_successes' not in self.stats:
                        self.stats['quarantine_successes'] = 0
                    self.stats['quarantine_successes'] += 1
                    
                    self.logger.warning(f"🔒 MANDATORY QUARANTINE SUCCESS: {file_path} - {quarantine_reason}")
                    self.protection_logger.info(f"THREAT QUARANTINED: {file_path} - SUCCESS")
                    
                    # CRITICAL FIX: Notify GUI about threat quarantined
                    if self.threat_callback:
                        self.threat_callback({
                            'type': 'threat_quarantined',
                            'file_path': file_path,
                            'threat_score': threat_score,
                            'quarantine_reason': quarantine_reason,
                            'results': results
                        })
                    
                    # Update threat log with quarantine action
                    if self.log_management:
                        threat_data['action'] = 'Quarantined'
                        threat_data['quarantine_reason'] = quarantine_reason
                        self.log_management.log_threat_detection(threat_data)
                else:
                    # Quarantine failed - log critical error with DETAILED info
                    self.logger.error(f"❌ QUARANTINE OPERATION FAILED: {file_path} - {quarantine_reason}")
                    
                    # CRITICAL: Detailed failure analysis
                    file_exists_now = os.path.exists(file_path)
                    self.logger.error(f"   Quarantine manager type: {type(self.quarantine_manager)}")
                    self.logger.error(f"   File exists NOW: {file_exists_now}")
                    
                    if file_exists_now:
                        try:
                            file_size_now = os.path.getsize(file_path)
                            self.logger.error(f"   File size NOW: {file_size_now} bytes")
                        except Exception as e:
                            self.logger.error(f"   Cannot get file size: {e}")
                    else:
                        self.logger.error(f"   File DISAPPEARED during quarantine operation (RACE CONDITION)")
                    
                    self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - quarantine operation returned False")
                    
            except Exception as quarantine_error:
                # Critical quarantine exception with FULL details
                self.logger.error(f"❌ QUARANTINE EXCEPTION: {file_path} - {quarantine_error}")
                self.protection_logger.error(f"QUARANTINE FAILED: {file_path} - exception: {str(quarantine_error)[:100]}")
                
                # Log exception details
                import traceback
                self.logger.error(f"   Exception type: {type(quarantine_error).__name__}")
                self.logger.error(f"   Exception details: {traceback.format_exc()}")
                
                # Additional context
                self.logger.error(f"   File exists during exception: {os.path.exists(file_path)}")
                self.logger.error(f"   Quarantine manager: {self.quarantine_manager}")
        
    def _handle_suspicious_file(self, results: Dict, event_type: str):
        """Handle suspicious files"""
        file_path = results['file_path']
        threat_score = results['threat_score']
        
        self.logger.info(f"⚠️ Suspicious file: {file_path} (Score: {threat_score:.2f})")
        self.protection_logger.info(f"SUSPICIOUS FILE: {file_path} | Score: {threat_score:.2f}")
        
        # Notify GUI about suspicious file
        if self.threat_callback:
            self.threat_callback({
                'type': 'suspicious_file',
                'file_path': file_path,
                'threat_score': threat_score,
                'results': results
            })
    
    def _start_file_monitoring(self, paths: List[str]):
        """Start file system monitoring"""
        self.observers = []
        self.monitored_paths = set()
        
        for path in paths:
            try:
                if os.path.exists(path):
                    observer = Observer()
                    event_handler = RealTimeProtectionHandler(self)
                    observer.schedule(event_handler, path, recursive=True)
                    observer.start()
                    
                    self.observers.append(observer)
                    self.monitored_paths.add(path)
                    self.logger.info(f"Monitoring: {path}")
                    
            except Exception as e:
                self.logger.error(f"Failed to monitor path {path}: {e}")
    
    def _stop_file_monitoring(self):
        """Stop file system monitoring"""
        for observer in self.observers:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as e:
                self.logger.error(f"Error stopping observer: {e}")
        
        self.observers = []
        self.monitored_paths = set()
    
    def _get_default_protection_paths(self) -> List[str]:
        """Get default paths for protection"""
        paths = []
        
        # User directories
        user_paths = [
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expandvars("%TEMP%"),
            # FIX: %APPDATA%\Local\Temp expands to ...\AppData\Roaming\Local\Temp
            # which does not exist; the real user temp dir is %LOCALAPPDATA%\Temp
            os.path.expandvars("%LOCALAPPDATA%\\Temp")
        ]
        
        for path in user_paths:
            if os.path.exists(path):
                paths.append(path)
        
        # System temp directories
        system_temps = ["C:\\Windows\\Temp", "C:\\Temp"]
        for path in system_temps:
            if os.path.exists(path):
                paths.append(path)
        
        return paths
    
    def get_protection_status(self) -> Dict:
        """Get current protection status"""
        return {
            'is_active': self.is_active,
            'is_paused': self.is_paused,
            'monitored_paths': len(self.monitored_paths),
            'queue_size': self.scan_queue.qsize(),
            'worker_threads': len(self.worker_threads),
            'stats': self.stats.copy(),
            'settings': self.settings.copy()
        }
    
    def update_settings(self, new_settings: Dict):
        """Update protection settings"""
        self.settings.update(new_settings)
        self.logger.info(f"Protection settings updated: {new_settings}")
    
    def set_threat_callback(self, callback: Callable):
        """Set callback for threat notifications"""
        self.threat_callback = callback
    
    def set_status_callback(self, callback: Callable):
        """Set callback for status updates"""
        self.status_callback = callback
