import os
import time
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Dict, List, Callable, Set
from pathlib import Path
import queue

class ThreatFileHandler(FileSystemEventHandler):
    """File system event handler for real-time monitoring"""
    
    def __init__(self, callback: Callable):
        super().__init__()
        self.callback = callback
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.core.file_monitor')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.monitored_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.com', '.pif', '.application', '.gadget', '.msi',
            '.cpl', '.hta', '.ins', '.isp', '.jse', '.lib', '.lnk',
            '.mde', '.msc', '.msp', '.mst', '.pcd', '.pif', '.reg',
            '.scf', '.sct', '.shb', '.shs', '.url', '.vb', '.vbe',
            '.vbs', '.wsc', '.wsf', '.wsh'
        }
        
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._process_file_event(event.src_path, 'created')
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._process_file_event(event.src_path, 'modified')
    
    def on_moved(self, event):
        """Handle file move/rename events"""
        if not event.is_directory:
            self._process_file_event(event.dest_path, 'moved')
    
    def _process_file_event(self, file_path: str, event_type: str):
        """Process file system events"""
        try:
            # Check if file extension is suspicious
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.monitored_extensions or self._is_suspicious_location(file_path):
                self.logger.info(f"Suspicious file {event_type}: {file_path}")
                self.callback(file_path, event_type)
        except Exception as e:
            self.logger.error(f"Error processing file event: {e}")
    
    def _is_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in a suspicious location"""
        file_path_lower = file_path.lower()
        
        # Always whitelist system directories first
        if ('windows\\system32' in file_path_lower or 
            'windows\\syswow64' in file_path_lower or
            'windows\\winsxs' in file_path_lower):
            return False
        
        # Whitelist for legitimate system and application paths
        legitimate_paths = [
            # System directories
            'program files', 'program files (x86)', 'programdata\\microsoft',
            
            # Browser directories
            'mozilla firefox', 'google\\chrome', 'microsoft\\edge',
            'microsoft\\edgeupdate', 'opera software', 'appdata\\local\\microsoft\\edge',
            'appdata\\local\\google\\chrome', 'appdata\\roaming\\mozilla',
            
            # Windows Update and system components
            'windows\\servicing', 'windows\\softwaredistribution',
            'windows\\system.diagnostics', 'windows\\microsoft.net',
            
            # Python and development environments
            'python\\python3', 'appdata\\local\\programs\\python',
            'site-packages\\pyqt5', 'lib\\site-packages', '.venv\\lib',
            '.venv\\scripts', 'venv\\lib', 'virtualenv', 'conda',
            
            # Antivirus software directories
            'kaspersky lab', 'common files\\kaspersky', 'klhk',
            'avast software', 'avg', 'norton', 'mcafee',
            
            # Driver and hardware vendors
            'amd-catalyst', 'nvidia', 'intel', 'realtek', 'ati',
            
            # Common legitimate application paths
            'appdata\\local\\programs', 'appdata\\local\\microsoft\\windowsapps'
        ]
        
        # First check if it's in a legitimate path - if so, not suspicious
        for legitimate_path in legitimate_paths:
            if legitimate_path in file_path_lower:
                return False
        
        # Only flag truly suspicious locations
        truly_suspicious_paths = [
            'temp\\malware', 'temp\\virus', 'downloads\\unknown',
            'desktop\\suspicious', 'users\\public\\temp',
            'appdata\\local\\temp\\rar', 'appdata\\local\\temp\\7z'
        ]
        
        for suspicious_path in truly_suspicious_paths:
            if suspicious_path in file_path_lower:
                return True
        
        return False

class FileMonitor:
    """Real-time file system monitoring for threat detection"""
    
    def __init__(self, ai_engine, quarantine_manager):
        self.ai_engine = ai_engine
        self.quarantine_manager = quarantine_manager
        self.logger = logging.getLogger(__name__)
        self.observer = Observer()
        # FIX: start/stop use self.is_running, which never existed until the
        # first start; any status query before that raised AttributeError.
        self.is_running = False
        self.is_monitoring = False
        self.monitored_paths = set()  # Changed from list to set
        self.excluded_paths = {
            "C:\\Windows\\System32",
            "C:\\Program Files\\Windows Defender"
        }
        self.observers = []
        self.scan_queue = queue.Queue()
        self.worker_threads = []
        self.max_file_size = 100 * 1024 * 1024  # 100MB max scan size
        self.scan_timeout = 30  # 30 seconds max scan time
        
    def start(self):
        """Start file monitoring"""
        self.start_monitoring()
        
    def stop(self):
        """Stop file monitoring"""
        self.stop_monitoring()
        
    def start_monitoring(self, paths: List[str] = None):
        """Start real-time file monitoring"""
        if paths is None:
            paths = self._get_default_monitor_paths()
        
        self.is_running = True
        
        # Start worker threads for file analysis
        for i in range(3):  # 3 worker threads
            worker = threading.Thread(target=self._scan_worker, daemon=True)
            worker.start()
            self.worker_threads.append(worker)
        
        # Set up file system observers
        for path in paths:
            if os.path.exists(path):
                self._add_monitor_path(path)
        
        self.logger.info(f"File monitoring started for {len(self.monitored_paths)} paths")
    
    def stop_monitoring(self):
        """Stop file monitoring"""
        self.is_running = False
        
        # Stop all observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
        self.monitored_paths.clear()
        self.logger.info("File monitoring stopped")
    
    def _add_monitor_path(self, path: str):
        """Add path to monitoring"""
        try:
            observer = Observer()
            event_handler = ThreatFileHandler(self._on_file_event)
            observer.schedule(event_handler, path, recursive=True)
            observer.start()
            
            self.observers.append(observer)
            self.monitored_paths.add(path)
            self.logger.info(f"Monitoring path: {path}")
            
        except Exception as e:
            self.logger.error(f"Failed to monitor path {path}: {e}")
    
    def _on_file_event(self, file_path: str, event_type: str):
        """Handle file system events"""
        try:
            # Add to scan queue for analysis
            if os.path.exists(file_path) and os.path.getsize(file_path) <= self.max_file_size:
                self.scan_queue.put({
                    'file_path': file_path,
                    'event_type': event_type,
                    'timestamp': time.time()
                })
        except Exception as e:
            self.logger.error(f"Error queuing file for scan: {e}")
    
    def _scan_worker(self):
        """Worker thread for file analysis"""
        while self.is_running:
            try:
                # Get file from queue with timeout
                scan_item = self.scan_queue.get(timeout=1)
                
                file_path = scan_item['file_path']
                event_type = scan_item['event_type']
                
                # Analyze file with AI engine
                analysis_result = self.ai_engine.analyze_file(file_path)
                
                # Handle threats based on score
                self._handle_threat_result(analysis_result, event_type, file_path)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Scan worker error: {e}")
    
    def _handle_threat_result(self, result, event_type: str, file_path: str = None):
        """Handle threat analysis results"""
        # Handle both float and dict results from AI engine
        if isinstance(result, float):
            threat_score = result
            threat_level = 'high' if result > 0.7 else 'medium' if result > 0.3 else 'low'
        else:
            threat_score = result.get('threat_score', 0.0)
            threat_level = result.get('threat_level', 'unknown')
            if not file_path:
                file_path = result.get('file_path')
        
        self.logger.info(f"File analysis: {file_path} - Score: {threat_score:.2f} ({threat_level})")
        
        # Take action based on threat level with proper thresholds
        if threat_score >= 0.7:  # Critical threat
            self._handle_critical_threat(result)
        elif threat_score >= 0.3:  # High threat
            self._handle_high_threat(result)
        elif threat_score >= 0.1:  # Medium threat (raised from 0.0)
            self._handle_medium_threat(result)
        # Files with score < 0.1 are considered safe and not flagged
        
        # Log all detections
        self._log_detection(result, event_type)
    
    def _handle_critical_threat(self, result):
        """Handle critical threats - immediate quarantine"""
        # Handle both float and dict results
        if isinstance(result, float):
            self.logger.critical(f"CRITICAL THREAT DETECTED: Score {result:.2f}")
            return
        
        file_path = result.get('file_path') if isinstance(result, dict) else None
        if not file_path:
            self.logger.error("Cannot handle critical threat: no file path provided")
            return
        try:
            # Immediately quarantine the file
            if self.quarantine_manager.quarantine_file(file_path, result):
                self.logger.critical(f"CRITICAL THREAT QUARANTINED: {file_path}")
                self._send_alert(result, "CRITICAL THREAT DETECTED AND QUARANTINED")
            else:
                self.logger.error(f"Failed to quarantine critical threat: {file_path}")
        except Exception as e:
            self.logger.error(f"Error handling critical threat: {e}")
    
    def _handle_high_threat(self, result):
        """Handle high threats - quarantine with user notification"""
        # Handle both float and dict results
        if isinstance(result, float):
            self.logger.warning(f"HIGH THREAT DETECTED: Score {result:.2f}")
            return
        
        file_path = result.get('file_path') if isinstance(result, dict) else None
        if not file_path:
            self.logger.error("Cannot handle high threat: no file path provided")
            return
        try:
            if self.quarantine_manager.quarantine_file(file_path, result):
                self.logger.warning(f"HIGH THREAT QUARANTINED: {file_path}")
                self._send_alert(result, "HIGH THREAT DETECTED AND QUARANTINED")
        except Exception as e:
            self.logger.error(f"Error handling high threat: {e}")
    
    def _handle_medium_threat(self, result):
        """Handle medium threats - log and alert"""
        # Handle both float and dict results
        if isinstance(result, float):
            self.logger.info(f"MEDIUM THREAT DETECTED: Score {result:.2f}")
            return
        
        file_path = result.get('file_path') if isinstance(result, dict) else None
        if not file_path:
            self.logger.error("Cannot handle medium threat: no file path provided")
            return
        self.logger.warning(f"MEDIUM THREAT DETECTED: {file_path}")
        self._send_alert(result, "SUSPICIOUS FILE DETECTED")
    
    def _send_alert(self, result, message: str):
        """Send threat alert to user interface"""
        # Handle both float and dict results
        if isinstance(result, float):
            alert_data = {
                'message': message,
                'threat_score': result,
                'threat_level': 'high' if result > 0.7 else 'medium' if result > 0.3 else 'low'
            }
        else:
            alert_data = {
                'message': message,
                'file_path': result.get('file_path', 'Unknown'),
                'threat_score': result.get('threat_score', 0.0),
                'threat_level': result.get('threat_level', 'unknown'),
                'timestamp': result.get('timestamp', time.time())
            }
        # TODO: Implement GUI notification system
        self.logger.info(f"ALERT: {alert_data}")
    
    def _log_detection(self, result, event_type: str):
        """Log detection details"""
        # Handle both float and dict results
        if isinstance(result, float):
            detection_data = {
                'timestamp': time.time(),
                'event_type': event_type,
                'threat_score': result,
                'threat_level': 'high' if result > 0.7 else 'medium' if result > 0.3 else 'low'
            }
        else:
            detection_data = {
                'timestamp': time.time(),
                'event_type': event_type,
                'file_path': result.get('file_path', 'Unknown'),
                'threat_score': result.get('threat_score', 0.0),
                'threat_level': result.get('threat_level', 'unknown'),
                'features': result.get('features', {})
            }
        # TODO: Implement detection logging to database
        self.logger.debug(f"Detection logged: {detection_data}")
    
    def _get_default_monitor_paths(self) -> List[str]:
        """Get default paths to monitor"""
        default_paths = []
        
        # System paths
        system_paths = [
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expandvars("%TEMP%"),
            os.path.expandvars("%APPDATA%"),
            "C:\\Windows\\Temp"
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                default_paths.append(path)

        # FIX: removed the drive-root loop (C:\, D:\, ...). Recursive watchdog
        # observation of every drive root also watched Windows, Program Files
        # and the app's own quarantine folder, which re-scanned quarantined
        # files and caused a self-feeding quarantine loop. The specific user
        # and temp paths above are the intended monitoring scope.
        return default_paths
    
    def add_custom_path(self, path: str):
        """Add custom path to monitoring"""
        if os.path.exists(path) and path not in self.monitored_paths:
            self._add_monitor_path(path)
    
    def remove_path(self, path: str):
        """Remove path from monitoring"""
        # Find and stop the observer for this path
        for i, observer in enumerate(self.observers):
            if path in self.monitored_paths:
                observer.stop()
                observer.join()
                self.observers.pop(i)
                self.monitored_paths.remove(path)
                self.logger.info(f"Stopped monitoring: {path}")
                break
    
    def get_monitoring_stats(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'monitored_paths': len(self.monitored_paths),
            'queue_size': self.scan_queue.qsize(),
            'worker_threads': len(self.worker_threads),
            'is_running': self.is_running
        }
