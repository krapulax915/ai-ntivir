import os
import time
import threading
import logging
from pathlib import Path

class SimpleRealTimeProtection:
    """Simplified real-time protection using polling"""
    
    def __init__(self, ai_engine, quarantine_manager):
        self.ai_engine = ai_engine
        self.quarantine_manager = quarantine_manager
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.simple_realtime')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.monitor_thread = None
        
        # Directories to monitor
        self.watch_dirs = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "C:\\Temp"
        ]
        
        # File tracking
        self.known_files = {}
        self.scan_interval = 5  # seconds
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_running:
            return True
            
        self.logger.info("🛡️ Starting simplified real-time protection...")
        self.is_running = True
        
        # Initialize known files
        self._scan_directories_initial()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("✅ Real-time protection started")
        return True
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.logger.info("🛑 Real-time protection stopped")
    
    def _scan_directories_initial(self):
        """Initial scan of directories"""
        for directory in self.watch_dirs:
            if os.path.exists(directory):
                self._scan_directory(directory, initial=True)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_running:
            try:
                for directory in self.watch_dirs:
                    if os.path.exists(directory):
                        self._scan_directory(directory)
                
                time.sleep(self.scan_interval)
                
            except Exception as e:
                self.logger.error(f"Monitor loop error: {e}")
                time.sleep(1)
    
    def _scan_directory(self, directory, initial=False):
        """Scan directory for new/changed files"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories
                if any(skip in root.lower() for skip in ['system32', 'syswow64', 'winsxs']):
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Get file stats
                        stat = os.stat(file_path)
                        file_key = f"{file_path}_{stat.st_size}_{stat.st_mtime}"
                        
                        # Check if file is new or changed
                        if file_key not in self.known_files:
                            if not initial:
                                self._scan_new_file(file_path)
                            self.known_files[file_key] = time.time()
                            
                    except (OSError, PermissionError):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Directory scan error: {e}")
    
    def _scan_new_file(self, file_path):
        """Scan new file for threats"""
        try:
            # Skip temp files
            if file_path.lower().endswith(('.tmp', '.temp', '.log')):
                return
            
            self.logger.info(f"🔍 Real-time scan: {os.path.basename(file_path)}")
            
            # AI scan
            threat_score = self.ai_engine.analyze_file(file_path)
            if isinstance(threat_score, dict):
                threat_score = threat_score.get('threat_score', 0.0)
            
            # High threat threshold for real-time
            if threat_score > 0.8:
                self.logger.warning(f"🚨 Real-time threat detected: {file_path}")
                self.logger.warning(f"   Threat score: {threat_score:.3f}")
                
                # Quarantine
                result = self.quarantine_manager.quarantine_file(
                    file_path, "Real-time detection"
                )
                
                if result.get('success'):
                    self.logger.info(f"✅ File quarantined: {file_path}")
                else:
                    self.logger.error(f"❌ Quarantine failed: {file_path}")
            
        except Exception as e:
            self.logger.error(f"File scan error: {e}")
