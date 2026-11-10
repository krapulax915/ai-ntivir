#!/usr/bin/env python3
"""
Real-time File System Monitoring - Advanced file system monitoring with AI integration
"""

import os
import sys
import time
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
import queue
import hashlib

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ..core.ai_engine import AIEngine
from ..detection.signature_engine import SignatureEngine
from ..detection.anomaly_detector import AnomalyDetector

class RealTimeFileMonitor(FileSystemEventHandler):
    """Real-time file system monitor with AI threat detection"""
    
    def __init__(self, ai_engine: AIEngine, signature_engine: SignatureEngine, 
                 anomaly_detector: AnomalyDetector):
        super().__init__()
        
        self.ai_engine = ai_engine
        self.signature_engine = signature_engine
        self.anomaly_detector = anomaly_detector
        
        # Monitoring configuration - use accessible paths
        self.monitored_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"), 
            os.path.expanduser("~/Documents"),
            os.path.join(os.path.dirname(__file__), "test_files")  # Local test directory
        ]
        
        # File processing queue
        self.file_queue = queue.Queue(maxsize=1000)
        self.processing_thread = None
        self.running = False
        
        # Monitoring statistics
        self.stats = {
            'files_monitored': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'false_positives': 0,
            'processing_time': []
        }
        
        # File filters
        self.monitored_extensions = {
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.scr', '.com', '.pif',
            '.jar', '.zip', '.rar', '.7z', '.tar', '.gz',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
            '.js', '.vbs', '.ps1', '.sh', '.py', '.pl'
        }
        
        self.ignored_paths = {
            'windows/system32', 'windows/syswow64', 'program files',
            'program files (x86)', 'windows/winsxs', '.git', 'node_modules',
            '__pycache__', '.venv', 'venv'
        }
        
        # Recent files cache (to avoid duplicate processing)
        self.recent_files = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Initialize monitoring database
        self.init_monitoring_db()
        
        # Setup logging
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.monitoring.realtime_monitoring')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
    def init_monitoring_db(self):
        """Initialize monitoring database"""
        try:
            os.makedirs("logs", exist_ok=True)
            self.db_path = "logs/realtime_monitoring.db"
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # File monitoring events
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        event_type TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER,
                        file_hash TEXT,
                        threat_detected BOOLEAN DEFAULT FALSE,
                        threat_name TEXT,
                        threat_level INTEGER,
                        action_taken TEXT,
                        processing_time REAL
                    )
                ''')
                
                # Quarantine log
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        threat_name TEXT,
                        threat_level INTEGER,
                        detection_method TEXT,
                        restored BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON file_events(file_path)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON file_events(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_detected ON file_events(threat_detected)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring database: {e}")
    
    def should_monitor_file(self, file_path: str) -> bool:
        """Determine if file should be monitored"""
        try:
            path_lower = file_path.lower()
            
            # Check ignored paths
            for ignored in self.ignored_paths:
                if ignored in path_lower:
                    return False
            
            # Check file extension - monitor all files for testing, not just specific extensions
            file_ext = Path(file_path).suffix.lower()
            
            # Skip some obviously safe extensions
            safe_extensions = {'.txt', '.log', '.jpg', '.png', '.gif', '.mp3', '.mp4', '.avi'}
            if file_ext in safe_extensions:
                return False
            
            # Check file size (ignore very large files for performance)
            try:
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    if file_size > 500 * 1024 * 1024:  # > 500MB
                        return False
                    if file_size == 0:  # Empty files
                        return False
            except:
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error checking file monitoring criteria: {e}")
            return False
    
    def is_recently_processed(self, file_path: str) -> bool:
        """Check if file was recently processed"""
        try:
            file_stat = os.stat(file_path)
            file_key = f"{file_path}_{file_stat.st_size}_{file_stat.st_mtime}"
            
            current_time = time.time()
            
            # Clean expired entries
            expired_keys = [
                key for key, timestamp in self.recent_files.items()
                if current_time - timestamp > self.cache_ttl
            ]
            for key in expired_keys:
                del self.recent_files[key]
            
            # Check if recently processed
            if file_key in self.recent_files:
                return True
            
            # Mark as processed
            self.recent_files[file_key] = current_time
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking recent processing: {e}")
            return False
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory and self.should_monitor_file(event.src_path):
            if not self.is_recently_processed(event.src_path):
                self.queue_file_for_analysis(event.src_path, "created")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory and self.should_monitor_file(event.src_path):
            if not self.is_recently_processed(event.src_path):
                self.queue_file_for_analysis(event.src_path, "modified")
    
    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory and self.should_monitor_file(event.dest_path):
            if not self.is_recently_processed(event.dest_path):
                self.queue_file_for_analysis(event.dest_path, "moved")
    
    def queue_file_for_analysis(self, file_path: str, event_type: str):
        """Queue file for threat analysis"""
        try:
            if not self.file_queue.full():
                self.file_queue.put((file_path, event_type, time.time()))
                self.stats['files_monitored'] += 1
            else:
                self.logger.warning("File processing queue is full, skipping file")
        except Exception as e:
            self.logger.error(f"Failed to queue file for analysis: {e}")
    
    def analyze_file_threat(self, file_path: str) -> Dict:
        """Comprehensive threat analysis of file"""
        start_time = time.time()
        
        try:
            # AI-based analysis
            ai_result = self.ai_engine.predict_with_ai_model(file_path)
            ai_threat = ai_result > 0.7 if ai_result else False
            
            # Signature-based analysis
            sig_result = self.signature_engine.check_file_signature(file_path)
            sig_threat = sig_result.get('is_threat', False)
            
            # Anomaly-based analysis
            anomaly_result = self.anomaly_detector.analyze_file_anomalies(file_path)
            anomaly_threat = anomaly_result.get('is_anomaly', False) if anomaly_result else False
            
            # Combine results
            threat_detected = ai_threat or sig_threat or anomaly_threat
            
            # Determine threat level and name
            threat_level = 0
            threat_name = "Clean"
            detection_method = "combined"
            
            if sig_threat:
                threat_level = sig_result.get('threat_level', 5)
                threat_name = sig_result.get('threat_name', 'Unknown Signature')
                detection_method = "signature"
            elif ai_threat:
                threat_level = int(ai_result * 10) if ai_result else 5
                threat_name = f"AI Detected Threat (confidence: {ai_result:.2f})"
                detection_method = "ai"
            elif anomaly_threat:
                threat_level = anomaly_result.get('threat_level', 3)
                threat_name = "Behavioral Anomaly"
                detection_method = "anomaly"
            
            processing_time = time.time() - start_time
            self.stats['processing_time'].append(processing_time)
            
            return {
                'threat_detected': threat_detected,
                'threat_name': threat_name,
                'threat_level': threat_level,
                'detection_method': detection_method,
                'ai_score': ai_result,
                'signature_match': sig_threat,
                'anomaly_detected': anomaly_threat,
                'processing_time': processing_time
            }
            
        except Exception as e:
            self.logger.error(f"Threat analysis failed for {file_path}: {e}")
            return {
                'threat_detected': False,
                'threat_name': 'Analysis Failed',
                'error': str(e)
            }
    
    def quarantine_file(self, file_path: str, threat_info: Dict) -> bool:
        """Quarantine detected threat"""
        try:
            # Create quarantine directory
            quarantine_dir = "quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Generate quarantine filename
            file_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
            timestamp = int(time.time())
            quarantine_name = f"{file_hash}_{timestamp}"
            quarantine_path = os.path.join(quarantine_dir, quarantine_name)
            
            # Move file to quarantine
            import shutil
            shutil.move(file_path, quarantine_path)
            
            # Log quarantine action
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO quarantine_log 
                    (original_path, quarantine_path, threat_name, threat_level, detection_method)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_path, quarantine_path, threat_info.get('threat_name'),
                      threat_info.get('threat_level'), threat_info.get('detection_method')))
                conn.commit()
            
            self.stats['files_quarantined'] += 1
            self.logger.warning(f"File quarantined: {file_path} -> {quarantine_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    def log_file_event(self, file_path: str, event_type: str, threat_info: Dict):
        """Log file monitoring event"""
        try:
            # Calculate file hash for logging
            file_hash = None
            file_size = None
            
            try:
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read(1024)).hexdigest()  # Quick hash
            except:
                pass
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO file_events 
                    (event_type, file_path, file_size, file_hash, threat_detected,
                     threat_name, threat_level, action_taken, processing_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (event_type, file_path, file_size, file_hash,
                      threat_info.get('threat_detected', False),
                      threat_info.get('threat_name'),
                      threat_info.get('threat_level'),
                      'quarantined' if threat_info.get('threat_detected') else 'allowed',
                      threat_info.get('processing_time')))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log file event: {e}")
    
    def process_file_queue(self):
        """Process queued files for threat analysis"""
        while self.running:
            try:
                # Get file from queue with timeout
                file_path, event_type, queue_time = self.file_queue.get(timeout=1.0)
                
                # Skip if file no longer exists
                if not os.path.exists(file_path):
                    continue
                
                # Wait a bit for file to be fully written
                time.sleep(0.5)
                
                # Analyze file for threats
                threat_info = self.analyze_file_threat(file_path)
                
                # Take action if threat detected
                if threat_info.get('threat_detected'):
                    self.stats['threats_detected'] += 1
                    
                    # Quarantine high-level threats
                    if threat_info.get('threat_level', 0) >= 7:
                        if self.quarantine_file(file_path, threat_info):
                            threat_info['action_taken'] = 'quarantined'
                        else:
                            threat_info['action_taken'] = 'quarantine_failed'
                    else:
                        threat_info['action_taken'] = 'monitored'
                    
                    self.logger.warning(f"Threat detected: {file_path} - {threat_info['threat_name']}")
                else:
                    threat_info['action_taken'] = 'allowed'
                
                # Log event
                self.log_file_event(file_path, event_type, threat_info)
                
                self.file_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing file queue: {e}")
    
    def start_monitoring(self):
        """Start real-time file monitoring"""
        try:
            self.running = True
            
            # Start file processing thread
            self.processing_thread = threading.Thread(target=self.process_file_queue, daemon=True)
            self.processing_thread.start()
            
            # Setup file system observers
            self.observers = []
            
            for path in self.monitored_paths:
                if os.path.exists(path):
                    observer = Observer()
                    observer.schedule(self, path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    self.logger.info(f"Started monitoring: {path}")
            
            self.logger.info("Real-time file monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop real-time file monitoring"""
        try:
            self.running = False
            
            # Stop observers
            if hasattr(self, 'observers'):
                for observer in self.observers:
                    observer.stop()
                    observer.join()
            
            # Wait for processing thread
            if self.processing_thread and self.processing_thread.is_alive():
                self.processing_thread.join(timeout=5.0)
            
            self.logger.info("Real-time file monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
    
    def get_monitoring_stats(self) -> Dict:
        """Get monitoring statistics"""
        stats = self.stats.copy()
        
        if stats['processing_time']:
            import numpy as np
            stats['avg_processing_time'] = np.mean(stats['processing_time'])
            stats['max_processing_time'] = np.max(stats['processing_time'])
        
        stats['queue_size'] = self.file_queue.qsize()
        stats['monitored_paths'] = len(self.monitored_paths)
        
        return stats

def test_realtime_monitoring():
    """Test real-time monitoring system"""
    print("=" * 80)
    print("🔍 TESTING REAL-TIME FILE MONITORING")
    print("=" * 80)
    
    # Initialize engines
    print("🔄 Initializing detection engines...")
    ai_engine = AIEngine()
    signature_engine = SignatureEngine()
    anomaly_detector = AnomalyDetector()
    
    # Create monitor
    monitor = RealTimeFileMonitor(ai_engine, signature_engine, anomaly_detector)
    
    print("✅ Real-time monitor initialized")
    
    # Test monitoring paths
    print(f"📁 Monitoring paths:")
    for path in monitor.monitored_paths:
        exists = "✅" if os.path.exists(path) else "❌"
        print(f"  {exists} {path}")
    
    # Test file filtering
    print("\n🔍 Testing file filtering...")
    test_files = [
        "test.exe",
        "document.pdf", 
        "script.py",
        "image.jpg",
        "data.txt"
    ]
    
    for test_file in test_files:
        should_monitor = monitor.should_monitor_file(test_file)
        status = "🔍 MONITOR" if should_monitor else "⏭️ SKIP"
        print(f"  {test_file:15} {status}")
    
    # Start monitoring for a short test
    print("\n🚀 Starting monitoring test...")
    success = monitor.start_monitoring()
    
    if success:
        print("✅ Monitoring started successfully")
        
        # Let it run for a few seconds
        print("⏱️ Running for 5 seconds...")
        time.sleep(5)
        
        # Stop monitoring
        monitor.stop_monitoring()
        print("🛑 Monitoring stopped")
        
        # Show statistics
        stats = monitor.get_monitoring_stats()
        print(f"\n📊 Monitoring Statistics:")
        print(f"  Files monitored: {stats['files_monitored']}")
        print(f"  Threats detected: {stats['threats_detected']}")
        print(f"  Files quarantined: {stats['files_quarantined']}")
        print(f"  Queue size: {stats['queue_size']}")
        
        return True
    else:
        print("❌ Failed to start monitoring")
        return False

def integrate_realtime_monitoring():
    """Integrate real-time monitoring into main application"""
    print("\n🔧 Integrating Real-time Monitoring...")
    
    # Create monitoring service module
    monitoring_code = '''# Real-time Monitoring Service
import threading
import time
from .realtime_monitoring import RealTimeFileMonitor
from ..core.ai_engine import AIEngine
from ..detection.signature_engine import SignatureEngine
from ..detection.anomaly_detector import AnomalyDetector

class MonitoringService:
    """Real-time monitoring service for main application"""
    
    def __init__(self):
        self.ai_engine = AIEngine()
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        
        self.monitor = RealTimeFileMonitor(
            self.ai_engine, 
            self.signature_engine, 
            self.anomaly_detector
        )
        
        self.running = False
    
    def start(self):
        """Start monitoring service"""
        if not self.running:
            success = self.monitor.start_monitoring()
            if success:
                self.running = True
                return True
        return False
    
    def stop(self):
        """Stop monitoring service"""
        if self.running:
            self.monitor.stop_monitoring()
            self.running = False
    
    def get_stats(self):
        """Get monitoring statistics"""
        return self.monitor.get_monitoring_stats()
    
    def is_running(self):
        """Check if monitoring is running"""
        return self.running
'''
    
    # Write monitoring service
    os.makedirs("src/monitoring", exist_ok=True)
    
    with open("src/monitoring/__init__.py", 'w') as f:
        f.write("# Real-time Monitoring Module\n")
    
    with open("src/monitoring/monitoring_service.py", 'w') as f:
        f.write(monitoring_code)
    
    # Copy main monitoring file
    import shutil
    shutil.copy(__file__, "src/monitoring/realtime_monitoring.py")
    
    print("✅ Real-time monitoring integrated")
    
    # Update main application imports
    main_py_path = "main.py"
    if os.path.exists(main_py_path):
        with open(main_py_path, 'r') as f:
            content = f.read()
        
        if 'MonitoringService' not in content:
            # Add import
            import_line = "from src.monitoring.monitoring_service import MonitoringService\n"
            
            # Find a good place to add the import
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.startswith('from src.') or line.startswith('import'):
                    lines.insert(i + 1, import_line.strip())
                    break
            
            with open(main_py_path, 'w') as f:
                f.write('\n'.join(lines))
            
            print("✅ Updated main application imports")
    
    return True

def main():
    """Implement real-time file monitoring"""
    print("Starting real-time file monitoring implementation...")
    
    # Test monitoring system
    success = test_realtime_monitoring()
    
    if success:
        # Integrate into main application
        integrate_realtime_monitoring()
        
        print("\n" + "=" * 80)
        print("✅ REAL-TIME FILE MONITORING IMPLEMENTED!")
        print("=" * 80)
        print("Key features:")
        print("• Real-time file system monitoring")
        print("• AI-powered threat detection")
        print("• Automatic quarantine of high-risk files")
        print("• Comprehensive logging and statistics")
        print("• Performance-optimized file filtering")
        print("• Multi-threaded processing queue")
        
        return True
    else:
        print("\n" + "=" * 80)
        print("❌ REAL-TIME MONITORING IMPLEMENTATION FAILED")
        print("=" * 80)
        return False

if __name__ == "__main__":
    main()
