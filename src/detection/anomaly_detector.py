"""
AI-powered Anomaly Detection Engine
Detects suspicious file, system, and browser activities using machine learning
"""

import os
import sys
import time
import threading
import hashlib
import json
import psutil
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sqlite3
import logging
from typing import Dict, List, Tuple, Optional
import subprocess
try:
    import winreg
    import win32api
    import win32con
    import win32process
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Warning: Win32 modules not available - some features will be limited")


class AnomalyDetector:
    """Advanced AI-powered anomaly detection system"""
    
    def __init__(self, db_path="anomaly_detection.db"):
        self.db_path = db_path
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.anomaly_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize monitoring state
        self.monitoring_active = False
        self.monitoring_threads = []
        self.win32_available = WIN32_AVAILABLE
        
        # Behavioral baselines
        self.file_access_patterns = defaultdict(list)
        self.process_patterns = defaultdict(list)
        self.network_patterns = defaultdict(list)
        self.browser_patterns = defaultdict(list)
        self.learning_period = 3600  # 1 hour learning period
        self.threat_confidence_threshold = 0.75  # Minimum confidence for threat reporting
        
        # Initialize database
        self.init_database()
        self.anomaly_threshold = 0.955  # Increased threshold to reduce false positives
        
        # Advanced AI learning parameters
        self.learning_rate = 0.01
        self.pattern_decay_factor = 0.95
        self.adaptive_threshold = True
        self.false_positive_penalty = 0.1
        
        # Enhanced behavioral analysis storage
        self.process_baselines = {}
    
    def analyze_file_anomalies(self, file_path: str) -> Dict:
        """Analyze file for anomalous behavior patterns"""
        try:
            if not os.path.exists(file_path):
                return {'error': 'File not found', 'is_anomaly': False}
            
            # Basic file analysis
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Calculate anomaly score
            anomaly_score = 0.0
            indicators = []
            
            # Size-based anomaly detection
            if file_size == 0:
                anomaly_score += 0.3
                indicators.append('zero_size_file')
            elif file_size > 100 * 1024 * 1024:  # > 100MB
                anomaly_score += 0.2
                indicators.append('large_file_size')
            
            # Extension-based analysis
            suspicious_extensions = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif'}
            if file_ext in suspicious_extensions:
                anomaly_score += 0.4
                indicators.append('suspicious_extension')
            
            # Location-based analysis
            suspicious_paths = ['temp', 'tmp', 'downloads', 'appdata']
            file_path_lower = file_path.lower()
            for path in suspicious_paths:
                if path in file_path_lower:
                    anomaly_score += 0.2
                    indicators.append(f'suspicious_location_{path}')
                    break
            
            # Determine if anomalous
            is_anomaly = anomaly_score >= self.anomaly_threshold
            threat_level = min(int(anomaly_score * 10), 10)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'threat_level': threat_level,
                'indicators': indicators,
                'file_path': file_path,
                'file_size': file_size,
                'analysis_time': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"File anomaly analysis failed for {file_path}: {e}")
            return {
                'error': str(e),
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'threat_level': 0
            }
    
    def init_database(self):
        """Initialize anomaly detection database"""
        try:
            os.makedirs("logs", exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create anomaly detection table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS anomaly_detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        file_path TEXT NOT NULL,
                        anomaly_score REAL,
                        threat_level INTEGER,
                        indicators TEXT,
                        is_anomaly BOOLEAN
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize anomaly database: {e}")
        
        # Load existing patterns and threat intelligence
        try:
            self._load_behavioral_patterns()
        except AttributeError:
            # Method not implemented yet, initialize empty patterns
            self.behavioral_patterns = {}
            
        try:
            self.load_threat_intelligence()
        except AttributeError:
            # Method not implemented yet, initialize empty threat intelligence
            self.threat_indicators = {
                'file_hashes': set(),
                'domains': set(),
                'ips': set(),
                'file_paths': set()
            }
    
    def _init_database(self):
        """Initialize SQLite database for anomaly data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create anomalies table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    severity REAL NOT NULL,
                    details TEXT
                )
            ''')
            
            # Create behavioral patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavioral_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    confidence_score REAL DEFAULT 0.5,
                    validation_count INTEGER DEFAULT 0
                )
            ''')
            
            # Create threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_level REAL NOT NULL,
                    source TEXT,
                    timestamp TEXT NOT NULL,
                    last_seen TEXT
                )
            ''')
            
            # Create ML features table for advanced analysis
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feature_type TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    feature_vector TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    classification REAL
                )
            ''')
            
            # Create learning feedback table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id TEXT NOT NULL,
                    feedback_type TEXT NOT NULL,
                    is_false_positive BOOLEAN,
                    user_feedback TEXT,
                    timestamp TEXT NOT NULL,
                    confidence_adjustment REAL DEFAULT 0.0
                )
            ''')
            
            # Create adaptive thresholds table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS adaptive_thresholds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_type TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    performance_score REAL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Check if timestamp column exists, if not add it
            cursor.execute("PRAGMA table_info(behavioral_patterns)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'timestamp' not in columns:
                cursor.execute('ALTER TABLE behavioral_patterns ADD COLUMN timestamp TEXT DEFAULT ""')
            
            conn.commit()
            conn.close()
            print("🤖 Anomaly detection database initialized")
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
    
    def load_patterns(self):
        """Load existing behavioral patterns from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT pattern_type, pattern_data FROM behavioral_patterns')
            patterns = cursor.fetchall()
            
            for pattern_type, pattern_data in patterns:
                data = json.loads(pattern_data)
                if pattern_type == 'file_access':
                    self.file_access_patterns.update(data)
                elif pattern_type == 'process':
                    self.process_patterns.update(data)
                elif pattern_type == 'network':
                    self.network_patterns.update(data)
                elif pattern_type == 'browser':
                    self.browser_patterns.update(data)
            
            conn.close()
            print(f"🤖 Loaded {len(patterns)} behavioral patterns")
            
        except Exception as e:
            self.logger.error(f"Pattern loading error: {e}")
    
    def save_patterns(self):
        """Save behavioral patterns to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ensure timestamp column exists
            cursor.execute("PRAGMA table_info(behavioral_patterns)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'timestamp' not in columns:
                cursor.execute('ALTER TABLE behavioral_patterns ADD COLUMN timestamp TEXT DEFAULT ""')
                conn.commit()
            
            # Clear existing patterns
            cursor.execute('DELETE FROM behavioral_patterns')
            
            # Save current patterns
            patterns = [
                ('file_access', json.dumps(dict(self.file_access_patterns))),
                ('process', json.dumps(dict(self.process_patterns))),
                ('network', json.dumps(dict(self.network_patterns))),
                ('browser', json.dumps(dict(self.browser_patterns)))
            ]
            
            current_time = datetime.now().isoformat()
            for pattern_type, pattern_data in patterns:
                if 'timestamp' in columns or True:  # Always use timestamp if column exists
                    cursor.execute('''
                        INSERT INTO behavioral_patterns (pattern_type, pattern_data, timestamp)
                        VALUES (?, ?, ?)
                    ''', (pattern_type, pattern_data, current_time))
                else:
                    cursor.execute('''
                        INSERT INTO behavioral_patterns (pattern_type, pattern_data)
                        VALUES (?, ?)
                    ''', (pattern_type, pattern_data))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Pattern saving error: {e}")
            # Try to save without timestamp as fallback
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM behavioral_patterns')
                
                patterns = [
                    ('file_access', json.dumps(dict(self.file_access_patterns))),
                    ('process', json.dumps(dict(self.process_patterns))),
                    ('network', json.dumps(dict(self.network_patterns))),
                    ('browser', json.dumps(dict(self.browser_patterns)))
                ]
                
                for pattern_type, pattern_data in patterns:
                    cursor.execute('''
                        INSERT INTO behavioral_patterns (pattern_type, pattern_data)
                        VALUES (?, ?)
                    ''', (pattern_type, pattern_data))
                
                conn.commit()
                conn.close()
                print("🤖 Patterns saved without timestamp (fallback)")
                
            except Exception as fallback_error:
                self.logger.error(f"Fallback pattern saving error: {fallback_error}")

    def start_monitoring(self):
        """Start anomaly detection monitoring"""
        self.monitoring_active = True
        
        # Start minimal monitoring threads for ultra-low resource usage
        # Only start essential monitoring with single thread
        essential_thread = threading.Thread(target=self._minimal_monitoring_loop, daemon=True)
        essential_thread.start()
        
        print("Minimal anomaly detection started")
        
        # Skip test anomaly generation to reduce resource usage
    
    def _minimal_monitoring_loop(self):
        """Minimal monitoring loop for ultra-low resource usage"""
        print("Minimal anomaly monitoring loop started")
        cycle_count = 0
        
        while self.monitoring_active:
            try:
                # Basic system check every 30 seconds
                cycle_count += 1
                if cycle_count % 6 == 0:  # Every 3 minutes
                    print(f"Minimal anomaly monitoring cycle {cycle_count}")
                
                # Light monitoring - only check critical processes
                self._check_critical_processes()
                
                # Sleep for 30 seconds to reduce CPU usage
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Minimal monitoring error: {e}")
                time.sleep(60)  # Longer sleep on error
    
    def _check_critical_processes(self):
        """Check only critical processes for anomalies"""
        try:
            # Only monitor processes with high CPU or memory usage
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if not self.monitoring_active:
                        break
                    
                    # Only check processes using significant resources
                    if proc.info['cpu_percent'] > 50 or proc.info['memory_percent'] > 10:
                        self._analyze_process_light(proc.info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Critical process check error: {e}")
    
    def _analyze_process_light(self, proc_info):
        """Lightweight process analysis"""
        try:
            process_name = proc_info['name']
            
            # Quick check for known malicious patterns
            suspicious_names = ['cryptolocker', 'ransomware', 'trojan', 'virus', 'malware']
            if any(pattern in process_name.lower() for pattern in suspicious_names):
                self.report_process_anomaly(
                    process_name, 
                    proc_info['pid'], 
                    0.9,  # High threat score
                    "Suspicious process name detected"
                )
                
        except Exception as e:
            pass  # Silent fail for lightweight monitoring
    
    def stop_monitoring(self):
        """Stop anomaly detection monitoring"""
        self.monitoring_active = False
        self.save_patterns()
        print("🤖 Anomaly detection monitoring stopped")
    
    def monitor_file_system(self):
        """Monitor file system for anomalous activities"""
        print("🤖 File system anomaly monitoring started")
        file_check_count = 0
        
        while self.monitoring_active:
            try:
                files_checked = 0
                # Monitor file access patterns
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        if not self.monitoring_active:
                            break
                        if proc.info['open_files']:
                            for file_info in proc.info['open_files']:
                                files_checked += 1
                                self.analyze_file_access(
                                    proc.info['name'], 
                                    file_info.path,
                                    proc.info['pid']
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                file_check_count += 1
                # Show activity every 2 cycles (10 seconds) instead of every minute
                if file_check_count % 2 == 0:
                    print(f"🤖 File system monitor: Checked {files_checked} files in cycle {file_check_count}")
                        
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"File system monitoring error: {e}")
                print(f"🤖 File system monitoring error: {e}")
                time.sleep(10)
                
    def analyze_file_access(self, process_name: str, file_path: str, pid: int):
        """Analyze file access patterns for anomalies"""
        try:
            current_time = datetime.now()
            
            # Record access pattern
            self.file_access_patterns[process_name].append({
                'file_path': file_path,
                'timestamp': current_time.isoformat(),
                'pid': pid
            })
            
            # Keep only recent patterns (last 24 hours)
            cutoff_time = current_time - timedelta(hours=24)
            self.file_access_patterns[process_name] = [
                p for p in self.file_access_patterns[process_name]
                if datetime.fromisoformat(p['timestamp']) > cutoff_time
            ]
            
            # Detect anomalies
            anomaly_score = self.calculate_file_anomaly_score(process_name, file_path)
            
            if anomaly_score > self.anomaly_threshold:
                self.report_file_anomaly(process_name, file_path, anomaly_score, pid)
                
        except Exception as e:
            # Silently continue - file access monitoring generates many access denied errors
            pass

    def calculate_file_anomaly_score(self, process_name: str, file_path: str) -> float:
        """Calculate anomaly score for file access using intelligent AI analysis"""
        try:
            # Initialize AI engine if not available
            if not hasattr(self, 'ai_engine'):
                try:
                    from src.core.ai_engine import AIEngine
                    self.ai_engine = AIEngine()
                except Exception as e:
                    print(f"⚠️ AI Engine not available: {e}")
                    self.ai_engine = None
            
            # Use AI engine for intelligent classification
            if self.ai_engine:
                result = self.ai_engine.classify_file_access(process_name, file_path)
                if result is not None:
                    return result.get('threat_score', 0.1)
                else:
                    return 0.1
            
            # Fallback to basic rules if AI not available
            return self._basic_file_anomaly_score(process_name, file_path)
            
        except Exception as e:
            self.logger.error(f"File anomaly calculation error: {e}")
            return 0.0
    
    def _basic_file_anomaly_score(self, process_name: str, file_path: str) -> float:
        """Enhanced fallback anomaly scoring with better file type detection"""
        # Known safe processes accessing system files - very low score
        safe_processes = {
            'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe',
            'runtimebroker.exe', 'searchindexer.exe', 'searchapp.exe', 'sihost.exe',
            'textinputhost.exe', 'ctfmon.exe', 'dllhost.exe', 'wmiprvse.exe',
            'taskhostw.exe', 'startmenuexperiencehost.exe', 'conhost.exe',
            'firefox.exe', 'chrome.exe', 'msedge.exe', 'winword.exe', 'python.exe',
            'code.exe', 'notepad.exe', 'notepad++.exe', 'pycharm64.exe', 'devenv.exe',
            'ollama.exe', 'antivirus_scanner.exe', 'aiaintivirus.exe', 'aiaintivirus_final.exe',
            'acrobat.exe', 'acrord32.exe', 'vlc.exe', 'spotify.exe', 'steam.exe'
        }
        
        if process_name.lower() in safe_processes:
            return 0.02  # Very low score for safe processes
            
        # Safe file extensions that should never be flagged as threats
        safe_extensions = {
            '.pdf', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico',
            '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac', '.ogg',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.json', '.xml', '.csv', '.log', '.ini', '.cfg', '.conf',
            '.html', '.css', '.js', '.py', '.java', '.cpp', '.h',
            '.md', '.rst', '.torrent', '.srt', '.sf2', '.gitignore',
            '.editorconfig', '.ts', '.tsx', '.nfo', '.d.ts', '.htm'
        }
        
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Safe file types get very low scores
        if file_ext in safe_extensions:
            return 0.05  # Very low threat for safe file types
            
        # Special handling for files without extensions (like 'host', 'js' directories)
        if not file_ext:
            filename = os.path.basename(file_path).lower()
            # Known safe files without extensions
            safe_no_ext_files = {'host', 'readme', 'license', 'changelog', 'makefile', 'dockerfile', 'js', 'css', 'html'}
            if filename in safe_no_ext_files:
                return 0.02  # Very low threat for known safe files
            # Files in development/download directories are likely safe
            dev_paths = ['downloads', 'projects', 'src', 'node_modules', '.git', 'github', 'web', 'site', 'assets']
            if any(path in file_path.lower() for path in dev_paths):
                return 0.03  # Very low threat for files in dev directories
            # Check if it's actually a directory being scanned as a file
            if os.path.isdir(file_path):
                return 0.01  # Directories should not be threats
        
        # Check for suspicious file extensions only in risky locations
        suspicious_extensions = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif'}
        if file_ext in suspicious_extensions:
            risky_locations = ['temp', 'download', 'appdata\\local\\temp', 'tmp']
            if any(loc in file_path.lower() for loc in risky_locations):
                return 0.75  # High threat for executables in temp locations
                
        # System files accessed by unknown processes - moderate threat
        system_paths = ['C:\\Windows\\System32', 'C:\\Windows\\SysWOW64']
        if any(path in file_path for path in system_paths):
            if process_name.lower() not in safe_processes:
                return 0.4  # Reduced from 0.6 - moderate threat
                
        # Windows system files that are commonly accessed
        common_system_files = {
            'hiberfil.sys', 'pagefile.sys', 'swapfile.sys', 'bootmgr',
            'ntldr', 'boot.ini', 'config.sys', 'autoexec.bat',
            'bootnxt', 'bootsect.bak', 'boottel.dat', 'dumpstack.log',
            'dumpstack.log.tmp', 'bcd', 'bcd.log', 'bcd.log1', 'bcd.log2',
            'bootstat.dat', 'bootuwf.dll', 'memtest.exe', 'bootmgr.exe.mui',
            'memtest.exe.mui', '$winre_backup_partition.marker'
        }
        
        filename = os.path.basename(file_path).lower()
        if filename in common_system_files:
            return 0.02  # Very low threat for system files
            
        # Windows system directories should be safe
        system_dirs = ['c:\\windows\\', 'c:\\boot\\', 'c:\\amd\\', 'c:\\intel\\', 
                      'c:\\program files\\', 'c:\\program files (x86)\\',
                      'c:\\programdata\\', 'c:\\system volume information\\']
        
        if any(sys_dir in file_path.lower() for sys_dir in system_dirs):
            return 0.03  # Very low threat for files in system directories
            
        # .env files are development configuration files
        if filename == '.env' or file_ext == '.env':
            return 0.02  # Very low threat for environment files
            
        return 0.15  # Slightly elevated but still low for unknown files
    
    def analyze_anomalies(self):
        """Analyze and correlate anomalies"""
        print("🤖 Anomaly correlation engine started")
        correlation_count = 0
        
        while self.monitoring_active:
            try:
                # Correlate anomalies and clean up old data
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=24)
                
                # Clean up old anomaly data
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM anomalies')
                total_anomalies = cursor.fetchone()[0]
                
                cursor.execute('DELETE FROM anomalies WHERE timestamp < ?', (cutoff_time.isoformat(),))
                deleted_count = cursor.rowcount
                conn.commit()
                conn.close()
                
                correlation_count += 1
                # Show activity every cycle (5 minutes) instead of every hour
                if correlation_count % 1 == 0:
                    print(f"🤖 Anomaly correlation: {total_anomalies} total anomalies, cleaned {deleted_count} old entries (cycle {correlation_count})")
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Anomaly correlation error: {e}")
                print(f"🤖 Anomaly correlation error: {e}")
                time.sleep(600)  # Wait 10 minutes on error
            
    def monitor_system_processes(self):
        """Monitor system processes for anomalous behavior"""
        print("🤖 System process anomaly monitoring started")
        
        known_processes = set()
        process_check_count = 0
        
        while self.monitoring_active:
            try:
                current_processes = set()
                processes_analyzed = 0
                new_processes_found = 0
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if not self.monitoring_active:
                            break
                        proc_name = proc.info['name']
                        current_processes.add(proc_name)
                        processes_analyzed += 1
                        
                        # Get CPU and memory with proper interval
                        try:
                            cpu_percent = proc.cpu_percent(interval=0.1)  # 0.1 second interval
                            memory_percent = proc.memory_percent()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                        
                        # Create enhanced proc_info
                        enhanced_proc_info = proc.info.copy()
                        enhanced_proc_info['cpu_percent'] = cpu_percent
                        enhanced_proc_info['memory_percent'] = memory_percent
                        
                        # Analyze new processes
                        if proc_name not in known_processes:
                            new_processes_found += 1
                            self.analyze_new_process(enhanced_proc_info)
                            
                        # Analyze resource usage
                        self.analyze_process_resources(enhanced_proc_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                known_processes.update(current_processes)
                
                process_check_count += 1
                # Show activity every cycle (10 seconds) instead of every minute  
                if process_check_count % 1 == 0:
                    print(f"🤖 Process monitor: Analyzed {processes_analyzed} processes, {new_processes_found} new (cycle {process_check_count})")
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                print(f"🤖 Process monitoring error: {e}")
                time.sleep(15)
            
    def analyze_new_process(self, proc_info: dict):
        """Analyze newly started processes for anomalies"""
        try:
            proc_name = proc_info['name']
            cmdline = proc_info.get('cmdline', [])
            
            # Check for suspicious process names
            suspicious_names = [
                'cryptolocker', 'wannacry', 'petya', 'locky', 'cerber',
                'keylogger', 'backdoor', 'trojan', 'rootkit'
            ]
            
            if any(sus in proc_name.lower() for sus in suspicious_names):
                self.report_system_anomaly(
                    proc_name, "suspicious_process_name", 0.95,
                    f"Suspicious process name detected: {proc_name}"
                )
                
            # Check for processes started from unusual locations - but exclude known safe processes
            if cmdline:
                exe_path = cmdline[0] if cmdline else ""
                # Only flag truly suspicious locations and unknown processes
                very_suspicious_paths = ['\\temp\\malware', '\\downloads\\virus', '\\appdata\\roaming\\temp']
                
                # Known safe processes that can run from various locations
                safe_processes = {
                    'windsurf.exe', 'python.exe', 'language_server_windows_x64.exe',
                    'chrome.exe', 'firefox.exe', 'msedge.exe', 'code.exe', 'notepad++.exe'
                }
                
                if any(path in exe_path.lower() for path in very_suspicious_paths):
                    if proc_name.lower() not in safe_processes:
                        self.report_system_anomaly(
                            proc_name, "suspicious_location", 0.8,
                            f"Process started from suspicious location: {exe_path}"
                        )
                        
        except Exception as e:
            self.logger.error(f"New process analysis error: {e}")
            
    def analyze_process_resources(self, proc_info: dict):
        """Analyze process resource usage for anomalies"""
        try:
            proc_name = proc_info['name']
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_percent = proc_info.get('memory_percent', 0)
            
            # Record resource usage
            current_time = datetime.now()
            self.process_patterns[proc_name].append({
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'timestamp': current_time.isoformat()
            })
            
            # Keep only recent data
            cutoff_time = current_time - timedelta(hours=1)
            self.process_patterns[proc_name] = [
                p for p in self.process_patterns[proc_name]
                if datetime.fromisoformat(p['timestamp']) > cutoff_time
            ]
            
            # Detect resource anomalies - use intelligent scoring
            anomaly_score = self.calculate_process_anomaly_score(
                proc_name, cpu_percent, memory_percent * 1024, proc_info.get('pid', 0)
            )
            
            # Only report anomalies for truly suspicious processes
            if anomaly_score > self.anomaly_threshold:
                # Skip reporting for known safe processes even with high resource usage
                safe_processes = {
                    'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe',
                    'runtimebroker.exe', 'searchindexer.exe', 'searchapp.exe', 'sihost.exe',
                    'textinputhost.exe', 'ctfmon.exe', 'dllhost.exe', 'wmiprvse.exe',
                    'taskhostw.exe', 'startmenuexperiencehost.exe', 'conhost.exe',
                    'firefox.exe', 'chrome.exe', 'msedge.exe', 'winword.exe', 'python.exe',
                    'windsurf.exe', 'language_server_windows_x64.exe', 'powershell.exe',
                    'cmd.exe', 'system idle process', 'system', 'registry', 'memory compression',
                    'secure system', 'audiodg.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
                    'spoolsv.exe', 'fontdrvhost.exe', 'unsecapp.exe', 'wudfhost.exe', 'ollama.exe'
                }
                
                if proc_name.lower() not in safe_processes:
                    # Normalize CPU for display (cap at 100%)
                    display_cpu = min(cpu_percent, 100.0)
                    
                    if cpu_percent > 90:  # Very high CPU usage
                        # Cap display CPU at 100% for anomaly reports
                        capped_cpu = min(cpu_percent, 100.0)
                        self.report_system_anomaly(
                            proc_name, "high_cpu_usage", anomaly_score,
                            f"Very high CPU usage: {capped_cpu:.1f}%"
                        )
                    elif memory_percent > 70:  # Very high memory usage
                        self.report_system_anomaly(
                            proc_name, "high_memory_usage", anomaly_score,
                            f"Very high memory usage: {memory_percent:.1f}%"
                        )
                
        except Exception as e:
            self.logger.error(f"Resource analysis error: {e}")
        
    def monitor_network_activity(self):
        """Monitor network activity for anomalies"""
        print("🤖 Network anomaly monitoring started")
        
        while self.monitoring_active:
            try:
                # Monitor network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        self.analyze_network_connection(conn)
                        
                time.sleep(15)  # Check every 15 seconds
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(20)
            
    def analyze_network_connection(self, connection):
        """Analyze network connections for anomalies"""
        try:
            if not connection.raddr:
                return
                
            remote_ip = connection.raddr.ip
            remote_port = connection.raddr.port
            local_port = connection.laddr.port
            
            # Check for suspicious ports
            suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
            if remote_port in suspicious_ports or local_port in suspicious_ports:
                self.report_system_anomaly(
                    "network", "suspicious_port", 0.8,
                    f"Connection to suspicious port: {remote_ip}:{remote_port}"
                )
                
            # Check for unusual outbound connections
            if connection.status == 'ESTABLISHED':
                current_time = datetime.now()
                self.network_patterns['connections'].append({
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'timestamp': current_time.isoformat()
                })
                
                # Keep only recent connections
                cutoff_time = current_time - timedelta(hours=1)
                self.network_patterns['connections'] = [
                    c for c in self.network_patterns['connections']
                    if datetime.fromisoformat(c['timestamp']) > cutoff_time
                ]
                
        except Exception as e:
            self.logger.error(f"Network connection analysis error: {e}")
        
    def monitor_browser_activity(self):
        """Monitor browser activity for anomalies"""
        print("🤖 Browser anomaly monitoring started")
        
        while self.monitoring_active:
            try:
                # Monitor browser connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        self.analyze_browser_connection(conn)
                        
                time.sleep(15)  # Check every 15 seconds
                
            except Exception as e:
                self.logger.error(f"Browser monitoring error: {e}")
                time.sleep(20)
                
    def analyze_browser_connection(self, connection):
        """Analyze browser connections for anomalies"""
        try:
            if not connection.raddr:
                return
                
            remote_ip = connection.raddr.ip
            remote_port = connection.raddr.port
            local_port = connection.laddr.port
            
            # Check for suspicious ports
            suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
            if remote_port in suspicious_ports or local_port in suspicious_ports:
                self.report_browser_anomaly(
                    "browser", "suspicious_port", 0.8,
                    f"Connection to suspicious port: {remote_ip}:{remote_port}"
                )
                
            # Check for unusual outbound connections
            if connection.status == 'ESTABLISHED':
                current_time = datetime.now()
                self.browser_patterns['connections'].append({
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'timestamp': current_time.isoformat()
                })
                
                # Keep only recent connections
                cutoff_time = current_time - timedelta(hours=1)
                self.browser_patterns['connections'] = [
                    c for c in self.browser_patterns['connections']
                    if datetime.fromisoformat(c['timestamp']) > cutoff_time
                ]
                
        except Exception as e:
            self.logger.error(f"Browser connection analysis error: {e}")
        
    def calculate_process_anomaly_score(self, process_name: str, cpu_percent: float, memory_mb: float, pid: int) -> float:
        """Calculate anomaly score for process behavior"""
        try:
            # Normalize CPU percent to max 100% (psutil can return >100% on multi-core systems)
            normalized_cpu = min(cpu_percent, 100.0)
            
            # Known safe processes - very low anomaly scores
            safe_processes = {
                'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe',
                'runtimebroker.exe', 'searchindexer.exe', 'searchapp.exe', 'sihost.exe',
                'textinputhost.exe', 'ctfmon.exe', 'dllhost.exe', 'wmiprvse.exe',
                'taskhostw.exe', 'startmenuexperiencehost.exe', 'conhost.exe',
                'firefox.exe', 'chrome.exe', 'msedge.exe', 'winword.exe', 'python.exe',
                'windsurf.exe', 'language_server_windows_x64.exe', 'powershell.exe',
                'cmd.exe', 'system idle process', 'system', 'registry', 'memory compression',
                'secure system', 'audiodg.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
                'spoolsv.exe', 'fontdrvhost.exe', 'unsecapp.exe', 'wudfhost.exe', 'ollama.exe'
            }
            
            process_lower = process_name.lower()
            
            # Safe processes get very low scores regardless of resource usage
            if process_lower in safe_processes:
                # Even high resource usage by safe processes is usually normal
                if normalized_cpu > 90 and process_lower not in ['system idle process', 'python.exe', 'windsurf.exe', 'ollama.exe']:
                    return 0.2  # Low score for safe processes with high CPU
                return 0.05  # Very low score for safe processes
            
            # For unknown processes, be more conservative
            anomaly_score = 0.0
            
            # Very high CPU usage anomaly (only for unknown processes) - use normalized CPU
            if normalized_cpu > 95:
                anomaly_score += 0.7
            elif normalized_cpu > 85:
                anomaly_score += 0.4
                
            # Very high memory usage anomaly (only for unknown processes)
            if memory_mb > 2000:  # 2GB
                anomaly_score += 0.5
            elif memory_mb > 1500:  # 1.5GB
                anomaly_score += 0.3
                
            # Unknown process gets moderate score only if high resource usage
            if anomaly_score == 0.0:
                anomaly_score = 0.2  # Moderate score for unknown processes
                
            return min(anomaly_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Process anomaly calculation error: {e}")
            return 0.0

    def report_file_anomaly(self, process_name: str, file_path: str, severity: float, pid: int):
        """Report a file access anomaly"""
        try:
            current_time = datetime.now()
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies (timestamp, anomaly_type, category, target, severity, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (current_time.isoformat(), 'file_access', 'file', file_path, severity, 
                  f"Process: {process_name}, PID: {pid}"))
            
            conn.commit()
            conn.close()
            
            # Create detailed log message
            log_message = f"[{current_time.strftime('%H:%M:%S')}] 🚨 FILE ANOMALY: {process_name}\n"
            log_message += f"  File: {file_path}\n"
            log_message += f"  PID: {pid}\n"
            log_message += f"  Severity: {severity:.2f}\n"
            log_message += "-" * 50
            
            print(log_message)
            
            # Also log to file for debugging
            try:
                os.makedirs("logs", exist_ok=True)
                with open("logs/anomaly_debug.log", "a", encoding="utf-8") as f:
                    f.write(log_message + "\n")
            except:
                pass  # Ignore file write errors
            
        except Exception as e:
            self.logger.error(f"File anomaly reporting error: {e}")
            
    def report_system_anomaly(self, process_name: str, anomaly_type: str, severity: float, details: str):
        """Report a system anomaly with detailed logging"""
        try:
            current_time = datetime.now()
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies (timestamp, anomaly_type, category, target, severity, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (current_time.isoformat(), anomaly_type, 'system', process_name, severity, details))
            
            conn.commit()
            conn.close()
            
            # Create detailed log message
            log_message = f"[{current_time.strftime('%H:%M:%S')}] 🚨 SYSTEM ANOMALY: {anomaly_type}\n"
            log_message += f"  Process: {process_name}\n"
            log_message += f"  Severity: {severity:.2f}\n"
            log_message += f"  Details: {details}\n"
            log_message += "-" * 50
            
            print(log_message)
            
            # Send to GUI anomaly logs if available
            try:
                if hasattr(self, 'gui_callback') and self.gui_callback:
                    self.gui_callback(log_message)
            except:
                pass
            
            # Also log to file for debugging
            try:
                os.makedirs("logs", exist_ok=True)
                with open("logs/anomaly_debug.log", "a", encoding="utf-8") as f:
                    f.write(log_message + "\n")
            except:
                pass  # Ignore file write errors
            
        except Exception as e:
            self.logger.error(f"System anomaly reporting error: {e}")
            
    def report_browser_anomaly(self, browser: str, url: str, anomaly_type: str, severity: float, details: str):
        """Report browser anomaly"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO anomalies (timestamp, anomaly_type, category, target, severity, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), anomaly_type, 'browser', url, severity, details))
            
            conn.commit()
            conn.close()
            
            print(f"🚨 BROWSER ANOMALY: {browser} -> {url} (Severity: {severity:.2f})")
            
        except Exception as e:
            self.logger.error(f"Browser anomaly reporting error: {e}")

    def get_anomaly_statistics(self) -> Dict:
        """Get anomaly detection statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total anomalies
            cursor.execute('SELECT COUNT(*) FROM anomalies')
            total_anomalies = cursor.fetchone()[0]
            
            # Get anomalies by category
            cursor.execute('SELECT category, COUNT(*) FROM anomalies GROUP BY category')
            category_counts = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'total_anomalies': total_anomalies,
                'file_anomalies': category_counts.get('file', 0),
                'system_anomalies': category_counts.get('system', 0),
                'browser_anomalies': category_counts.get('browser', 0),
                'network_anomalies': category_counts.get('network', 0)
            }
            
        except Exception as e:
            self.logger.error(f"Statistics error: {e}")
            return {
                'total_anomalies': 0,
                'file_anomalies': 0,
                'system_anomalies': 0,
                'browser_anomalies': 0,
                'network_anomalies': 0
            }

    def get_recent_anomalies(self, limit: int = 50) -> Dict[str, List[Dict]]:
        """Get recent anomalies for display, grouped by category"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, anomaly_type, category, target, severity, details
                FROM anomalies 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            # Group anomalies by category
            grouped_anomalies = {
                'file_anomalies': [],
                'system_anomalies': [],
                'browser_anomalies': [],
                'network_anomalies': []
            }
            
            for row in cursor.fetchall():
                anomaly_data = {
                    'timestamp': row[0],
                    'type': row[1],
                    'category': row[2],
                    'target': row[3],
                    'severity': row[4],
                    'details': row[5]
                }
                
                # Group by category
                if row[2] == 'file':
                    grouped_anomalies['file_anomalies'].append(anomaly_data)
                elif row[2] == 'system':
                    grouped_anomalies['system_anomalies'].append(anomaly_data)
                elif row[2] == 'browser':
                    grouped_anomalies['browser_anomalies'].append(anomaly_data)
                elif row[2] == 'network':
                    grouped_anomalies['network_anomalies'].append(anomaly_data)
            
            conn.close()
            return grouped_anomalies
            
        except Exception as e:
            self.logger.error(f"Recent anomalies error: {e}")
            return {
                'file_anomalies': [],
                'system_anomalies': [],
                'browser_anomalies': [],
                'network_anomalies': []
            }

    def _generate_test_anomaly(self):
        """Generate a test anomaly to verify the system is working"""
        try:
            time.sleep(2)  # Wait 2 seconds after startup
            print("🤖 Generating test anomaly to verify detector is working...")
            
            # Create a test system anomaly
            self.report_system_anomaly(
                "test_process.exe", 
                "test_anomaly", 
                0.9,
                "Test anomaly generated to verify anomaly detection system is operational"
            )
            
            # Create a test file anomaly
            self.report_file_anomaly(
                "test_process.exe",
                "C:\\Windows\\System32\\test_file.dll",
                0.85,
                12345
            )
            
            print("🤖 Test anomalies generated successfully - detector is operational!")
            
        except Exception as e:
            print(f"🤖 Test anomaly generation error: {e}")


if __name__ == "__main__":
    # Test the anomaly detector
    detector = AnomalyDetector()
    
    try:
        print("🤖 Starting anomaly detection test...")
        detector.start_monitoring()
        
        # Run for a short time
        time.sleep(30)
        
        # Get and display statistics
        stats = detector.get_anomaly_statistics()
        print(f"🤖 Anomaly Statistics: {stats}")
        
    except KeyboardInterrupt:
        print("\n🤖 Stopping anomaly detection...")
        detector.stop_monitoring()
