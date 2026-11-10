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
    print("⚠️ Win32 modules not available - some features will be limited")


class AnomalyDetector:
    """Advanced AI-powered anomaly detection system"""
    
    def __init__(self, db_path="anomaly_detection.db"):
        self.db_path = db_path
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.anomaly_detector_backup')
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
        
        # Anomaly thresholds - increased to reduce false positives
        self.anomaly_threshold = 0.8  # Increased from 0.7
        self.learning_period = 3600  # 1 hour learning period
        
        # Initialize database
        self.init_database()
        
        # Load existing patterns
        self.load_patterns()
        
    def init_database(self):
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
                    timestamp TEXT NOT NULL
                )
            ''')
            
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
            
            # Clear existing patterns
            cursor.execute('DELETE FROM behavioral_patterns')
            
            # Save current patterns
            patterns = [
                ('file_access', json.dumps(dict(self.file_access_patterns))),
                ('process', json.dumps(dict(self.process_patterns))),
                ('network', json.dumps(dict(self.network_patterns))),
                ('browser', json.dumps(dict(self.browser_patterns)))
            ]
            
            for pattern_type, pattern_data in patterns:
                cursor.execute('''
                    INSERT INTO behavioral_patterns (pattern_type, pattern_data, timestamp)
                    VALUES (?, ?, ?)
                ''', (pattern_type, pattern_data, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Pattern saving error: {e}")

    def start_monitoring(self):
        """Start anomaly detection monitoring"""
        self.monitoring_active = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_file_system, daemon=True),
            threading.Thread(target=self.monitor_system_processes, daemon=True),
            threading.Thread(target=self.monitor_network_activity, daemon=True),
            threading.Thread(target=self.monitor_browser_activity, daemon=True),
            threading.Thread(target=self.analyze_anomalies, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.monitoring_threads.append(thread)
            
        print("🤖 All anomaly detection modules started")
    
    def stop_monitoring(self):
        """Stop anomaly detection monitoring"""
        self.monitoring_active = False
        self.save_patterns()
        print("🤖 Anomaly detection monitoring stopped")
    
    def monitor_file_system(self):
        """Monitor file system for anomalous activities"""
        print("🤖 File system anomaly monitoring started")
        
        while self.monitoring_active:
            try:
                # Monitor file access patterns
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        if proc.info['open_files']:
                            for file_info in proc.info['open_files']:
                                self.analyze_file_access(
                                    proc.info['name'], 
                                    file_info.path,
                                    proc.info['pid']
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"File system monitoring error: {e}")
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
            self.logger.error(f"File access analysis error: {e}")

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
                return result.get('threat_score', 0.1)
            
            # Fallback to basic rules if AI not available
            return self._basic_file_anomaly_score(process_name, file_path)
            
        except Exception as e:
            self.logger.error(f"File anomaly calculation error: {e}")
            return 0.0
    
    def _basic_file_anomaly_score(self, process_name: str, file_path: str) -> float:
        """Basic fallback anomaly scoring"""
        # Known safe processes accessing system files - very low score
        safe_processes = {
            'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe',
            'runtimebroker.exe', 'searchindexer.exe', 'searchapp.exe', 'sihost.exe',
            'textinputhost.exe', 'ctfmon.exe', 'dllhost.exe', 'wmiprvse.exe',
            'taskhostw.exe', 'startmenuexperiencehost.exe', 'conhost.exe',
            'firefox.exe', 'chrome.exe', 'msedge.exe', 'winword.exe', 'python.exe',
            'windsurf.exe', 'language_server_windows_x64.exe', 'powershell.exe',
            'cmd.exe', 'ccc.exe', 'xtuservice.exe', 'ymc.exe', 'dashost.exe',
            'wslservice.exe', 'rstmwservice.exe', 'mom.exe', 'powermgr.exe',
            'wmpnetwk.exe', 'splwow64.exe', 'uhssvc.exe', 'mousocoreworker.exe',
            'dtshellhlp.exe', 'isd_tablet.exe', 'paintstudio.view.exe', 'msedgewebview2.exe'
        }
        
        if process_name.lower() in safe_processes:
            # Safe process accessing system files
            if any(path in file_path.lower() for path in ['windows\\system32', 'windows\\syswow64']):
                return 0.05  # Very low threat
            # Safe process accessing common files
            if any(ext in file_path.lower() for ext in ['.dll', '.mui', '.winmd', '.tlb', '.dat']):
                return 0.02  # Extremely low threat
        
        # Suspicious file extensions in temp/download locations
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
        if any(file_path.lower().endswith(ext) for ext in suspicious_extensions):
            if any(loc in file_path.lower() for loc in ['temp', 'download', 'appdata\\local\\temp']):
                return 0.8  # High threat
                
        # Unknown process accessing system files
        system_paths = ['C:\\Windows\\System32', 'C:\\Windows\\SysWOW64']
        if any(path in file_path for path in system_paths):
            if process_name.lower() not in safe_processes:
                return 0.6  # Medium threat (reduced from 0.9)
                
        return 0.1  # Normal activity
    
    def analyze_anomalies(self):
        """Analyze and correlate anomalies"""
        print("🤖 Anomaly correlation engine started")
        
        while self.monitoring_active:
            try:
                # Correlate anomalies and clean up old data
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=24)
                
                # Clean up old anomaly data
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM anomalies WHERE timestamp < ?', (cutoff_time.isoformat(),))
                conn.commit()
                conn.close()
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Anomaly correlation error: {e}")
                time.sleep(600)  # Wait 10 minutes on error
            
    def monitor_system_processes(self):
        """Monitor system processes for anomalous behavior"""
        print("🤖 System process anomaly monitoring started")
        
        known_processes = set()
        
        while self.monitoring_active:
            try:
                current_processes = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                    try:
                        proc_name = proc.info['name']
                        current_processes.add(proc_name)
                        
                        # Analyze new processes
                        if proc_name not in known_processes:
                            self.analyze_new_process(proc.info)
                            
                        # Analyze resource usage
                        self.analyze_process_resources(proc.info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                known_processes.update(current_processes)
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
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
            
            if anomaly_score > self.anomaly_threshold:
                if cpu_percent > 90:  # Very high CPU usage
                    self.report_system_anomaly(
                        proc_name, "high_cpu_usage", anomaly_score,
                        f"Very high CPU usage: {cpu_percent}%"
                    )
                elif memory_percent > 70:  # Very high memory usage
                    self.report_system_anomaly(
                        proc_name, "high_memory_usage", anomaly_score,
                        f"Very high memory usage: {memory_percent}%"
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
                'spoolsv.exe', 'fontdrvhost.exe', 'unsecapp.exe', 'wudfhost.exe'
            }
            
            process_lower = process_name.lower()
            
            # Safe processes get very low scores regardless of resource usage
            if process_lower in safe_processes:
                # Even high resource usage by safe processes is usually normal
                if cpu_percent > 90 and process_lower not in ['system idle process', 'python.exe', 'windsurf.exe']:
                    return 0.2  # Low score for safe processes with high CPU
                return 0.05  # Very low score for safe processes
            
            # For unknown processes, be more conservative
            anomaly_score = 0.0
            
            # Very high CPU usage anomaly (only for unknown processes)
            if cpu_percent > 95:
                anomaly_score += 0.7
            elif cpu_percent > 85:
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
            
            print(f"🚨 FILE ANOMALY: {process_name} -> {file_path} (Severity: {severity:.2f})")
            
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
            
            # Also log to file for debugging
            with open("logs/anomaly_debug.log", "a", encoding="utf-8") as f:
                f.write(log_message + "\n")
            
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

    def get_recent_anomalies(self, limit: int = 50) -> List[Dict]:
        """Get recent anomalies for display"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, anomaly_type, category, target, severity, details
                FROM anomalies 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            anomalies = []
            for row in cursor.fetchall():
                anomalies.append({
                    'timestamp': row[0],
                    'type': row[1],
                    'category': row[2],
                    'target': row[3],
                    'severity': row[4],
                    'details': row[5]
                })
            
            conn.close()
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Recent anomalies error: {e}")
            return []


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
