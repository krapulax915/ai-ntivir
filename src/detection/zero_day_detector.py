#!/usr/bin/env python3
"""
Zero-Day Threat Detection System
Advanced behavioral analysis and pattern recognition for unknown threats
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import logging
import threading
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
import psutil

@dataclass
class BehavioralPattern:
    pattern_id: str
    pattern_type: str
    indicators: List[str]
    severity: float
    confidence: float
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    associated_files: Set[str]

@dataclass
class ZeroDayThreat:
    threat_id: str
    file_path: str
    threat_score: float
    behavioral_indicators: List[str]
    confidence: float
    detection_time: datetime
    threat_category: str
    risk_level: str

class ZeroDayDetector:
    """Advanced zero-day threat detection using behavioral analysis"""
    
    def __init__(self, ai_trainer=None, intelligence_engine=None, callback=None):
        self.ai_trainer = ai_trainer
        self.intelligence_engine = intelligence_engine
        self.callback = callback
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.zero_day_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Database for behavioral patterns and detections
        self.db_path = os.path.join(os.path.dirname(__file__), "zero_day_detection.db")
        self.init_database()
        
        # Behavioral monitoring
        self.behavioral_patterns = {}
        self.active_processes = {}
        
        # Detection thresholds
        self.behavioral_threshold = 0.7
        self.zero_day_threshold = 0.85
        
        # Monitoring state
        self.monitoring_thread = None
        self.running = False
        self.detection_callbacks = []
        
        # Suspicious behaviors
        self.suspicious_behaviors = {
            'file_operations': ['mass_file_encryption', 'rapid_file_deletion', 'system_file_modification'],
            'network_operations': ['unusual_outbound_connections', 'data_exfiltration_patterns', 'c2_communication'],
            'process_operations': ['process_injection', 'privilege_escalation', 'anti_analysis_techniques'],
            'registry_operations': ['startup_modification', 'security_setting_changes', 'service_installation']
        }
        
        self.logger.info("Zero-Day Detector initialized")
    
    def init_database(self):
        """Initialize SQLite database for zero-day detection"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Behavioral patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS behavioral_patterns (
                        pattern_id TEXT PRIMARY KEY,
                        pattern_type TEXT,
                        indicators TEXT,
                        severity REAL,
                        confidence REAL,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        occurrence_count INTEGER,
                        associated_files TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Zero-day detections table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS zero_day_detections (
                        threat_id TEXT PRIMARY KEY,
                        file_path TEXT,
                        threat_score REAL,
                        behavioral_indicators TEXT,
                        confidence REAL,
                        detection_time TIMESTAMP,
                        threat_category TEXT,
                        risk_level TEXT,
                        verified BOOLEAN DEFAULT 0,
                        false_positive BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Process monitoring table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS process_monitoring (
                        monitor_id TEXT PRIMARY KEY,
                        process_name TEXT,
                        process_id INTEGER,
                        command_line TEXT,
                        start_time TIMESTAMP,
                        suspicious_activities TEXT,
                        risk_score REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_type ON behavioral_patterns(pattern_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_time ON zero_day_detections(detection_time)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_process_name ON process_monitoring(process_name)')
                
                conn.commit()
                self.logger.info("Zero-day detection database initialized")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
    
    def start_monitoring(self):
        """Start zero-day threat monitoring"""
        try:
            if self.running:
                return
            
            self.running = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            self.logger.info("Zero-day monitoring started")
            
        except Exception as e:
            self.logger.error(f"Failed to start zero-day monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop zero-day threat monitoring"""
        try:
            self.running = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=10)
            
            self.logger.info("Zero-day monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping zero-day monitoring: {e}")
    
    def _monitoring_loop(self):
        """Main monitoring loop for zero-day detection"""
        try:
            while self.running:
                try:
                    # Monitor active processes
                    self.monitor_processes()
                    
                    # Analyze behavioral patterns
                    self.analyze_behavioral_patterns()
                    
                    # Detect zero-day threats
                    self.detect_zero_day_threats()
                    
                    # Sleep for monitoring interval
                    time.sleep(30)  # 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"Monitoring loop error: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"Monitoring loop failed: {e}")
    
    def monitor_processes(self):
        """Monitor active processes for suspicious behavior"""
        try:
            current_processes = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name']
                    
                    if pid not in self.active_processes:
                        # New process detected
                        self.active_processes[pid] = {
                            'name': name,
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                            'start_time': datetime.fromtimestamp(proc_info['create_time']),
                            'suspicious_activities': [],
                            'risk_score': 0.0
                        }
                        
                        # Analyze new process
                        self.analyze_new_process(pid, self.active_processes[pid])
                    
                    current_processes[pid] = self.active_processes[pid]
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Remove terminated processes
            terminated_pids = set(self.active_processes.keys()) - set(current_processes.keys())
            for pid in terminated_pids:
                del self.active_processes[pid]
            
        except Exception as e:
            self.logger.error(f"Process monitoring failed: {e}")
    
    def analyze_new_process(self, pid: int, proc_info: Dict[str, Any]):
        """Analyze newly detected process for suspicious behavior"""
        try:
            risk_score = 0.0
            suspicious_activities = []
            
            name = proc_info['name'].lower()
            cmdline = proc_info['cmdline'].lower()
            
            # Check for suspicious process names
            suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32', 'regsvr32']
            
            if any(sus_name in name for sus_name in suspicious_names):
                risk_score += 0.3
                suspicious_activities.append('suspicious_process_name')
            
            # Check for suspicious command line arguments
            suspicious_args = ['-encodedcommand', '-noprofile', '-windowstyle hidden', 'downloadstring', 'invoke-expression']
            
            if any(sus_arg in cmdline for sus_arg in suspicious_args):
                risk_score += 0.4
                suspicious_activities.append('suspicious_command_line')
            
            # Check for process injection indicators
            if 'inject' in cmdline or 'hollow' in cmdline:
                risk_score += 0.5
                suspicious_activities.append('process_injection_indicators')
            
            # Update process info
            proc_info['risk_score'] = risk_score
            proc_info['suspicious_activities'] = suspicious_activities
            
            # Log high-risk processes
            if risk_score > 0.5:
                self.log_suspicious_process(pid, proc_info)
            
        except Exception as e:
            self.logger.error(f"Process analysis failed for PID {pid}: {e}")
    
    def log_suspicious_process(self, pid: int, proc_info: Dict[str, Any]):
        """Log suspicious process to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                monitor_id = hashlib.md5(f"{pid}_{time.time()}".encode()).hexdigest()
                
                cursor.execute('''
                    INSERT INTO process_monitoring 
                    (monitor_id, process_name, process_id, command_line,
                     start_time, suspicious_activities, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    monitor_id,
                    proc_info['name'],
                    pid,
                    proc_info['cmdline'],
                    proc_info['start_time'],
                    json.dumps(proc_info['suspicious_activities']),
                    proc_info['risk_score']
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log suspicious process: {e}")
    
    def analyze_behavioral_patterns(self):
        """Analyze behavioral patterns for zero-day indicators"""
        try:
            # Analyze process behavior patterns
            self.analyze_process_patterns()
            
        except Exception as e:
            self.logger.error(f"Behavioral pattern analysis failed: {e}")
    
    def analyze_process_patterns(self):
        """Analyze process behavior patterns"""
        try:
            # Check for process injection patterns
            suspicious_processes = [p for p in self.active_processes.values() if p['risk_score'] > 0.5]
            
            for proc_info in suspicious_processes:
                activities = proc_info['suspicious_activities']
                
                # Check for anti-analysis techniques
                if 'suspicious_command_line' in activities:
                    self.create_behavioral_pattern(
                        'anti_analysis_behavior',
                        ['evasion_technique', 'advanced_malware'],
                        0.85,
                        proc_info['name']
                    )
                
                # Check for process injection
                if 'process_injection_indicators' in activities:
                    self.create_behavioral_pattern(
                        'process_injection_attempt',
                        ['code_injection', 'system_compromise'],
                        0.9,
                        proc_info['name']
                    )
            
        except Exception as e:
            self.logger.error(f"Process pattern analysis failed: {e}")
    
    def create_behavioral_pattern(self, pattern_type: str, indicators: List[str], 
                                severity: float, associated_file: str):
        """Create or update behavioral pattern"""
        try:
            pattern_id = hashlib.md5(f"{pattern_type}_{associated_file}".encode()).hexdigest()
            
            if pattern_id in self.behavioral_patterns:
                # Update existing pattern
                pattern = self.behavioral_patterns[pattern_id]
                pattern.last_seen = datetime.now()
                pattern.occurrence_count += 1
                pattern.associated_files.add(associated_file)
            else:
                # Create new pattern
                pattern = BehavioralPattern(
                    pattern_id=pattern_id,
                    pattern_type=pattern_type,
                    indicators=indicators,
                    severity=severity,
                    confidence=0.7,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    occurrence_count=1,
                    associated_files={associated_file}
                )
                self.behavioral_patterns[pattern_id] = pattern
            
            # Save to database
            self.save_behavioral_pattern(pattern)
            
        except Exception as e:
            self.logger.error(f"Failed to create behavioral pattern: {e}")
    
    def save_behavioral_pattern(self, pattern: BehavioralPattern):
        """Save behavioral pattern to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO behavioral_patterns 
                    (pattern_id, pattern_type, indicators, severity, confidence,
                     first_seen, last_seen, occurrence_count, associated_files)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id,
                    pattern.pattern_type,
                    json.dumps(pattern.indicators),
                    pattern.severity,
                    pattern.confidence,
                    pattern.first_seen,
                    pattern.last_seen,
                    pattern.occurrence_count,
                    json.dumps(list(pattern.associated_files))
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save behavioral pattern: {e}")
    
    def detect_zero_day_threats(self):
        """Detect zero-day threats based on behavioral patterns"""
        try:
            # Analyze high-severity patterns
            high_severity_patterns = [p for p in self.behavioral_patterns.values() 
                                    if p.severity >= self.behavioral_threshold]
            
            for pattern in high_severity_patterns:
                for file_path in pattern.associated_files:
                    threat_score = self.calculate_zero_day_score(pattern, file_path)
                    
                    if threat_score >= self.zero_day_threshold:
                        zero_day_threat = self.create_zero_day_threat(pattern, file_path, threat_score)
                        self.handle_zero_day_detection(zero_day_threat)
            
        except Exception as e:
            self.logger.error(f"Zero-day threat detection failed: {e}")
    
    def calculate_zero_day_score(self, pattern: BehavioralPattern, file_path: str) -> float:
        """Calculate zero-day threat score"""
        try:
            base_score = pattern.severity
            confidence_factor = pattern.confidence
            frequency_factor = min(pattern.occurrence_count / 10.0, 1.0)
            
            # Factor in recency
            time_diff = (datetime.now() - pattern.last_seen).total_seconds()
            recency_factor = max(0.1, 1.0 - (time_diff / 3600))  # Decay over 1 hour
            
            # Combine factors
            threat_score = (base_score * 0.5 + confidence_factor * 0.2 + 
                          frequency_factor * 0.2 + recency_factor * 0.1)
            
            return min(threat_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Zero-day score calculation failed: {e}")
            return 0.0
    
    def create_zero_day_threat(self, pattern: BehavioralPattern, file_path: str, 
                             threat_score: float) -> ZeroDayThreat:
        """Create zero-day threat object"""
        try:
            threat_id = hashlib.md5(f"{pattern.pattern_id}_{file_path}_{time.time()}".encode()).hexdigest()
            
            # Categorize threat based on indicators
            threat_category = self.categorize_threat(pattern.indicators)
            risk_level = self.determine_risk_level(threat_score)
            
            zero_day_threat = ZeroDayThreat(
                threat_id=threat_id,
                file_path=file_path,
                threat_score=threat_score,
                behavioral_indicators=pattern.indicators,
                confidence=pattern.confidence,
                detection_time=datetime.now(),
                threat_category=threat_category,
                risk_level=risk_level
            )
            
            return zero_day_threat
            
        except Exception as e:
            self.logger.error(f"Failed to create zero-day threat: {e}")
            return None
    
    def categorize_threat(self, indicators: List[str]) -> str:
        """Categorize threat based on behavioral indicators"""
        try:
            if any('injection' in indicator for indicator in indicators):
                return 'code_injection'
            elif any('evasion' in indicator for indicator in indicators):
                return 'evasion_malware'
            elif any('privilege' in indicator for indicator in indicators):
                return 'privilege_escalation'
            else:
                return 'unknown_malware'
                
        except Exception as e:
            return 'unknown'
    
    def determine_risk_level(self, threat_score: float) -> str:
        """Determine risk level based on threat score"""
        if threat_score >= 0.9:
            return 'critical'
        elif threat_score >= 0.8:
            return 'high'
        elif threat_score >= 0.6:
            return 'medium'
        else:
            return 'low'
    
    def handle_zero_day_detection(self, zero_day_threat: ZeroDayThreat):
        """Handle zero-day threat detection"""
        try:
            # Save to database
            self.save_zero_day_detection(zero_day_threat)
            
            # Notify callbacks
            for callback in self.detection_callbacks:
                try:
                    callback(zero_day_threat)
                except Exception as e:
                    self.logger.error(f"Detection callback failed: {e}")
            
            # Log detection
            self.logger.warning(f"Zero-day threat detected: {zero_day_threat.file_path} "
                              f"(Score: {zero_day_threat.threat_score:.3f}, "
                              f"Category: {zero_day_threat.threat_category})")
            
        except Exception as e:
            self.logger.error(f"Failed to handle zero-day detection: {e}")
    
    def save_zero_day_detection(self, zero_day_threat: ZeroDayThreat):
        """Save zero-day detection to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO zero_day_detections 
                    (threat_id, file_path, threat_score, behavioral_indicators,
                     confidence, detection_time, threat_category, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    zero_day_threat.threat_id,
                    zero_day_threat.file_path,
                    zero_day_threat.threat_score,
                    json.dumps(zero_day_threat.behavioral_indicators),
                    zero_day_threat.confidence,
                    zero_day_threat.detection_time,
                    zero_day_threat.threat_category,
                    zero_day_threat.risk_level
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save zero-day detection: {e}")
    
    def add_detection_callback(self, callback):
        """Add callback for zero-day detections"""
        self.detection_callbacks.append(callback)
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get zero-day detection statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get total detections
                cursor.execute('SELECT COUNT(*) FROM zero_day_detections')
                total_detections = cursor.fetchone()[0]
                
                # Get detections by category
                cursor.execute('''
                    SELECT threat_category, COUNT(*) FROM zero_day_detections 
                    GROUP BY threat_category
                ''')
                category_stats = dict(cursor.fetchall())
                
                # Get recent detections
                cursor.execute('''
                    SELECT COUNT(*) FROM zero_day_detections 
                    WHERE detection_time > datetime('now', '-24 hours')
                ''')
                recent_detections = cursor.fetchone()[0]
                
                return {
                    'total_detections': total_detections,
                    'category_statistics': category_stats,
                    'recent_detections_24h': recent_detections,
                    'monitoring_status': 'active' if self.running else 'inactive',
                    'active_patterns': len(self.behavioral_patterns),
                    'monitored_processes': len(self.active_processes)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get detection statistics: {e}")
            return {}
