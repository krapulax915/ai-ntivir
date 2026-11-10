"""
Enhanced AI-powered Anomaly Detection Engine
Advanced machine learning with adaptive thresholds and intelligent pattern recognition
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
import re
from pathlib import Path

try:
    import winreg
    import win32api
    import win32con
    import win32process
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

class EnhancedAnomalyDetector:
    """Advanced AI-powered anomaly detection with machine learning capabilities"""
    
    def __init__(self, db_path="enhanced_anomaly_detection.db"):
        self.db_path = db_path
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.enhanced_anomaly_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Enhanced AI parameters
        self.learning_rate = 0.01
        self.pattern_decay_factor = 0.95
        self.adaptive_threshold = True
        self.false_positive_penalty = 0.1
        self.base_anomaly_threshold = 0.85
        self.dynamic_threshold_adjustment = 0.05
        
        # Initialize database and components
        self._init_database()
        self.logger.info("Enhanced Anomaly Detector initialized")
    
    def calculate_file_anomaly_score(self, process_name: str, file_path: str) -> float:
        """Calculate anomaly score for file access using intelligent AI analysis"""
        try:
            # Initialize AI engine if not available
            if not hasattr(self, 'ai_engine'):
                try:
                    from src.core.ai_engine import AIEngine
                    self.ai_engine = AIEngine()
                except Exception as e:
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
            'explorer.exe', 'svchost.exe', 'winlogon.exe', 'csrss.exe',
            'dwm.exe', 'lsass.exe', 'services.exe', 'smss.exe', 'wininit.exe',
            'antivirus_scanner.exe', 'python.exe', 'pythonw.exe'
        }
        
        # Safe file extensions
        safe_extensions = {
            '.txt', '.log', '.cfg', '.ini', '.xml', '.json', '.yaml', '.yml',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
            '.zip', '.rar', '.7z', '.tar', '.gz'
        }
        
        try:
            file_ext = os.path.splitext(file_path.lower())[1]
            
            # Very safe combinations
            if process_name.lower() in safe_processes and file_ext in safe_extensions:
                return 0.05
            
            # Safe file types regardless of process
            if file_ext in safe_extensions:
                return 0.1
            
            # Executable files need higher scrutiny
            if file_ext in ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1']:
                return 0.6
            
            # Unknown files with safe processes
            if process_name.lower() in safe_processes:
                return 0.2
            
            # Default moderate score
            return 0.3
            
        except Exception:
            return 0.1
    
    def _init_database(self):
        """Initialize SQLite database for anomaly detection"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_patterns (
                    id INTEGER PRIMARY KEY,
                    pattern_hash TEXT UNIQUE,
                    pattern_data TEXT,
                    confidence REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
        
        # Advanced behavioral analysis
        self.ml_feature_cache = {}
        self.threat_history = deque(maxlen=10000)
        self.whitelist_cache = set()
        self.dynamic_patterns = defaultdict(lambda: {
            'count': 0, 
            'confidence': 0.5, 
            'last_seen': None,
            'false_positive_count': 0,
            'true_positive_count': 0
        })
        
        # Pattern recognition matrices
        self.file_pattern_matrix = defaultdict(lambda: defaultdict(int))
        self.process_behavior_matrix = defaultdict(lambda: defaultdict(float))
        self.temporal_patterns = defaultdict(list)
        
        # Initialize enhanced database
        self._init_enhanced_database()
        
        # Load existing intelligence
        self._load_enhanced_patterns()
        self._load_whitelist_intelligence()
        
        print("🧠 Enhanced AI Anomaly Detector initialized")
    
    def _init_enhanced_database(self):
        """Initialize enhanced database schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Enhanced anomalies table with ML features
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS enhanced_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    target_entity TEXT NOT NULL,
                    severity_score REAL NOT NULL,
                    confidence_score REAL NOT NULL,
                    feature_vector TEXT,
                    detection_method TEXT,
                    is_validated BOOLEAN DEFAULT NULL,
                    feedback_score REAL DEFAULT 0.0,
                    context_data TEXT
                )
            ''')
            
            # ML training data table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_training_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feature_type TEXT NOT NULL,
                    feature_vector TEXT NOT NULL,
                    label REAL NOT NULL,
                    confidence REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    validation_status TEXT DEFAULT 'pending'
                )
            ''')
            
            # Adaptive thresholds with performance tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS adaptive_thresholds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_type TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    performance_metrics TEXT,
                    adjustment_reason TEXT,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Whitelist intelligence
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS whitelist_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    source TEXT,
                    validation_count INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Pattern evolution tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pattern_evolution (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_id TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    evolution_score REAL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            # Learning feedback table for false positive training
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id TEXT,
                    feedback_type TEXT NOT NULL,
                    is_false_positive BOOLEAN DEFAULT 0,
                    user_feedback TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    confidence_adjustment REAL DEFAULT 0.0
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Enhanced database initialization error: {e}")
    
    def _save_adaptive_thresholds(self):
        """Save adaptive thresholds to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for detection_type, threshold_data in self.adaptive_thresholds.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO adaptive_thresholds 
                    (detection_type, threshold_value, performance_metrics, adjustment_reason, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    detection_type,
                    threshold_data['threshold'],
                    json.dumps(threshold_data.get('metrics', {})),
                    'false_positive_training',
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Save adaptive thresholds error: {e}")
    
    def _load_enhanced_patterns(self):
        """Load enhanced behavioral patterns with ML features"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load ML training data
            cursor.execute('''
                SELECT feature_type, feature_vector, label, confidence 
                FROM ml_training_data 
                WHERE validation_status = 'validated'
                ORDER BY timestamp DESC LIMIT 1000
            ''')
            
            training_data = cursor.fetchall()
            for feature_type, feature_vector, label, confidence in training_data:
                features = json.loads(feature_vector)
                self.ml_feature_cache[feature_type] = {
                    'features': features,
                    'label': label,
                    'confidence': confidence
                }
            
            # Load adaptive thresholds
            cursor.execute('''
                SELECT detection_type, threshold_value, performance_metrics
                FROM adaptive_thresholds
                ORDER BY timestamp DESC
            ''')
            
            thresholds = cursor.fetchall()
            self.adaptive_thresholds = {}
            for detection_type, threshold_value, performance_metrics in thresholds:
                self.adaptive_thresholds[detection_type] = {
                    'threshold': threshold_value,
                    'metrics': json.loads(performance_metrics) if performance_metrics else {}
                }
            
            conn.close()
            print(f"🧠 Loaded {len(training_data)} ML patterns and {len(thresholds)} adaptive thresholds")
            
        except Exception as e:
            self.logger.error(f"Enhanced pattern loading error: {e}")
    
    def _load_whitelist_intelligence(self):
        """Load whitelist intelligence from recent scan data"""
        try:
            # Load from recent scan logs
            scan_logs = [
                "c_drive_scan_20250823_200714.txt",
                "d_drive_scan_20250823_210624.txt", 
                "f_drive_scan_20250823_231038.txt"
            ]
            
            for log_file in scan_logs:
                if os.path.exists(log_file):
                    self._extract_whitelist_from_scan_log(log_file)
            
            # Load from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT entity_value, confidence_score 
                FROM whitelist_intelligence 
                WHERE confidence_score > 0.8
            ''')
            
            whitelist_entries = cursor.fetchall()
            for entity_value, confidence in whitelist_entries:
                self.whitelist_cache.add(entity_value)
            
            conn.close()
            print(f"🧠 Loaded {len(self.whitelist_cache)} whitelist entries")
            
        except Exception as e:
            self.logger.error(f"Whitelist intelligence loading error: {e}")
    
    def _extract_whitelist_from_scan_log(self, log_file):
        """Extract safe patterns from scan logs"""
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if "✅ Clean:" in line:
                        # Extract file path
                        match = re.search(r'✅ Clean: (.+)$', line)
                        if match:
                            file_path = match.group(1).strip()
                            
                            # Add file extension to whitelist
                            ext = os.path.splitext(file_path)[1].lower()
                            if ext:
                                self.whitelist_cache.add(f"ext:{ext}")
                            
                            # Add directory patterns
                            if any(safe_dir in file_path.lower() for safe_dir in [
                                'site-packages', 'node_modules', '.venv', 'python',
                                'windows\\system32', 'program files'
                            ]):
                                self.whitelist_cache.add(f"path_pattern:{file_path.lower()}")
                                
        except Exception as e:
            self.logger.error(f"Scan log extraction error for {log_file}: {e}")
    
    def enhanced_file_analysis(self, process_name: str, file_path: str) -> Dict:
        """Enhanced file analysis with ML features"""
        try:
            # Extract comprehensive features
            features = self._extract_file_features(process_name, file_path)
            
            # Check whitelist first
            if self._is_whitelisted(file_path, process_name):
                return {
                    'anomaly_score': 0.01,
                    'confidence': 0.99,
                    'classification': 'safe',
                    'reason': 'Whitelisted entity',
                    'features': features
                }
            
            # Calculate ML-based anomaly score
            ml_score = self._calculate_ml_anomaly_score(features)
            
            # Apply adaptive threshold
            threshold = self._get_adaptive_threshold('file_access')
            
            # Temporal pattern analysis
            temporal_score = self._analyze_temporal_patterns(process_name, file_path)
            
            # Combine scores with weighted average
            final_score = (ml_score * 0.6) + (temporal_score * 0.4)
            
            # Determine classification
            if final_score > threshold:
                classification = 'anomalous'
                confidence = min(final_score, 0.95)
            else:
                classification = 'normal'
                confidence = 1.0 - final_score
            
            return {
                'anomaly_score': final_score,
                'confidence': confidence,
                'classification': classification,
                'ml_score': ml_score,
                'temporal_score': temporal_score,
                'threshold': threshold,
                'features': features
            }
            
        except Exception as e:
            self.logger.error(f"Enhanced file analysis error: {e}")
            return {
                'anomaly_score': 0.1,
                'confidence': 0.5,
                'classification': 'unknown',
                'error': str(e)
            }
    
    def _extract_file_features(self, process_name: str, file_path: str) -> Dict:
        """Extract comprehensive features for ML analysis"""
        features = {}
        
        try:
            # Basic file features
            features['file_extension'] = os.path.splitext(file_path)[1].lower()
            features['file_name_length'] = len(os.path.basename(file_path))
            features['path_depth'] = len(Path(file_path).parts)
            
            # Process features
            features['process_name'] = process_name.lower()
            features['process_name_length'] = len(process_name)
            
            # Path analysis features
            path_lower = file_path.lower()
            features['is_system_path'] = any(sys_path in path_lower for sys_path in [
                'windows\\system32', 'windows\\syswow64', 'program files'
            ])
            features['is_temp_path'] = any(temp_path in path_lower for temp_path in [
                'temp', 'tmp', 'cache'
            ])
            features['is_user_path'] = 'users\\' in path_lower
            features['is_dev_path'] = any(dev_path in path_lower for dev_path in [
                'site-packages', 'node_modules', '.venv', 'src\\', 'lib\\'
            ])
            
            # Temporal features
            current_hour = datetime.now().hour
            features['access_hour'] = current_hour
            features['is_business_hours'] = 9 <= current_hour <= 17
            features['is_night_access'] = current_hour < 6 or current_hour > 22
            
            # Historical features
            access_count = self.dynamic_patterns[f"{process_name}:{file_path}"]['count']
            features['historical_access_count'] = min(access_count, 100)  # Cap for normalization
            features['is_frequent_access'] = access_count > 10
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction error: {e}")
            return {'error': str(e)}
    
    def _calculate_ml_anomaly_score(self, features: Dict) -> float:
        """Calculate anomaly score using ML features"""
        try:
            # Simple rule-based ML simulation (can be replaced with actual ML model)
            score = 0.1  # Base score
            
            # File extension analysis
            safe_extensions = {'.dll', '.exe', '.sys', '.py', '.js', '.json', '.txt', '.log'}
            if features.get('file_extension') in safe_extensions:
                score -= 0.3
            
            # Path analysis
            if features.get('is_system_path'):
                score -= 0.4
            if features.get('is_dev_path'):
                score -= 0.3
            if features.get('is_temp_path'):
                score += 0.2
            
            # Process analysis
            safe_processes = {'python.exe', 'node.exe', 'chrome.exe', 'explorer.exe'}
            if features.get('process_name') in safe_processes:
                score -= 0.2
            
            # Temporal analysis
            if features.get('is_night_access'):
                score += 0.1
            if features.get('is_business_hours'):
                score -= 0.1
            
            # Historical analysis
            if features.get('is_frequent_access'):
                score -= 0.2
            
            # Normalize score to [0, 1]
            return max(0.0, min(1.0, score + 0.5))
            
        except Exception as e:
            self.logger.error(f"ML score calculation error: {e}")
            return 0.5
    
    def _is_whitelisted(self, file_path: str, process_name: str) -> bool:
        """Check if entity is whitelisted"""
        try:
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            if f"ext:{ext}" in self.whitelist_cache:
                return True
            
            # Check path patterns
            path_lower = file_path.lower()
            for whitelist_entry in self.whitelist_cache:
                if whitelist_entry.startswith("path_pattern:"):
                    pattern = whitelist_entry.replace("path_pattern:", "")
                    if pattern in path_lower:
                        return True
            
            # Check process name
            if process_name.lower() in self.whitelist_cache:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Whitelist check error: {e}")
            return False
    
    def _get_adaptive_threshold(self, detection_type: str) -> float:
        """Get adaptive threshold based on performance"""
        try:
            if detection_type in self.adaptive_thresholds:
                threshold_data = self.adaptive_thresholds[detection_type]
                base_threshold = threshold_data['threshold']
                
                # Adjust based on recent performance
                metrics = threshold_data.get('metrics', {})
                false_positive_rate = metrics.get('false_positive_rate', 0.1)
                
                # Increase threshold if too many false positives
                if false_positive_rate > 0.15:
                    adjustment = self.dynamic_threshold_adjustment * 2
                elif false_positive_rate > 0.1:
                    adjustment = self.dynamic_threshold_adjustment
                else:
                    adjustment = 0
            
                return min(0.98, base_threshold + adjustment)
            
            return self.base_anomaly_threshold
            
        except Exception as e:
            self.logger.error(f"Adaptive threshold error: {e}")
            return self.base_anomaly_threshold
    
    def _analyze_temporal_patterns(self, process_name: str, file_path: str) -> float:
        """Analyze temporal access patterns"""
        try:
            key = f"{process_name}:{file_path}"
            pattern_data = self.dynamic_patterns[key]
            
            current_time = datetime.now()
            last_seen = pattern_data.get('last_seen')
            
            if last_seen:
                time_diff = (current_time - datetime.fromisoformat(last_seen)).total_seconds()
                
                # Recent access is less anomalous
                if time_diff < 3600:  # 1 hour
                    temporal_score = 0.1
                elif time_diff < 86400:  # 1 day
                    temporal_score = 0.3
                else:
                    temporal_score = 0.6
            else:
                # First time access is more anomalous
                temporal_score = 0.7
            
            # Update pattern data
            pattern_data['count'] += 1
            pattern_data['last_seen'] = current_time.isoformat()
            
            return temporal_score
            
        except Exception as e:
            self.logger.error(f"Temporal pattern analysis error: {e}")
            return 0.5
    
    def learn_from_feedback(self, detection_id: str, is_false_positive: bool, user_feedback: str = ""):
        """Learn from user feedback to improve detection accuracy"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Record feedback
            cursor.execute('''
                INSERT INTO learning_feedback 
                (detection_id, feedback_type, is_false_positive, user_feedback, timestamp, confidence_adjustment)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                'false_positive' if is_false_positive else 'true_positive',
                is_false_positive,
                user_feedback,
                datetime.now().isoformat(),
                -self.false_positive_penalty if is_false_positive else self.learning_rate
            ))
            
            # Update adaptive thresholds based on feedback
            if is_false_positive:
                self._adjust_threshold_for_false_positive(detection_id)
            
            conn.commit()
            conn.close()
            
            print(f"🧠 Learned from feedback: {'False positive' if is_false_positive else 'True positive'}")
            
        except Exception as e:
            self.logger.error(f"Learning from feedback error: {e}")
    
    def _adjust_threshold_for_false_positive(self, detection_id: str):
        """Adjust thresholds based on false positive feedback"""
        try:
            # Increase threshold slightly to reduce false positives
            for detection_type in self.adaptive_thresholds:
                current_threshold = self.adaptive_thresholds[detection_type]['threshold']
                new_threshold = min(0.95, current_threshold + 0.01)
                self.adaptive_thresholds[detection_type]['threshold'] = new_threshold
            
        except Exception as e:
            self.logger.error(f"Threshold adjustment error: {e}")
    
    def train_from_scan_data(self, scan_log_file: str):
        """Train the AI from scan log data"""
        try:
            print(f"🧠 Training AI from scan data: {scan_log_file}")
            
            if not os.path.exists(scan_log_file):
                print(f"⚠️ Scan log file not found: {scan_log_file}")
                return
            
            clean_count = 0
            threat_count = 0
            
            with open(scan_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if "✅ Clean:" in line:
                        # Extract clean file for training
                        match = re.search(r'✅ Clean: (.+)$', line)
                        if match:
                            file_path = match.group(1).strip()
                            self._add_training_data(file_path, "clean", 0.0, 0.9)
                            clean_count += 1
                    
                    elif "🚨 THREAT" in line and "Score:" in line:
                        # Extract threat file for training
                        match = re.search(r'🚨 THREAT.*?: (.+?) \(Score: ([\d.]+)\)', line)
                        if match:
                            file_path = match.group(1).strip()
                            score = float(match.group(2))
                            
                            # Only train on high-confidence threats
                            if score > 0.9:
                                self._add_training_data(file_path, "threat", score, 0.8)
                                threat_count += 1
            
            print(f"🧠 Training complete: {clean_count} clean samples, {threat_count} threat samples")
            
        except Exception as e:
            self.logger.error(f"Training from scan data error: {e}")
    
    def _add_training_data(self, file_path: str, label_type: str, score: float, confidence: float):
        """Add training data to ML database"""
        try:
            # Extract features
            features = self._extract_file_features("scanner", file_path)
            
            # Convert label to numeric
            label = 0.0 if label_type == "clean" else score
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO ml_training_data 
                (feature_type, feature_vector, label, confidence, timestamp, validation_status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                'file_analysis',
                json.dumps(features),
                label,
                confidence,
                datetime.now().isoformat(),
                'validated'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Training data addition error: {e}")
    
    def get_performance_metrics(self) -> Dict:
        """Get AI performance metrics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get feedback statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_feedback,
                    SUM(CASE WHEN is_false_positive = 1 THEN 1 ELSE 0 END) as false_positives,
                    SUM(CASE WHEN is_false_positive = 0 THEN 1 ELSE 0 END) as true_positives
                FROM learning_feedback
                WHERE timestamp > datetime('now', '-7 days')
            ''')
            
            feedback_stats = cursor.fetchone()
            
            # Get training data statistics
            cursor.execute('''
                SELECT COUNT(*) FROM ml_training_data WHERE validation_status = 'validated'
            ''')
            
            training_count = cursor.fetchone()[0]
            
            conn.close()
            
            total_feedback = feedback_stats[0] or 0
            false_positives = feedback_stats[1] or 0
            true_positives = feedback_stats[2] or 0
            
            false_positive_rate = false_positives / max(total_feedback, 1)
            accuracy = true_positives / max(total_feedback, 1)
            
            return {
                'total_feedback': total_feedback,
                'false_positive_rate': false_positive_rate,
                'accuracy': accuracy,
                'training_samples': training_count,
                'whitelist_entries': len(self.whitelist_cache),
                'dynamic_patterns': len(self.dynamic_patterns),
                'adaptive_thresholds': len(self.adaptive_thresholds)
            }
            
        except Exception as e:
            self.logger.error(f"Performance metrics error: {e}")
            return {}

def main():
    """Test the enhanced anomaly detector"""
    detector = EnhancedAnomalyDetector()
    
    # Train from recent scan data
    scan_logs = [
        "c_drive_scan_20250823_200714.txt",
        "d_drive_scan_20250823_210624.txt", 
        "f_drive_scan_20250823_231038.txt"
    ]
    
    for log_file in scan_logs:
        if os.path.exists(log_file):
            detector.train_from_scan_data(log_file)
    
    # Test analysis
    test_files = [
        ("python.exe", "F:\\ai-pipeline\\venv\\Lib\\site-packages\\pip\\__init__.py"),
        ("chrome.exe", "C:\\Users\\test\\Downloads\\suspicious.exe"),
        ("explorer.exe", "C:\\Windows\\System32\\kernel32.dll")
    ]
    
    print("\n🧠 Testing Enhanced AI Analysis:")
    for process, file_path in test_files:
        result = detector.enhanced_file_analysis(process, file_path)
        print(f"Process: {process}")
        print(f"File: {file_path}")
        print(f"Score: {result['anomaly_score']:.3f}, Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']:.3f}")
        print("-" * 60)
    
    # Show performance metrics
    metrics = detector.get_performance_metrics()
    print("\n📊 AI Performance Metrics:")
    for key, value in metrics.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
