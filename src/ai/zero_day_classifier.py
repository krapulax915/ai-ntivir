#!/usr/bin/env python3
"""
Machine Learning-Based Zero-Day Classifier
Advanced ML classification for zero-day threat detection
"""

import os
import json
import pickle
import logging
import numpy as np
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import hashlib

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.cluster import DBSCAN
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

@dataclass
class ClassificationResult:
    """ML classification result"""
    prediction: str
    confidence: float
    threat_probability: float
    feature_importance: Dict[str, float]
    model_used: str
    classification_time: float

@dataclass
class TrainingData:
    """Training data for ML models"""
    features: np.ndarray
    labels: np.ndarray
    feature_names: List[str]
    sample_count: int
    positive_samples: int
    negative_samples: int

class ZeroDayClassifier:
    """Machine learning-based zero-day threat classifier"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.ai.zero_day_classifier')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "zero_day_classifier.db")
        
        os.makedirs(models_dir, exist_ok=True)
        self.init_database()
        
        # ML Models
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        
        # Feature configuration
        self.feature_names = [
            # Process features
            'process_suspicious_name', 'process_cmdline_suspicious', 'process_injection_indicators',
            'process_privilege_escalation', 'process_anti_analysis', 'process_memory_usage',
            'process_cpu_usage', 'process_network_activity', 'process_file_activity',
            'process_registry_activity',
            
            # Network features
            'network_external_connections', 'network_suspicious_ports', 'network_data_volume',
            'network_connection_frequency', 'network_protocol_anomaly', 'network_c2_indicators',
            'network_dns_requests', 'network_encryption_usage',
            
            # File features
            'file_suspicious_locations', 'file_rapid_operations', 'file_encryption_activity',
            'file_deletion_patterns', 'file_modification_frequency', 'file_size_anomalies',
            'file_type_diversity', 'file_system_access',
            
            # Registry features
            'registry_startup_modifications', 'registry_security_changes', 'registry_service_changes',
            'registry_policy_modifications', 'registry_persistence_indicators',
            
            # Behavioral features
            'behavior_evasion_techniques', 'behavior_persistence_attempts', 'behavior_data_theft',
            'behavior_system_compromise', 'behavior_lateral_movement', 'behavior_command_control',
            
            # Temporal features
            'temporal_activity_pattern', 'temporal_burst_activity', 'temporal_stealth_indicators',
            'temporal_coordination_patterns'
        ]
        
        # Initialize models
        self.init_models()
        self.load_trained_models()
        
        self.logger.info("Zero-Day Classifier initialized")
    
    def init_database(self):
        """Initialize database for ML classifier"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Training data table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS training_data (
                        sample_id TEXT PRIMARY KEY,
                        features TEXT NOT NULL,
                        label TEXT NOT NULL,
                        source TEXT,
                        confidence REAL,
                        verified BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Model performance table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_performance (
                        model_id TEXT PRIMARY KEY,
                        model_name TEXT NOT NULL,
                        accuracy REAL,
                        precision_score REAL,
                        recall REAL,
                        f1_score REAL,
                        training_samples INTEGER,
                        training_time REAL,
                        last_trained TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Classification results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS classification_results (
                        result_id TEXT PRIMARY KEY,
                        features TEXT NOT NULL,
                        prediction TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        threat_probability REAL NOT NULL,
                        model_used TEXT NOT NULL,
                        classification_time REAL,
                        verified_result TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_training_label ON training_data(label)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_name ON model_performance(model_name)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_classification_time ON classification_results(created_at)')
                
                conn.commit()
                self.logger.info("Zero-day classifier database initialized")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
    
    def init_models(self):
        """Initialize ML models"""
        try:
            if not SKLEARN_AVAILABLE:
                self.logger.warning("Scikit-learn not available, using basic classification")
                return
            
            # Random Forest Classifier
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            
            # Neural Network Classifier
            self.models['neural_network'] = MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation='relu',
                solver='adam',
                alpha=0.001,
                batch_size=32,
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            )
            
            # Isolation Forest for anomaly detection
            self.models['isolation_forest'] = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # DBSCAN for clustering
            self.models['dbscan'] = DBSCAN(
                eps=0.5,
                min_samples=5,
                metric='euclidean'
            )
            
            # Initialize scalers
            for model_name in self.models.keys():
                self.scalers[model_name] = StandardScaler()
            
            # Initialize label encoders
            self.label_encoders['threat_type'] = LabelEncoder()
            
            self.logger.info("ML models initialized")
            
        except Exception as e:
            self.logger.error(f"Model initialization failed: {e}")
    
    def load_trained_models(self):
        """Load pre-trained models from disk"""
        try:
            model_files = {
                'random_forest': 'zero_day_rf_model.pkl',
                'neural_network': 'zero_day_nn_model.pkl',
                'isolation_forest': 'zero_day_if_model.pkl'
            }
            
            for model_name, filename in model_files.items():
                model_path = os.path.join(self.models_dir, filename)
                scaler_path = os.path.join(self.models_dir, f"{model_name}_scaler.pkl")
                
                if os.path.exists(model_path) and os.path.exists(scaler_path):
                    try:
                        self.models[model_name] = joblib.load(model_path)
                        self.scalers[model_name] = joblib.load(scaler_path)
                        self.logger.info(f"Loaded pre-trained model: {model_name}")
                    except Exception as e:
                        self.logger.warning(f"Failed to load model {model_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Model loading failed: {e}")
    
    def extract_features(self, behavior_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from behavior data"""
        try:
            features = np.zeros(len(self.feature_names))
            
            # Process features
            process_data = behavior_data.get('process', {})
            features[0] = self._extract_process_suspicious_name(process_data)
            features[1] = self._extract_process_cmdline_suspicious(process_data)
            features[2] = self._extract_process_injection_indicators(process_data)
            features[3] = self._extract_process_privilege_escalation(process_data)
            features[4] = self._extract_process_anti_analysis(process_data)
            features[5] = process_data.get('memory_usage', 0.0) / 1024.0  # Normalize to GB
            features[6] = process_data.get('cpu_usage', 0.0) / 100.0  # Normalize to percentage
            features[7] = len(process_data.get('network_connections', []))
            features[8] = len(process_data.get('file_operations', []))
            features[9] = len(process_data.get('registry_operations', []))
            
            # Network features
            network_data = behavior_data.get('network', {})
            features[10] = len(network_data.get('external_connections', []))
            features[11] = self._extract_suspicious_ports(network_data)
            features[12] = network_data.get('data_volume', 0.0) / 1024.0  # Normalize to KB
            features[13] = network_data.get('connection_frequency', 0.0)
            features[14] = self._extract_protocol_anomaly(network_data)
            features[15] = self._extract_c2_indicators(network_data)
            features[16] = len(network_data.get('dns_requests', []))
            features[17] = network_data.get('encryption_usage', 0.0)
            
            # File features
            file_data = behavior_data.get('file', {})
            features[18] = self._extract_suspicious_file_locations(file_data)
            features[19] = file_data.get('rapid_operations', 0.0)
            features[20] = file_data.get('encryption_activity', 0.0)
            features[21] = self._extract_deletion_patterns(file_data)
            features[22] = file_data.get('modification_frequency', 0.0)
            features[23] = self._extract_size_anomalies(file_data)
            features[24] = len(set(file_data.get('file_types', [])))
            features[25] = file_data.get('system_access', 0.0)
            
            # Registry features
            registry_data = behavior_data.get('registry', {})
            features[26] = self._extract_startup_modifications(registry_data)
            features[27] = self._extract_security_changes(registry_data)
            features[28] = self._extract_service_changes(registry_data)
            features[29] = self._extract_policy_modifications(registry_data)
            features[30] = self._extract_persistence_indicators(registry_data)
            
            # Behavioral features
            behavioral_data = behavior_data.get('behavioral', {})
            features[31] = behavioral_data.get('evasion_techniques', 0.0)
            features[32] = behavioral_data.get('persistence_attempts', 0.0)
            features[33] = behavioral_data.get('data_theft', 0.0)
            features[34] = behavioral_data.get('system_compromise', 0.0)
            features[35] = behavioral_data.get('lateral_movement', 0.0)
            features[36] = behavioral_data.get('command_control', 0.0)
            
            # Temporal features
            temporal_data = behavior_data.get('temporal', {})
            features[37] = self._extract_activity_pattern(temporal_data)
            features[38] = temporal_data.get('burst_activity', 0.0)
            features[39] = temporal_data.get('stealth_indicators', 0.0)
            features[40] = temporal_data.get('coordination_patterns', 0.0)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return np.zeros(len(self.feature_names))
    
    def _extract_process_suspicious_name(self, process_data: Dict[str, Any]) -> float:
        """Extract suspicious process name indicator"""
        suspicious_names = ['powershell', 'cmd', 'rundll32', 'regsvr32', 'wscript', 'cscript']
        process_name = process_data.get('name', '').lower()
        return 1.0 if any(name in process_name for name in suspicious_names) else 0.0
    
    def _extract_process_cmdline_suspicious(self, process_data: Dict[str, Any]) -> float:
        """Extract suspicious command line indicator"""
        suspicious_args = ['-encodedcommand', '-noprofile', 'downloadstring', 'invoke-expression', 'bypass']
        cmdline = process_data.get('command_line', '').lower()
        return sum(1.0 for arg in suspicious_args if arg in cmdline) / len(suspicious_args)
    
    def _extract_process_injection_indicators(self, process_data: Dict[str, Any]) -> float:
        """Extract process injection indicators"""
        injection_indicators = ['inject', 'hollow', 'createremotethread', 'writeprocessmemory']
        cmdline = process_data.get('command_line', '').lower()
        activities = process_data.get('activities', [])
        
        score = 0.0
        for indicator in injection_indicators:
            if indicator in cmdline or indicator in str(activities).lower():
                score += 1.0
        
        return min(score / len(injection_indicators), 1.0)
    
    def _extract_process_privilege_escalation(self, process_data: Dict[str, Any]) -> float:
        """Extract privilege escalation indicators"""
        escalation_indicators = ['runas', 'elevate', 'uac', 'bypass', 'admin']
        cmdline = process_data.get('command_line', '').lower()
        return sum(1.0 for indicator in escalation_indicators if indicator in cmdline) / len(escalation_indicators)
    
    def _extract_process_anti_analysis(self, process_data: Dict[str, Any]) -> float:
        """Extract anti-analysis indicators"""
        anti_analysis = ['debugger', 'sandbox', 'vm', 'virtual', 'analysis', 'monitor']
        cmdline = process_data.get('command_line', '').lower()
        return sum(1.0 for indicator in anti_analysis if indicator in cmdline) / len(anti_analysis)
    
    def _extract_suspicious_ports(self, network_data: Dict[str, Any]) -> float:
        """Extract suspicious port usage"""
        suspicious_ports = [4444, 8080, 9999, 31337, 12345, 6666, 1337]
        ports = network_data.get('ports', [])
        return sum(1.0 for port in ports if port in suspicious_ports) / max(len(ports), 1)
    
    def _extract_protocol_anomaly(self, network_data: Dict[str, Any]) -> float:
        """Extract protocol anomaly indicators"""
        protocols = network_data.get('protocols', [])
        unusual_protocols = ['irc', 'p2p', 'tor', 'i2p']
        return sum(1.0 for protocol in protocols if protocol.lower() in unusual_protocols) / max(len(protocols), 1)
    
    def _extract_c2_indicators(self, network_data: Dict[str, Any]) -> float:
        """Extract command and control indicators"""
        c2_indicators = network_data.get('c2_indicators', [])
        return len(c2_indicators) / 10.0  # Normalize
    
    def _extract_suspicious_file_locations(self, file_data: Dict[str, Any]) -> float:
        """Extract suspicious file location indicators"""
        suspicious_paths = ['temp', 'appdata', 'programdata', 'startup', 'system32']
        file_paths = file_data.get('file_paths', [])
        
        score = 0.0
        for path in file_paths:
            for sus_path in suspicious_paths:
                if sus_path.lower() in path.lower():
                    score += 1.0
                    break
        
        return score / max(len(file_paths), 1)
    
    def _extract_deletion_patterns(self, file_data: Dict[str, Any]) -> float:
        """Extract file deletion pattern indicators"""
        operations = file_data.get('operations', [])
        deletions = sum(1 for op in operations if 'delete' in str(op).lower())
        return deletions / max(len(operations), 1)
    
    def _extract_size_anomalies(self, file_data: Dict[str, Any]) -> float:
        """Extract file size anomaly indicators"""
        sizes = file_data.get('file_sizes', [])
        if not sizes:
            return 0.0
        
        mean_size = np.mean(sizes)
        std_size = np.std(sizes)
        
        if std_size == 0:
            return 0.0
        
        anomalies = sum(1 for size in sizes if abs(size - mean_size) > 2 * std_size)
        return anomalies / len(sizes)
    
    def _extract_startup_modifications(self, registry_data: Dict[str, Any]) -> float:
        """Extract startup modification indicators"""
        keys = registry_data.get('keys', [])
        startup_keys = ['run', 'runonce', 'startup', 'winlogon']
        return sum(1.0 for key in keys if any(startup in key.lower() for startup in startup_keys)) / max(len(keys), 1)
    
    def _extract_security_changes(self, registry_data: Dict[str, Any]) -> float:
        """Extract security setting change indicators"""
        keys = registry_data.get('keys', [])
        security_keys = ['security', 'policies', 'firewall', 'defender']
        return sum(1.0 for key in keys if any(sec in key.lower() for sec in security_keys)) / max(len(keys), 1)
    
    def _extract_service_changes(self, registry_data: Dict[str, Any]) -> float:
        """Extract service change indicators"""
        keys = registry_data.get('keys', [])
        service_keys = ['services', 'service']
        return sum(1.0 for key in keys if any(svc in key.lower() for svc in service_keys)) / max(len(keys), 1)
    
    def _extract_policy_modifications(self, registry_data: Dict[str, Any]) -> float:
        """Extract policy modification indicators"""
        keys = registry_data.get('keys', [])
        policy_keys = ['policy', 'policies', 'group policy']
        return sum(1.0 for key in keys if any(pol in key.lower() for pol in policy_keys)) / max(len(keys), 1)
    
    def _extract_persistence_indicators(self, registry_data: Dict[str, Any]) -> float:
        """Extract persistence mechanism indicators"""
        operations = registry_data.get('operations', [])
        persistence_ops = ['create', 'modify', 'add']
        return sum(1.0 for op in operations if any(pers in str(op).lower() for pers in persistence_ops)) / max(len(operations), 1)
    
    def _extract_activity_pattern(self, temporal_data: Dict[str, Any]) -> float:
        """Extract activity pattern indicators"""
        timestamps = temporal_data.get('timestamps', [])
        if len(timestamps) < 2:
            return 0.0
        
        # Calculate time intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)
        
        # Check for regular patterns (potential automation)
        if len(intervals) > 1:
            std_interval = np.std(intervals)
            mean_interval = np.mean(intervals)
            
            if mean_interval > 0:
                regularity = 1.0 - (std_interval / mean_interval)
                return max(0.0, min(1.0, regularity))
        
        return 0.0
    
    def classify_threat(self, behavior_data: Dict[str, Any]) -> ClassificationResult:
        """Classify threat using ML models"""
        try:
            start_time = datetime.now()
            
            # Extract features
            features = self.extract_features(behavior_data)
            features_2d = features.reshape(1, -1)
            
            # Get predictions from all models
            predictions = {}
            confidences = {}
            
            for model_name, model in self.models.items():
                if model_name in ['random_forest', 'neural_network']:
                    try:
                        # Scale features
                        if model_name in self.scalers:
                            scaled_features = self.scalers[model_name].transform(features_2d)
                        else:
                            scaled_features = features_2d
                        
                        # Get prediction
                        if hasattr(model, 'predict_proba'):
                            proba = model.predict_proba(scaled_features)[0]
                            prediction = model.classes_[np.argmax(proba)]
                            confidence = np.max(proba)
                        else:
                            prediction = model.predict(scaled_features)[0]
                            confidence = 0.8  # Default confidence
                        
                        predictions[model_name] = prediction
                        confidences[model_name] = confidence
                        
                    except Exception as e:
                        self.logger.warning(f"Model {model_name} prediction failed: {e}")
                        continue
            
            # Ensemble prediction
            if predictions:
                # Use majority voting with confidence weighting
                weighted_votes = {}
                for model_name, prediction in predictions.items():
                    confidence = confidences[model_name]
                    if prediction not in weighted_votes:
                        weighted_votes[prediction] = 0.0
                    weighted_votes[prediction] += confidence
                
                # Get final prediction
                final_prediction = max(weighted_votes.keys(), key=lambda x: weighted_votes[x])
                final_confidence = weighted_votes[final_prediction] / len(predictions)
                
                # Calculate threat probability
                threat_probability = self._calculate_threat_probability(features, predictions, confidences)
                
                # Get feature importance
                feature_importance = self._get_feature_importance(features)
                
                # Determine best model
                best_model = max(confidences.keys(), key=lambda x: confidences[x])
                
            else:
                # Fallback prediction
                final_prediction = "unknown"
                final_confidence = 0.5
                threat_probability = 0.5
                feature_importance = {}
                best_model = "fallback"
            
            classification_time = (datetime.now() - start_time).total_seconds()
            
            result = ClassificationResult(
                prediction=final_prediction,
                confidence=final_confidence,
                threat_probability=threat_probability,
                feature_importance=feature_importance,
                model_used=best_model,
                classification_time=classification_time
            )
            
            # Save result
            self.save_classification_result(result, features)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Threat classification failed: {e}")
            return ClassificationResult(
                prediction="error",
                confidence=0.0,
                threat_probability=0.0,
                feature_importance={},
                model_used="none",
                classification_time=0.0
            )
    
    def _calculate_threat_probability(self, features: np.ndarray, 
                                    predictions: Dict[str, str], 
                                    confidences: Dict[str, float]) -> float:
        """Calculate overall threat probability"""
        try:
            # Base probability from feature analysis
            high_risk_features = [0, 1, 2, 3, 4, 11, 14, 15, 18, 20, 26, 27, 31, 32, 33, 34]
            feature_risk = np.mean([features[i] for i in high_risk_features if i < len(features)])
            
            # Model consensus
            threat_predictions = sum(1 for pred in predictions.values() if pred in ['malware', 'threat', 'suspicious'])
            model_consensus = threat_predictions / max(len(predictions), 1)
            
            # Confidence weighting
            avg_confidence = np.mean(list(confidences.values())) if confidences else 0.5
            
            # Combine factors
            threat_probability = (feature_risk * 0.4 + model_consensus * 0.4 + avg_confidence * 0.2)
            
            return min(max(threat_probability, 0.0), 1.0)
            
        except Exception as e:
            self.logger.error(f"Threat probability calculation failed: {e}")
            return 0.5
    
    def _get_feature_importance(self, features: np.ndarray) -> Dict[str, float]:
        """Get feature importance scores"""
        try:
            importance = {}
            
            # Use Random Forest feature importance if available
            if 'random_forest' in self.models and hasattr(self.models['random_forest'], 'feature_importances_'):
                importances = self.models['random_forest'].feature_importances_
                for i, importance_score in enumerate(importances):
                    if i < len(self.feature_names):
                        importance[self.feature_names[i]] = float(importance_score)
            else:
                # Fallback: use feature values as importance
                for i, feature_value in enumerate(features):
                    if i < len(self.feature_names):
                        importance[self.feature_names[i]] = float(feature_value)
            
            return importance
            
        except Exception as e:
            self.logger.error(f"Feature importance calculation failed: {e}")
            return {}
    
    def save_classification_result(self, result: ClassificationResult, features: np.ndarray):
        """Save classification result to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                result_id = hashlib.md5(f"{result.prediction}_{datetime.now().isoformat()}".encode()).hexdigest()
                
                cursor.execute('''
                    INSERT INTO classification_results 
                    (result_id, features, prediction, confidence, threat_probability,
                     model_used, classification_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_id,
                    json.dumps(features.tolist()),
                    result.prediction,
                    result.confidence,
                    result.threat_probability,
                    result.model_used,
                    result.classification_time
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save classification result: {e}")
    
    def get_classifier_statistics(self) -> Dict[str, Any]:
        """Get classifier statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total classifications
                cursor.execute('SELECT COUNT(*) FROM classification_results')
                total_classifications = cursor.fetchone()[0]
                
                # Classifications by prediction
                cursor.execute('''
                    SELECT prediction, COUNT(*) FROM classification_results 
                    GROUP BY prediction
                ''')
                prediction_stats = dict(cursor.fetchall())
                
                # Average confidence
                cursor.execute('SELECT AVG(confidence) FROM classification_results')
                avg_confidence = cursor.fetchone()[0] or 0.0
                
                # Recent classifications
                cursor.execute('''
                    SELECT COUNT(*) FROM classification_results 
                    WHERE created_at > datetime('now', '-24 hours')
                ''')
                recent_classifications = cursor.fetchone()[0]
                
                return {
                    'total_classifications': total_classifications,
                    'prediction_statistics': prediction_stats,
                    'average_confidence': avg_confidence,
                    'recent_classifications_24h': recent_classifications,
                    'loaded_models': list(self.models.keys()),
                    'feature_count': len(self.feature_names)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get classifier statistics: {e}")
            return {}
