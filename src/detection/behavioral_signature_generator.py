#!/usr/bin/env python3
"""
Behavioral Signature Generator
Generates behavioral signatures for zero-day threat detection
"""

import os
import json
import time
import hashlib
import logging
import sqlite3
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import pickle

try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.feature_extraction.text import TfidfVectorizer
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

@dataclass
class BehavioralSignature:
    """Behavioral signature for threat detection"""
    signature_id: str
    signature_name: str
    behavior_patterns: List[str]
    feature_vector: List[float]
    confidence_score: float
    severity_level: str
    threat_family: str
    detection_rules: Dict[str, Any]
    created_at: datetime
    last_updated: datetime
    usage_count: int = 0
    false_positive_rate: float = 0.0

@dataclass
class BehaviorFeature:
    """Individual behavior feature"""
    feature_name: str
    feature_type: str  # 'process', 'network', 'file', 'registry'
    feature_value: Any
    weight: float
    frequency: int

class BehavioralSignatureGenerator:
    """Generate behavioral signatures from threat patterns"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.behavioral_signature_generator')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = os.path.join(models_dir, "behavioral_signatures.db")
        
        os.makedirs(models_dir, exist_ok=True)
        self.init_database()
        
        # Signature storage
        self.signatures = {}
        self.behavior_features = defaultdict(list)
        
        # Feature extraction
        self.feature_extractors = {
            'process': self._extract_process_features,
            'network': self._extract_network_features,
            'file': self._extract_file_features,
            'registry': self._extract_registry_features
        }
        
        # ML components
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.clusterer = None
        self.vectorizer = TfidfVectorizer(max_features=1000) if SKLEARN_AVAILABLE else None
        
        self.load_existing_signatures()
        self.logger.info("Behavioral Signature Generator initialized")
    
    def init_database(self):
        """Initialize database for behavioral signatures"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Behavioral signatures table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS behavioral_signatures (
                        signature_id TEXT PRIMARY KEY,
                        signature_name TEXT NOT NULL,
                        behavior_patterns TEXT NOT NULL,
                        feature_vector TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        severity_level TEXT NOT NULL,
                        threat_family TEXT NOT NULL,
                        detection_rules TEXT NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        last_updated TIMESTAMP NOT NULL,
                        usage_count INTEGER DEFAULT 0,
                        false_positive_rate REAL DEFAULT 0.0
                    )
                ''')
                
                # Behavior features table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS behavior_features (
                        feature_id TEXT PRIMARY KEY,
                        feature_name TEXT NOT NULL,
                        feature_type TEXT NOT NULL,
                        feature_value TEXT NOT NULL,
                        weight REAL NOT NULL,
                        frequency INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Signature usage tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS signature_usage (
                        usage_id TEXT PRIMARY KEY,
                        signature_id TEXT NOT NULL,
                        detection_time TIMESTAMP NOT NULL,
                        file_path TEXT,
                        detection_result TEXT,
                        confidence REAL,
                        FOREIGN KEY (signature_id) REFERENCES behavioral_signatures (signature_id)
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_signatures_family ON behavioral_signatures(threat_family)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_features_type ON behavior_features(feature_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_usage_time ON signature_usage(detection_time)')
                
                conn.commit()
                self.logger.info("Behavioral signatures database initialized")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
    
    def load_existing_signatures(self):
        """Load existing signatures from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM behavioral_signatures')
                
                for row in cursor.fetchall():
                    signature = BehavioralSignature(
                        signature_id=row[0],
                        signature_name=row[1],
                        behavior_patterns=json.loads(row[2]),
                        feature_vector=json.loads(row[3]),
                        confidence_score=row[4],
                        severity_level=row[5],
                        threat_family=row[6],
                        detection_rules=json.loads(row[7]),
                        created_at=datetime.fromisoformat(row[8]),
                        last_updated=datetime.fromisoformat(row[9]),
                        usage_count=row[10],
                        false_positive_rate=row[11]
                    )
                    self.signatures[signature.signature_id] = signature
                
                self.logger.info(f"Loaded {len(self.signatures)} behavioral signatures")
                
        except Exception as e:
            self.logger.error(f"Failed to load existing signatures: {e}")
    
    def generate_signature_from_patterns(self, behavior_patterns: List[Dict[str, Any]], 
                                       threat_family: str = "unknown") -> Optional[BehavioralSignature]:
        """Generate behavioral signature from behavior patterns"""
        try:
            if not behavior_patterns:
                return None
            
            # Extract features from patterns
            features = self._extract_features_from_patterns(behavior_patterns)
            
            if not features:
                return None
            
            # Create feature vector
            feature_vector = self._create_feature_vector(features)
            
            # Calculate confidence score
            confidence_score = self._calculate_signature_confidence(behavior_patterns, features)
            
            # Determine severity level
            severity_level = self._determine_severity_level(behavior_patterns, confidence_score)
            
            # Generate detection rules
            detection_rules = self._generate_detection_rules(features, behavior_patterns)
            
            # Create signature
            signature_id = hashlib.md5(
                f"{threat_family}_{time.time()}_{len(features)}".encode()
            ).hexdigest()
            
            signature_name = f"{threat_family}_behavioral_sig_{signature_id[:8]}"
            
            signature = BehavioralSignature(
                signature_id=signature_id,
                signature_name=signature_name,
                behavior_patterns=[str(p) for p in behavior_patterns],
                feature_vector=feature_vector,
                confidence_score=confidence_score,
                severity_level=severity_level,
                threat_family=threat_family,
                detection_rules=detection_rules,
                created_at=datetime.now(),
                last_updated=datetime.now()
            )
            
            # Store signature
            self.signatures[signature_id] = signature
            self.save_signature(signature)
            
            self.logger.info(f"Generated behavioral signature: {signature_name}")
            return signature
            
        except Exception as e:
            self.logger.error(f"Failed to generate signature from patterns: {e}")
            return None
    
    def _extract_features_from_patterns(self, behavior_patterns: List[Dict[str, Any]]) -> List[BehaviorFeature]:
        """Extract features from behavior patterns"""
        try:
            features = []
            feature_counts = defaultdict(int)
            
            for pattern in behavior_patterns:
                pattern_type = pattern.get('type', 'unknown')
                
                if pattern_type in self.feature_extractors:
                    pattern_features = self.feature_extractors[pattern_type](pattern)
                    features.extend(pattern_features)
                    
                    # Count feature frequencies
                    for feature in pattern_features:
                        feature_counts[feature.feature_name] += 1
            
            # Update feature frequencies and weights
            for feature in features:
                feature.frequency = feature_counts[feature.feature_name]
                feature.weight = self._calculate_feature_weight(feature)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return []
    
    def _extract_process_features(self, pattern: Dict[str, Any]) -> List[BehaviorFeature]:
        """Extract process-related features"""
        features = []
        
        try:
            process_name = pattern.get('process_name', '')
            command_line = pattern.get('command_line', '')
            activities = pattern.get('activities', [])
            
            # Process name feature
            if process_name:
                features.append(BehaviorFeature(
                    feature_name=f"process_name_{process_name.lower()}",
                    feature_type='process',
                    feature_value=process_name,
                    weight=0.8,
                    frequency=1
                ))
            
            # Command line features
            if command_line:
                # Check for suspicious command line patterns
                suspicious_patterns = [
                    'powershell', 'cmd', 'rundll32', 'regsvr32',
                    '-encodedcommand', '-noprofile', 'downloadstring',
                    'invoke-expression', 'bypass', 'hidden'
                ]
                
                for pattern_str in suspicious_patterns:
                    if pattern_str.lower() in command_line.lower():
                        features.append(BehaviorFeature(
                            feature_name=f"cmdline_pattern_{pattern_str}",
                            feature_type='process',
                            feature_value=pattern_str,
                            weight=0.9,
                            frequency=1
                        ))
            
            # Activity features
            for activity in activities:
                features.append(BehaviorFeature(
                    feature_name=f"process_activity_{activity}",
                    feature_type='process',
                    feature_value=activity,
                    weight=0.7,
                    frequency=1
                ))
            
        except Exception as e:
            self.logger.error(f"Process feature extraction failed: {e}")
        
        return features
    
    def _extract_network_features(self, pattern: Dict[str, Any]) -> List[BehaviorFeature]:
        """Extract network-related features"""
        features = []
        
        try:
            connections = pattern.get('connections', [])
            protocols = pattern.get('protocols', [])
            ports = pattern.get('ports', [])
            
            # Connection features
            for conn in connections:
                if isinstance(conn, dict):
                    remote_addr = conn.get('remote_addr', '')
                    if remote_addr:
                        features.append(BehaviorFeature(
                            feature_name=f"network_connection_{remote_addr}",
                            feature_type='network',
                            feature_value=remote_addr,
                            weight=0.6,
                            frequency=1
                        ))
            
            # Protocol features
            for protocol in protocols:
                features.append(BehaviorFeature(
                    feature_name=f"network_protocol_{protocol}",
                    feature_type='network',
                    feature_value=protocol,
                    weight=0.5,
                    frequency=1
                ))
            
            # Suspicious port features
            suspicious_ports = [4444, 8080, 9999, 31337, 12345]
            for port in ports:
                if port in suspicious_ports:
                    features.append(BehaviorFeature(
                        feature_name=f"suspicious_port_{port}",
                        feature_type='network',
                        feature_value=port,
                        weight=0.8,
                        frequency=1
                    ))
            
        except Exception as e:
            self.logger.error(f"Network feature extraction failed: {e}")
        
        return features
    
    def _extract_file_features(self, pattern: Dict[str, Any]) -> List[BehaviorFeature]:
        """Extract file-related features"""
        features = []
        
        try:
            file_operations = pattern.get('file_operations', [])
            file_paths = pattern.get('file_paths', [])
            file_types = pattern.get('file_types', [])
            
            # File operation features
            for operation in file_operations:
                features.append(BehaviorFeature(
                    feature_name=f"file_operation_{operation}",
                    feature_type='file',
                    feature_value=operation,
                    weight=0.7,
                    frequency=1
                ))
            
            # Suspicious file path features
            suspicious_paths = [
                'temp', 'appdata', 'programdata', 'system32',
                'startup', 'documents', 'downloads'
            ]
            
            for file_path in file_paths:
                for sus_path in suspicious_paths:
                    if sus_path.lower() in file_path.lower():
                        features.append(BehaviorFeature(
                            feature_name=f"suspicious_path_{sus_path}",
                            feature_type='file',
                            feature_value=sus_path,
                            weight=0.6,
                            frequency=1
                        ))
            
            # File type features
            for file_type in file_types:
                features.append(BehaviorFeature(
                    feature_name=f"file_type_{file_type}",
                    feature_type='file',
                    feature_value=file_type,
                    weight=0.5,
                    frequency=1
                ))
            
        except Exception as e:
            self.logger.error(f"File feature extraction failed: {e}")
        
        return features
    
    def _extract_registry_features(self, pattern: Dict[str, Any]) -> List[BehaviorFeature]:
        """Extract registry-related features"""
        features = []
        
        try:
            registry_operations = pattern.get('registry_operations', [])
            registry_keys = pattern.get('registry_keys', [])
            
            # Registry operation features
            for operation in registry_operations:
                features.append(BehaviorFeature(
                    feature_name=f"registry_operation_{operation}",
                    feature_type='registry',
                    feature_value=operation,
                    weight=0.7,
                    frequency=1
                ))
            
            # Suspicious registry key features
            suspicious_keys = [
                'run', 'runonce', 'startup', 'services',
                'policies', 'security', 'winlogon'
            ]
            
            for reg_key in registry_keys:
                for sus_key in suspicious_keys:
                    if sus_key.lower() in reg_key.lower():
                        features.append(BehaviorFeature(
                            feature_name=f"suspicious_regkey_{sus_key}",
                            feature_type='registry',
                            feature_value=sus_key,
                            weight=0.8,
                            frequency=1
                        ))
            
        except Exception as e:
            self.logger.error(f"Registry feature extraction failed: {e}")
        
        return features
    
    def _calculate_feature_weight(self, feature: BehaviorFeature) -> float:
        """Calculate weight for a feature based on its characteristics"""
        try:
            base_weight = feature.weight
            
            # Adjust weight based on frequency
            frequency_factor = min(feature.frequency / 10.0, 1.0)
            
            # Adjust weight based on feature type importance
            type_weights = {
                'process': 1.0,
                'network': 0.8,
                'file': 0.7,
                'registry': 0.9
            }
            
            type_factor = type_weights.get(feature.feature_type, 0.5)
            
            # Calculate final weight
            final_weight = base_weight * (0.7 + frequency_factor * 0.3) * type_factor
            
            return min(final_weight, 1.0)
            
        except Exception as e:
            self.logger.error(f"Feature weight calculation failed: {e}")
            return 0.5
    
    def _create_feature_vector(self, features: List[BehaviorFeature]) -> List[float]:
        """Create numerical feature vector from features"""
        try:
            if not features:
                return []
            
            # Group features by type
            feature_groups = defaultdict(list)
            for feature in features:
                feature_groups[feature.feature_type].append(feature)
            
            # Create vector components
            vector = []
            
            # Process features (20 dimensions)
            process_features = feature_groups.get('process', [])
            process_vector = self._create_type_vector(process_features, 20)
            vector.extend(process_vector)
            
            # Network features (15 dimensions)
            network_features = feature_groups.get('network', [])
            network_vector = self._create_type_vector(network_features, 15)
            vector.extend(network_vector)
            
            # File features (15 dimensions)
            file_features = feature_groups.get('file', [])
            file_vector = self._create_type_vector(file_features, 15)
            vector.extend(file_vector)
            
            # Registry features (10 dimensions)
            registry_features = feature_groups.get('registry', [])
            registry_vector = self._create_type_vector(registry_features, 10)
            vector.extend(registry_vector)
            
            return vector
            
        except Exception as e:
            self.logger.error(f"Feature vector creation failed: {e}")
            return []
    
    def _create_type_vector(self, features: List[BehaviorFeature], dimensions: int) -> List[float]:
        """Create vector for specific feature type"""
        try:
            vector = [0.0] * dimensions
            
            if not features:
                return vector
            
            # Calculate feature statistics
            weights = [f.weight for f in features]
            frequencies = [f.frequency for f in features]
            
            # Fill vector with aggregated statistics
            if len(weights) > 0:
                vector[0] = np.mean(weights)  # Average weight
                vector[1] = np.max(weights)   # Max weight
                vector[2] = np.std(weights) if len(weights) > 1 else 0.0  # Weight std
                
            if len(frequencies) > 0:
                vector[3] = np.mean(frequencies)  # Average frequency
                vector[4] = np.max(frequencies)   # Max frequency
                vector[5] = len(features)         # Feature count
            
            # Fill remaining dimensions with feature-specific values
            for i, feature in enumerate(features[:dimensions-6]):
                vector[6+i] = feature.weight * (feature.frequency / 10.0)
            
            return vector
            
        except Exception as e:
            self.logger.error(f"Type vector creation failed: {e}")
            return [0.0] * dimensions
    
    def _calculate_signature_confidence(self, behavior_patterns: List[Dict[str, Any]], 
                                      features: List[BehaviorFeature]) -> float:
        """Calculate confidence score for signature"""
        try:
            if not features:
                return 0.0
            
            # Base confidence from feature weights
            feature_weights = [f.weight for f in features]
            base_confidence = np.mean(feature_weights)
            
            # Pattern diversity factor
            pattern_types = set(p.get('type', 'unknown') for p in behavior_patterns)
            diversity_factor = min(len(pattern_types) / 4.0, 1.0)
            
            # Feature count factor
            count_factor = min(len(features) / 20.0, 1.0)
            
            # Combine factors
            confidence = (base_confidence * 0.6 + diversity_factor * 0.2 + count_factor * 0.2)
            
            return min(confidence, 1.0)
            
        except Exception as e:
            self.logger.error(f"Confidence calculation failed: {e}")
            return 0.5
    
    def _determine_severity_level(self, behavior_patterns: List[Dict[str, Any]], 
                                confidence_score: float) -> str:
        """Determine severity level based on patterns and confidence"""
        try:
            # Count high-risk indicators
            high_risk_indicators = [
                'process_injection', 'privilege_escalation', 'anti_analysis',
                'code_injection', 'system_compromise', 'data_exfiltration'
            ]
            
            risk_count = 0
            for pattern in behavior_patterns:
                indicators = pattern.get('indicators', [])
                for indicator in indicators:
                    if any(risk in str(indicator).lower() for risk in high_risk_indicators):
                        risk_count += 1
            
            # Determine severity
            if confidence_score >= 0.9 and risk_count >= 3:
                return 'critical'
            elif confidence_score >= 0.8 and risk_count >= 2:
                return 'high'
            elif confidence_score >= 0.6 and risk_count >= 1:
                return 'medium'
            else:
                return 'low'
                
        except Exception as e:
            self.logger.error(f"Severity determination failed: {e}")
            return 'medium'
    
    def _generate_detection_rules(self, features: List[BehaviorFeature], 
                                behavior_patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detection rules from features and patterns"""
        try:
            rules = {
                'feature_rules': [],
                'pattern_rules': [],
                'threshold_rules': {},
                'logical_operators': 'AND'
            }
            
            # Feature-based rules
            for feature in features:
                if feature.weight >= 0.7:
                    rule = {
                        'type': 'feature_match',
                        'feature_name': feature.feature_name,
                        'feature_type': feature.feature_type,
                        'weight': feature.weight,
                        'required': feature.weight >= 0.9
                    }
                    rules['feature_rules'].append(rule)
            
            # Pattern-based rules
            for pattern in behavior_patterns:
                pattern_type = pattern.get('type', 'unknown')
                indicators = pattern.get('indicators', [])
                
                if indicators:
                    rule = {
                        'type': 'pattern_match',
                        'pattern_type': pattern_type,
                        'indicators': indicators,
                        'min_matches': max(1, len(indicators) // 2)
                    }
                    rules['pattern_rules'].append(rule)
            
            # Threshold rules
            rules['threshold_rules'] = {
                'min_feature_matches': max(1, len(rules['feature_rules']) // 2),
                'min_pattern_matches': max(1, len(rules['pattern_rules']) // 2),
                'confidence_threshold': 0.7
            }
            
            return rules
            
        except Exception as e:
            self.logger.error(f"Detection rule generation failed: {e}")
            return {}
    
    def save_signature(self, signature: BehavioralSignature):
        """Save behavioral signature to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO behavioral_signatures 
                    (signature_id, signature_name, behavior_patterns, feature_vector,
                     confidence_score, severity_level, threat_family, detection_rules,
                     created_at, last_updated, usage_count, false_positive_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    signature.signature_id,
                    signature.signature_name,
                    json.dumps(signature.behavior_patterns),
                    json.dumps(signature.feature_vector),
                    signature.confidence_score,
                    signature.severity_level,
                    signature.threat_family,
                    json.dumps(signature.detection_rules),
                    signature.created_at.isoformat(),
                    signature.last_updated.isoformat(),
                    signature.usage_count,
                    signature.false_positive_rate
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save signature: {e}")
    
    def match_signature(self, behavior_data: Dict[str, Any]) -> Optional[Tuple[BehavioralSignature, float]]:
        """Match behavior data against existing signatures"""
        try:
            best_match = None
            best_score = 0.0
            
            # Extract features from behavior data
            features = self._extract_features_from_patterns([behavior_data])
            
            if not features:
                return None
            
            # Create feature vector
            feature_vector = self._create_feature_vector(features)
            
            # Compare against all signatures
            for signature in self.signatures.values():
                match_score = self._calculate_match_score(feature_vector, signature)
                
                if match_score > best_score and match_score >= 0.7:
                    best_score = match_score
                    best_match = signature
            
            return (best_match, best_score) if best_match else None
            
        except Exception as e:
            self.logger.error(f"Signature matching failed: {e}")
            return None
    
    def _calculate_match_score(self, feature_vector: List[float], 
                             signature: BehavioralSignature) -> float:
        """Calculate match score between feature vector and signature"""
        try:
            if not feature_vector or not signature.feature_vector:
                return 0.0
            
            # Ensure vectors have same length
            min_len = min(len(feature_vector), len(signature.feature_vector))
            vec1 = np.array(feature_vector[:min_len])
            vec2 = np.array(signature.feature_vector[:min_len])
            
            # Calculate cosine similarity
            dot_product = np.dot(vec1, vec2)
            norm1 = np.linalg.norm(vec1)
            norm2 = np.linalg.norm(vec2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            similarity = dot_product / (norm1 * norm2)
            
            # Apply confidence weighting
            weighted_score = similarity * signature.confidence_score
            
            return max(0.0, min(1.0, weighted_score))
            
        except Exception as e:
            self.logger.error(f"Match score calculation failed: {e}")
            return 0.0
    
    def get_signature_statistics(self) -> Dict[str, Any]:
        """Get signature generation statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total signatures
                cursor.execute('SELECT COUNT(*) FROM behavioral_signatures')
                total_signatures = cursor.fetchone()[0]
                
                # Signatures by threat family
                cursor.execute('''
                    SELECT threat_family, COUNT(*) FROM behavioral_signatures 
                    GROUP BY threat_family
                ''')
                family_stats = dict(cursor.fetchall())
                
                # Signatures by severity
                cursor.execute('''
                    SELECT severity_level, COUNT(*) FROM behavioral_signatures 
                    GROUP BY severity_level
                ''')
                severity_stats = dict(cursor.fetchall())
                
                # Average confidence
                cursor.execute('SELECT AVG(confidence_score) FROM behavioral_signatures')
                avg_confidence = cursor.fetchone()[0] or 0.0
                
                return {
                    'total_signatures': total_signatures,
                    'family_statistics': family_stats,
                    'severity_statistics': severity_stats,
                    'average_confidence': avg_confidence,
                    'loaded_signatures': len(self.signatures)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get signature statistics: {e}")
            return {}
