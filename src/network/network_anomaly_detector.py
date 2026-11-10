#!/usr/bin/env python3
"""
Network Anomaly Detection System
Advanced ML-based network traffic anomaly detection
"""

import os
import sys
import json
import time
import logging
import sqlite3
import threading
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
import pickle

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")

@dataclass
class NetworkAnomaly:
    """Network anomaly detection result"""
    anomaly_id: str
    timestamp: float
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    affected_ips: List[str]
    metrics: Dict[str, float]
    evidence: Dict[str, Any]

@dataclass
class TrafficMetrics:
    """Network traffic metrics for analysis"""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    packet_count: int
    byte_count: int
    connection_duration: float
    packet_rate: float
    byte_rate: float
    port_diversity: int
    unique_destinations: int

class NetworkAnomalyDetector:
    """ML-based network anomaly detection system"""
    
    def __init__(self, db_path: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.network.network_anomaly_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), "..", "..", "models", "network_anomaly.db")
        
        # Initialize database
        self.init_database()
        
        # ML models
        self.isolation_forest = None
        self.dbscan_model = None
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=10)
        
        # Detection settings
        self.anomaly_threshold = 0.1  # Isolation Forest threshold
        self.min_samples_dbscan = 5
        self.eps_dbscan = 0.5
        self.analysis_window = 300  # 5 minutes
        
        # Traffic analysis
        self.traffic_buffer = deque(maxlen=10000)
        self.baseline_metrics = {}
        self.anomaly_callbacks = []
        
        # Analysis thread
        self.analysis_running = False
        self.analysis_thread = None
        
        # Feature extraction settings
        self.feature_window = 60  # 1 minute windows
        self.min_connections = 5  # Minimum connections for analysis
        
        # Initialize ML models
        if SKLEARN_AVAILABLE:
            self.init_ml_models()
        
        self.logger.info("Network Anomaly Detector initialized")
    
    def init_database(self):
        """Initialize SQLite database for anomaly detection"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Network anomalies table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS network_anomalies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        anomaly_id TEXT UNIQUE,
                        timestamp REAL,
                        anomaly_type TEXT,
                        severity TEXT,
                        confidence REAL,
                        description TEXT,
                        affected_ips TEXT,
                        metrics TEXT,
                        evidence TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Traffic metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS traffic_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT,
                        packet_count INTEGER,
                        byte_count INTEGER,
                        connection_duration REAL,
                        packet_rate REAL,
                        byte_rate REAL,
                        port_diversity INTEGER,
                        unique_destinations INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Baseline metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS baseline_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT,
                        mean_value REAL,
                        std_value REAL,
                        min_value REAL,
                        max_value REAL,
                        sample_count INTEGER,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON network_anomalies(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON traffic_metrics(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_src_ip ON traffic_metrics(src_ip)')
                
                conn.commit()
                
            self.logger.info("Network anomaly detection database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def init_ml_models(self):
        """Initialize machine learning models"""
        try:
            # Isolation Forest for outlier detection
            self.isolation_forest = IsolationForest(
                contamination=self.anomaly_threshold,
                random_state=42,
                n_estimators=100
            )
            
            # DBSCAN for clustering analysis
            self.dbscan_model = DBSCAN(
                eps=self.eps_dbscan,
                min_samples=self.min_samples_dbscan
            )
            
            # Load existing models if available
            self.load_models()
            
            self.logger.info("ML models initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
    
    def start_analysis(self):
        """Start continuous anomaly analysis"""
        if self.analysis_running:
            self.logger.warning("Anomaly analysis already running")
            return
        
        self.analysis_running = True
        self.analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        self.analysis_thread.start()
        
        self.logger.info("Started network anomaly analysis")
    
    def stop_analysis(self):
        """Stop anomaly analysis"""
        self.analysis_running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        self.logger.info("Stopped network anomaly analysis")
    
    def _analysis_loop(self):
        """Main analysis loop"""
        while self.analysis_running:
            try:
                self.analyze_traffic_window()
                time.sleep(30)  # Analyze every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Analysis loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def add_traffic_data(self, packet_info):
        """Add traffic data for analysis"""
        try:
            # Convert packet info to traffic metrics
            metrics = self.extract_traffic_metrics(packet_info)
            if metrics:
                self.traffic_buffer.append(metrics)
                
                # Store metrics in database (sample)
                if len(self.traffic_buffer) % 100 == 0:
                    self.store_traffic_metrics(metrics)
            
        except Exception as e:
            self.logger.error(f"Failed to add traffic data: {e}")
    
    def extract_traffic_metrics(self, packet_info) -> Optional[TrafficMetrics]:
        """Extract traffic metrics from packet information"""
        try:
            # Group recent packets by connection
            current_time = time.time()
            window_start = current_time - self.feature_window
            
            # Find related packets in the window
            related_packets = [
                p for p in self.traffic_buffer
                if (p.timestamp >= window_start and
                    ((p.src_ip == packet_info.src_ip and p.dst_ip == packet_info.dst_ip) or
                     (p.src_ip == packet_info.dst_ip and p.dst_ip == packet_info.src_ip)))
            ]
            
            if len(related_packets) < 2:
                return None
            
            # Calculate metrics
            packet_count = len(related_packets) + 1
            byte_count = sum(getattr(p, 'byte_count', packet_info.size) for p in related_packets) + packet_info.size
            
            duration = current_time - min(p.timestamp for p in related_packets)
            packet_rate = packet_count / max(duration, 1)
            byte_rate = byte_count / max(duration, 1)
            
            # Port diversity
            ports = set()
            for p in related_packets:
                if hasattr(p, 'src_port'):
                    ports.add(p.src_port)
                if hasattr(p, 'dst_port'):
                    ports.add(p.dst_port)
            ports.add(getattr(packet_info, 'src_port', 0))
            ports.add(getattr(packet_info, 'dst_port', 0))
            port_diversity = len(ports)
            
            # Unique destinations
            destinations = set(p.dst_ip for p in related_packets)
            destinations.add(packet_info.dst_ip)
            unique_destinations = len(destinations)
            
            return TrafficMetrics(
                timestamp=current_time,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                protocol=packet_info.protocol,
                packet_count=packet_count,
                byte_count=byte_count,
                connection_duration=duration,
                packet_rate=packet_rate,
                byte_rate=byte_rate,
                port_diversity=port_diversity,
                unique_destinations=unique_destinations
            )
            
        except Exception as e:
            self.logger.error(f"Failed to extract traffic metrics: {e}")
            return None
    
    def analyze_traffic_window(self):
        """Analyze current traffic window for anomalies"""
        if not SKLEARN_AVAILABLE or len(self.traffic_buffer) < self.min_connections:
            return
        
        try:
            # Extract features from traffic buffer
            features = self.extract_features_from_buffer()
            if len(features) < self.min_connections:
                return
            
            # Normalize features
            features_scaled = self.scaler.fit_transform(features)
            
            # Apply PCA for dimensionality reduction
            if features_scaled.shape[1] > 10:
                features_pca = self.pca.fit_transform(features_scaled)
            else:
                features_pca = features_scaled
            
            # Detect anomalies using Isolation Forest
            isolation_anomalies = self.detect_isolation_anomalies(features_pca)
            
            # Detect anomalies using clustering
            clustering_anomalies = self.detect_clustering_anomalies(features_pca)
            
            # Detect statistical anomalies
            statistical_anomalies = self.detect_statistical_anomalies()
            
            # Combine and process all anomalies
            all_anomalies = isolation_anomalies + clustering_anomalies + statistical_anomalies
            
            for anomaly in all_anomalies:
                self.handle_anomaly_detection(anomaly)
            
        except Exception as e:
            self.logger.error(f"Failed to analyze traffic window: {e}")
    
    def extract_features_from_buffer(self) -> np.ndarray:
        """Extract feature matrix from traffic buffer"""
        try:
            features = []
            current_time = time.time()
            window_start = current_time - self.analysis_window
            
            # Group by source IP
            ip_groups = defaultdict(list)
            for metrics in self.traffic_buffer:
                if metrics.timestamp >= window_start:
                    ip_groups[metrics.src_ip].append(metrics)
            
            for src_ip, ip_metrics in ip_groups.items():
                if len(ip_metrics) >= 3:  # Minimum samples per IP
                    # Aggregate metrics for this IP
                    feature_vector = [
                        len(ip_metrics),  # Connection count
                        sum(m.packet_count for m in ip_metrics),  # Total packets
                        sum(m.byte_count for m in ip_metrics),  # Total bytes
                        np.mean([m.packet_rate for m in ip_metrics]),  # Avg packet rate
                        np.mean([m.byte_rate for m in ip_metrics]),  # Avg byte rate
                        np.mean([m.connection_duration for m in ip_metrics]),  # Avg duration
                        np.mean([m.port_diversity for m in ip_metrics]),  # Avg port diversity
                        np.mean([m.unique_destinations for m in ip_metrics]),  # Avg unique destinations
                        len(set(m.dst_ip for m in ip_metrics)),  # Total unique destinations
                        len(set(m.protocol for m in ip_metrics)),  # Protocol diversity
                    ]
                    features.append(feature_vector)
            
            return np.array(features) if features else np.array([]).reshape(0, 10)
            
        except Exception as e:
            self.logger.error(f"Failed to extract features: {e}")
            return np.array([]).reshape(0, 10)
    
    def detect_isolation_anomalies(self, features: np.ndarray) -> List[NetworkAnomaly]:
        """Detect anomalies using Isolation Forest"""
        anomalies = []
        
        try:
            if len(features) < 10:  # Need minimum samples
                return anomalies
            
            # Fit and predict
            outliers = self.isolation_forest.fit_predict(features)
            scores = self.isolation_forest.score_samples(features)
            
            # Find anomalous samples
            for i, (outlier, score) in enumerate(zip(outliers, scores)):
                if outlier == -1:  # Anomaly detected
                    confidence = abs(score)
                    
                    anomaly = NetworkAnomaly(
                        anomaly_id=f"isolation_{int(time.time())}_{i}",
                        timestamp=time.time(),
                        anomaly_type="traffic_outlier",
                        severity="medium" if confidence > 0.1 else "low",
                        confidence=min(confidence * 2, 1.0),
                        description=f"Traffic pattern outlier detected (score: {score:.3f})",
                        affected_ips=[],  # Would need to map back to IPs
                        metrics={"isolation_score": score, "feature_index": i},
                        evidence={"model": "isolation_forest", "feature_vector": features[i].tolist()}
                    )
                    anomalies.append(anomaly)
            
        except Exception as e:
            self.logger.error(f"Isolation Forest detection error: {e}")
        
        return anomalies
    
    def detect_clustering_anomalies(self, features: np.ndarray) -> List[NetworkAnomaly]:
        """Detect anomalies using clustering analysis"""
        anomalies = []
        
        try:
            if len(features) < self.min_samples_dbscan:
                return anomalies
            
            # Perform clustering
            cluster_labels = self.dbscan_model.fit_predict(features)
            
            # Find outliers (label -1)
            outlier_indices = np.where(cluster_labels == -1)[0]
            
            for idx in outlier_indices:
                anomaly = NetworkAnomaly(
                    anomaly_id=f"cluster_{int(time.time())}_{idx}",
                    timestamp=time.time(),
                    anomaly_type="clustering_outlier",
                    severity="medium",
                    confidence=0.7,
                    description="Traffic pattern does not fit any cluster",
                    affected_ips=[],
                    metrics={"cluster_label": -1, "feature_index": int(idx)},
                    evidence={"model": "dbscan", "feature_vector": features[idx].tolist()}
                )
                anomalies.append(anomaly)
            
            # Analyze cluster sizes for suspicious patterns
            unique_labels = set(cluster_labels)
            for label in unique_labels:
                if label != -1:  # Skip outliers
                    cluster_size = np.sum(cluster_labels == label)
                    if cluster_size == 1:  # Singleton clusters might be suspicious
                        singleton_idx = np.where(cluster_labels == label)[0][0]
                        
                        anomaly = NetworkAnomaly(
                            anomaly_id=f"singleton_{int(time.time())}_{singleton_idx}",
                            timestamp=time.time(),
                            anomaly_type="singleton_cluster",
                            severity="low",
                            confidence=0.5,
                            description="Isolated traffic pattern (singleton cluster)",
                            affected_ips=[],
                            metrics={"cluster_label": int(label), "cluster_size": 1},
                            evidence={"model": "dbscan", "feature_vector": features[singleton_idx].tolist()}
                        )
                        anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Clustering detection error: {e}")
        
        return anomalies
    
    def detect_statistical_anomalies(self) -> List[NetworkAnomaly]:
        """Detect statistical anomalies in traffic patterns"""
        anomalies = []
        
        try:
            current_time = time.time()
            window_start = current_time - self.analysis_window
            
            # Analyze recent traffic
            recent_traffic = [m for m in self.traffic_buffer if m.timestamp >= window_start]
            
            if len(recent_traffic) < 10:
                return anomalies
            
            # Calculate current statistics
            current_stats = {
                'packet_rate': np.mean([m.packet_rate for m in recent_traffic]),
                'byte_rate': np.mean([m.byte_rate for m in recent_traffic]),
                'connection_duration': np.mean([m.connection_duration for m in recent_traffic]),
                'port_diversity': np.mean([m.port_diversity for m in recent_traffic]),
                'unique_destinations': np.mean([m.unique_destinations for m in recent_traffic])
            }
            
            # Compare with baseline
            for metric_name, current_value in current_stats.items():
                baseline = self.baseline_metrics.get(metric_name)
                if baseline:
                    # Calculate z-score
                    z_score = abs(current_value - baseline['mean']) / max(baseline['std'], 0.001)
                    
                    if z_score > 3:  # 3 sigma rule
                        severity = "high" if z_score > 5 else "medium"
                        
                        anomaly = NetworkAnomaly(
                            anomaly_id=f"statistical_{int(time.time())}_{metric_name}",
                            timestamp=time.time(),
                            anomaly_type="statistical_anomaly",
                            severity=severity,
                            confidence=min(z_score / 5, 1.0),
                            description=f"Statistical anomaly in {metric_name} (z-score: {z_score:.2f})",
                            affected_ips=[],
                            metrics={"z_score": z_score, "metric_name": metric_name, "current_value": current_value},
                            evidence={"baseline": baseline, "current_stats": current_stats}
                        )
                        anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Statistical detection error: {e}")
        
        return anomalies
    
    def handle_anomaly_detection(self, anomaly: NetworkAnomaly):
        """Handle detected network anomaly"""
        try:
            # Store anomaly in database
            self.store_anomaly(anomaly)
            
            # Log anomaly
            self.logger.warning(
                f"Network anomaly detected: {anomaly.anomaly_type} "
                f"(severity: {anomaly.severity}, confidence: {anomaly.confidence:.2f})"
            )
            
            # Notify callbacks
            for callback in self.anomaly_callbacks:
                try:
                    callback(anomaly)
                except Exception as e:
                    self.logger.error(f"Anomaly callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle anomaly detection: {e}")
    
    def store_anomaly(self, anomaly: NetworkAnomaly):
        """Store anomaly in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO network_anomalies 
                    (anomaly_id, timestamp, anomaly_type, severity, confidence, description, 
                     affected_ips, metrics, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    anomaly.anomaly_id, anomaly.timestamp, anomaly.anomaly_type,
                    anomaly.severity, anomaly.confidence, anomaly.description,
                    json.dumps(anomaly.affected_ips), json.dumps(anomaly.metrics),
                    json.dumps(anomaly.evidence)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store anomaly: {e}")
    
    def store_traffic_metrics(self, metrics: TrafficMetrics):
        """Store traffic metrics in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO traffic_metrics 
                    (timestamp, src_ip, dst_ip, protocol, packet_count, byte_count,
                     connection_duration, packet_rate, byte_rate, port_diversity, unique_destinations)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.timestamp, metrics.src_ip, metrics.dst_ip, metrics.protocol,
                    metrics.packet_count, metrics.byte_count, metrics.connection_duration,
                    metrics.packet_rate, metrics.byte_rate, metrics.port_diversity,
                    metrics.unique_destinations
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store traffic metrics: {e}")
    
    def update_baseline_metrics(self):
        """Update baseline metrics from historical data"""
        try:
            current_time = time.time()
            baseline_window = current_time - (7 * 24 * 3600)  # Last 7 days
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Calculate baseline statistics
                metrics_to_analyze = [
                    'packet_rate', 'byte_rate', 'connection_duration',
                    'port_diversity', 'unique_destinations'
                ]
                
                for metric in metrics_to_analyze:
                    cursor.execute(f'''
                        SELECT AVG({metric}), 
                               CASE WHEN COUNT(*) > 1 
                                    THEN SQRT(SUM(({metric} - avg_val) * ({metric} - avg_val)) / (COUNT(*) - 1))
                                    ELSE 0 
                               END as std_val,
                               MIN({metric}), MAX({metric}), COUNT(*)
                        FROM (
                            SELECT {metric}, AVG({metric}) OVER() as avg_val
                            FROM traffic_metrics 
                            WHERE timestamp >= ?
                        )
                    ''', (baseline_window,))
                    
                    result = cursor.fetchone()
                    if result and result[4] > 10:  # Minimum 10 samples
                        self.baseline_metrics[metric] = {
                            'mean': result[0] or 0,
                            'std': result[1] or 1,
                            'min': result[2] or 0,
                            'max': result[3] or 0,
                            'sample_count': result[4]
                        }
                
                self.logger.info(f"Updated baseline metrics for {len(self.baseline_metrics)} metrics")
                
        except Exception as e:
            self.logger.error(f"Failed to update baseline metrics: {e}")
    
    def save_models(self):
        """Save trained ML models"""
        try:
            models_dir = os.path.dirname(self.db_path)
            
            if self.isolation_forest:
                model_path = os.path.join(models_dir, "isolation_forest.pkl")
                with open(model_path, 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
            
            if hasattr(self.scaler, 'mean_'):
                scaler_path = os.path.join(models_dir, "network_scaler.pkl")
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
            
            self.logger.info("ML models saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
    
    def load_models(self):
        """Load trained ML models"""
        try:
            models_dir = os.path.dirname(self.db_path)
            
            model_path = os.path.join(models_dir, "isolation_forest.pkl")
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
            
            scaler_path = os.path.join(models_dir, "network_scaler.pkl")
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            self.logger.info("ML models loaded")
            
        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")
    
    def add_anomaly_callback(self, callback):
        """Add anomaly detection callback"""
        self.anomaly_callbacks.append(callback)
    
    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Recent anomalies count
                recent_time = time.time() - 3600  # Last hour
                cursor.execute('''
                    SELECT COUNT(*) FROM network_anomalies WHERE timestamp >= ?
                ''', (recent_time,))
                recent_anomalies = cursor.fetchone()[0]
                
                # Anomalies by type
                cursor.execute('''
                    SELECT anomaly_type, COUNT(*) 
                    FROM network_anomalies 
                    WHERE timestamp >= ? 
                    GROUP BY anomaly_type
                ''', (recent_time,))
                anomaly_types = dict(cursor.fetchall())
                
                # Anomalies by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM network_anomalies 
                    WHERE timestamp >= ? 
                    GROUP BY severity
                ''', (recent_time,))
                severity_counts = dict(cursor.fetchall())
                
                return {
                    'recent_anomalies': recent_anomalies,
                    'anomaly_types': anomaly_types,
                    'severity_counts': severity_counts,
                    'baseline_metrics_count': len(self.baseline_metrics),
                    'analysis_running': self.analysis_running,
                    'traffic_buffer_size': len(self.traffic_buffer)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def get_recent_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent network anomalies"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT anomaly_id, timestamp, anomaly_type, severity, confidence,
                           description, affected_ips, metrics, evidence
                    FROM network_anomalies 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                anomalies = []
                for row in cursor.fetchall():
                    anomaly_data = {
                        'anomaly_id': row[0],
                        'timestamp': row[1],
                        'anomaly_type': row[2],
                        'severity': row[3],
                        'confidence': row[4],
                        'description': row[5],
                        'affected_ips': json.loads(row[6]) if row[6] else [],
                        'metrics': json.loads(row[7]) if row[7] else {},
                        'evidence': json.loads(row[8]) if row[8] else {}
                    }
                    anomalies.append(anomaly_data)
                
                return anomalies
                
        except Exception as e:
            self.logger.error(f"Failed to get recent anomalies: {e}")
            return []
