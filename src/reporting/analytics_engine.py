#!/usr/bin/env python3
"""
Enterprise Analytics Engine
Comprehensive analytics and reporting system for AI Antivirus
"""

import os
import sys
import json
import time
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics
from dataclasses import dataclass

try:
    import numpy as np
    import pandas as pd
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import StandardScaler
    ADVANCED_ANALYTICS_AVAILABLE = True
except ImportError:
    ADVANCED_ANALYTICS_AVAILABLE = False
    np = None
    pd = None

@dataclass
class AnalyticsMetric:
    """Analytics metric data structure"""
    metric_id: str
    name: str
    value: float
    timestamp: float
    category: str
    subcategory: str
    metadata: Dict[str, Any]

@dataclass
class TrendAnalysis:
    """Trend analysis result"""
    metric_name: str
    trend_direction: str
    trend_strength: float
    forecast_values: List[float]
    confidence_interval: Tuple[float, float]
    r_squared: float
    period_days: int

class AnalyticsEngine:
    """Enterprise Analytics Engine for comprehensive reporting"""
    
    def __init__(self, db_path: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.reporting.analytics_engine')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), "..", "..", "models", "analytics.db")
        
        # Initialize database
        self.init_database()
        
        # Analytics settings
        self.collection_interval = 300  # 5 minutes
        self.retention_days = 365  # 1 year
        
        # Data collection thread
        self.collection_running = False
        self.collection_thread = None
        
        # Cached analytics
        self.cached_metrics = {}
        self.cache_expiry = {}
        
        self.logger.info("Analytics Engine initialized")
    
    def init_database(self):
        """Initialize analytics database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_id TEXT,
                        name TEXT,
                        value REAL,
                        timestamp REAL,
                        category TEXT,
                        subcategory TEXT,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # KPI definitions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kpi_definitions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kpi_id TEXT UNIQUE,
                        name TEXT,
                        description TEXT,
                        calculation_method TEXT,
                        target_value REAL,
                        warning_threshold REAL,
                        critical_threshold REAL,
                        unit TEXT,
                        category TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_id TEXT UNIQUE,
                        report_type TEXT,
                        title TEXT,
                        content TEXT,
                        format TEXT,
                        generated_at REAL,
                        period_start REAL,
                        period_end REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_category ON metrics(category)')
                
                conn.commit()
                
            # Initialize default KPIs
            self.init_default_kpis()
            
            self.logger.info("Analytics database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize analytics database: {e}")
            raise
    
    def init_default_kpis(self):
        """Initialize default KPI definitions"""
        default_kpis = [
            {
                'kpi_id': 'threat_detection_rate',
                'name': 'Threat Detection Rate',
                'description': 'Percentage of threats detected vs total threats',
                'calculation_method': 'threats_detected / total_threats * 100',
                'target_value': 99.0,
                'warning_threshold': 95.0,
                'critical_threshold': 90.0,
                'unit': '%',
                'category': 'Security'
            },
            {
                'kpi_id': 'false_positive_rate',
                'name': 'False Positive Rate',
                'description': 'Percentage of false positives in detections',
                'calculation_method': 'false_positives / total_detections * 100',
                'target_value': 1.0,
                'warning_threshold': 3.0,
                'critical_threshold': 5.0,
                'unit': '%',
                'category': 'Quality'
            },
            {
                'kpi_id': 'system_uptime',
                'name': 'System Uptime',
                'description': 'Percentage of time system is operational',
                'calculation_method': 'uptime_hours / total_hours * 100',
                'target_value': 99.9,
                'warning_threshold': 99.0,
                'critical_threshold': 95.0,
                'unit': '%',
                'category': 'Performance'
            },
            {
                'kpi_id': 'scan_completion_time',
                'name': 'Average Scan Completion Time',
                'description': 'Average time to complete system scans',
                'calculation_method': 'sum(scan_times) / count(scans)',
                'target_value': 300.0,
                'warning_threshold': 600.0,
                'critical_threshold': 900.0,
                'unit': 'seconds',
                'category': 'Performance'
            }
        ]
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for kpi in default_kpis:
                    cursor.execute('''
                        INSERT OR REPLACE INTO kpi_definitions 
                        (kpi_id, name, description, calculation_method, target_value,
                         warning_threshold, critical_threshold, unit, category)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        kpi['kpi_id'], kpi['name'], kpi['description'],
                        kpi['calculation_method'], kpi['target_value'],
                        kpi['warning_threshold'], kpi['critical_threshold'],
                        kpi['unit'], kpi['category']
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize default KPIs: {e}")
    
    def start_collection(self):
        """Start automatic metrics collection"""
        if self.collection_running:
            self.logger.warning("Metrics collection already running")
            return
        
        self.collection_running = True
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            daemon=True
        )
        self.collection_thread.start()
        
        self.logger.info("Started automatic metrics collection")
    
    def stop_collection(self):
        """Stop automatic metrics collection"""
        self.collection_running = False
        
        if self.collection_thread and self.collection_thread.is_alive():
            self.collection_thread.join(timeout=5)
        
        self.logger.info("Stopped automatic metrics collection")
    
    def _collection_loop(self):
        """Main metrics collection loop"""
        while self.collection_running:
            try:
                self.collect_system_metrics()
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                time.sleep(60)
    
    def collect_system_metrics(self):
        """Collect system-wide metrics"""
        try:
            current_time = time.time()
            
            # Collect performance metrics
            self.collect_performance_metrics(current_time)
            
            # Collect security metrics
            self.collect_security_metrics(current_time)
            
            # Clean up old metrics
            self.cleanup_old_metrics()
            
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
    
    def collect_performance_metrics(self, timestamp: float):
        """Collect performance metrics"""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.record_metric(AnalyticsMetric(
                metric_id="cpu_usage",
                name="CPU Usage",
                value=cpu_percent,
                timestamp=timestamp,
                category="Performance",
                subcategory="System",
                metadata={"unit": "percent"}
            ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            self.record_metric(AnalyticsMetric(
                metric_id="memory_usage",
                name="Memory Usage",
                value=memory_percent,
                timestamp=timestamp,
                category="Performance",
                subcategory="System",
                metadata={"unit": "percent"}
            ))
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance metrics: {e}")
    
    def collect_security_metrics(self, timestamp: float):
        """Collect security metrics"""
        try:
            # Simulate threat detection metrics
            import random
            
            threats_detected = random.randint(0, 5)
            self.record_metric(AnalyticsMetric(
                metric_id="threats_per_hour",
                name="Threats Per Hour",
                value=threats_detected,
                timestamp=timestamp,
                category="Security",
                subcategory="Threats",
                metadata={"period": "1_hour"}
            ))
            
        except Exception as e:
            self.logger.error(f"Failed to collect security metrics: {e}")
    
    def record_metric(self, metric: AnalyticsMetric):
        """Record a metric in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO metrics 
                    (metric_id, name, value, timestamp, category, subcategory, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metric.metric_id, metric.name, metric.value, metric.timestamp,
                    metric.category, metric.subcategory, json.dumps(metric.metadata)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to record metric: {e}")
    
    def cleanup_old_metrics(self):
        """Clean up old metrics beyond retention period"""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 3600)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM metrics WHERE timestamp < ?
                ''', (cutoff_time,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned up {deleted_count} old metrics")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old metrics: {e}")
    
    def calculate_kpi(self, kpi_id: str, period_hours: int = 24) -> Dict[str, Any]:
        """Calculate KPI value for specified period"""
        try:
            # Get KPI definition
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT name, calculation_method, target_value, warning_threshold,
                           critical_threshold, unit, category
                    FROM kpi_definitions WHERE kpi_id = ?
                ''', (kpi_id,))
                
                kpi_def = cursor.fetchone()
                if not kpi_def:
                    return None
                
                name, calc_method, target, warning, critical, unit, category = kpi_def
                
                # Calculate KPI value
                current_value = self.execute_kpi_calculation(kpi_id, period_hours)
                
                # Determine status
                if current_value is None:
                    status = "unknown"
                elif kpi_id in ['false_positive_rate', 'scan_completion_time']:
                    # Lower is better
                    if current_value <= target:
                        status = "good"
                    elif current_value <= warning:
                        status = "warning"
                    else:
                        status = "critical"
                else:
                    # Higher is better
                    if current_value >= target:
                        status = "good"
                    elif current_value >= warning:
                        status = "warning"
                    else:
                        status = "critical"
                
                return {
                    'kpi_id': kpi_id,
                    'name': name,
                    'current_value': current_value,
                    'target_value': target,
                    'warning_threshold': warning,
                    'critical_threshold': critical,
                    'unit': unit,
                    'category': category,
                    'status': status,
                    'period_hours': period_hours
                }
                
        except Exception as e:
            self.logger.error(f"Failed to calculate KPI {kpi_id}: {e}")
            return None
    
    def execute_kpi_calculation(self, kpi_id: str, period_hours: int) -> Optional[float]:
        """Execute KPI calculation"""
        try:
            cutoff_time = time.time() - (period_hours * 3600)
            
            if kpi_id == "threat_detection_rate":
                return 98.5  # Simulated value
            elif kpi_id == "false_positive_rate":
                return 2.0  # Simulated value
            elif kpi_id == "system_uptime":
                return 99.5  # Simulated value
            elif kpi_id == "scan_completion_time":
                return 300.0  # Simulated value
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to execute KPI calculation: {e}")
            return None
    
    def get_all_kpis(self, period_hours: int = 24) -> List[Dict[str, Any]]:
        """Get all KPI values"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT kpi_id FROM kpi_definitions')
                kpi_ids = [row[0] for row in cursor.fetchall()]
                
                kpis = []
                for kpi_id in kpi_ids:
                    kpi_data = self.calculate_kpi(kpi_id, period_hours)
                    if kpi_data:
                        kpis.append(kpi_data)
                
                return kpis
                
        except Exception as e:
            self.logger.error(f"Failed to get all KPIs: {e}")
            return []
    
    def get_metrics_by_category(self, category: str, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Get metrics by category"""
        try:
            cutoff_time = time.time() - (hours_back * 3600)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT metric_id, name, value, timestamp, subcategory, metadata
                    FROM metrics 
                    WHERE category = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (category, cutoff_time))
                
                metrics = []
                for row in cursor.fetchall():
                    metric_id, name, value, timestamp, subcategory, metadata_str = row
                    
                    try:
                        metadata = json.loads(metadata_str) if metadata_str else {}
                    except:
                        metadata = {}
                    
                    metrics.append({
                        'metric_id': metric_id,
                        'name': name,
                        'value': value,
                        'timestamp': timestamp,
                        'subcategory': subcategory,
                        'metadata': metadata
                    })
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to get metrics by category: {e}")
            return []
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get comprehensive analytics summary"""
        try:
            # Get KPIs
            kpis = self.get_all_kpis(24)
            
            # Get recent metrics by category
            security_metrics = self.get_metrics_by_category("Security", 24)
            performance_metrics = self.get_metrics_by_category("Performance", 24)
            
            return {
                'kpis': kpis,
                'security_metrics': security_metrics,
                'performance_metrics': performance_metrics,
                'generated_at': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get analytics summary: {e}")
            return {}
    
    def generate_trend_analysis(self, metric_id: str, days_back: int = 30) -> Optional[TrendAnalysis]:
        """Generate trend analysis for a metric"""
        try:
            if not ADVANCED_ANALYTICS_AVAILABLE:
                self.logger.warning("Advanced analytics not available - install numpy, pandas, scikit-learn")
                return None
            
            cutoff_time = time.time() - (days_back * 24 * 3600)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT value, timestamp FROM metrics 
                    WHERE metric_id = ? AND timestamp >= ?
                    ORDER BY timestamp
                ''', (metric_id, cutoff_time))
                
                data = cursor.fetchall()
                
                if len(data) < 5:  # Need minimum data points
                    return None
                
                values = [row[0] for row in data]
                timestamps = [row[1] for row in data]
                
                # Convert to numpy arrays
                X = np.array(timestamps).reshape(-1, 1)
                y = np.array(values)
                
                # Fit linear regression
                model = LinearRegression()
                model.fit(X, y)
                
                # Calculate trend metrics
                slope = model.coef_[0]
                r_squared = model.score(X, y)
                
                # Determine trend direction
                if abs(slope) < 0.001:
                    trend_direction = "stable"
                elif slope > 0:
                    trend_direction = "increasing"
                else:
                    trend_direction = "decreasing"
                
                # Calculate trend strength
                trend_strength = min(abs(slope) * 1000, 1.0)
                
                # Generate forecast
                future_timestamps = np.array([timestamps[-1] + i * 3600 for i in range(1, 25)]).reshape(-1, 1)
                forecast_values = model.predict(future_timestamps).tolist()
                
                # Calculate confidence interval (simplified)
                std_error = np.std(y - model.predict(X))
                confidence_interval = (
                    forecast_values[-1] - 2 * std_error,
                    forecast_values[-1] + 2 * std_error
                )
                
                return TrendAnalysis(
                    metric_name=metric_id,
                    trend_direction=trend_direction,
                    trend_strength=trend_strength,
                    forecast_values=forecast_values,
                    confidence_interval=confidence_interval,
                    r_squared=r_squared,
                    period_days=days_back
                )
                
        except Exception as e:
            self.logger.error(f"Failed to generate trend analysis: {e}")
            return None
    
    def get_current_kpis(self) -> Dict[str, Any]:
        """Get current KPI values for dashboard display"""
        try:
            kpis = {}
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get latest KPI values - create table if not exists
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS kpis (
                        kpi_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        current_value REAL DEFAULT 0,
                        target_value REAL DEFAULT 0,
                        status TEXT DEFAULT 'unknown',
                        last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    SELECT kpi_id, name, current_value, target_value, status, last_updated
                    FROM kpis 
                    ORDER BY last_updated DESC
                """)
                
                for row in cursor.fetchall():
                    kpi_id, name, current_value, target_value, status, last_updated = row
                    kpis[kpi_id] = {
                        'name': name,
                        'current_value': current_value,
                        'target_value': target_value,
                        'status': status,
                        'last_updated': last_updated
                    }
                
                return kpis
                
        except Exception as e:
            self.logger.error(f"Failed to get current KPIs: {e}")
            return {}
    
    def get_recent_metrics(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent metrics for dashboard display"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT metric_id, name, value, timestamp, category, subcategory, metadata
                    FROM metrics 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                metrics = []
                for row in cursor.fetchall():
                    metric_id, name, value, timestamp, category, subcategory, metadata_json = row
                    try:
                        metadata = json.loads(metadata_json) if metadata_json else {}
                    except json.JSONDecodeError:
                        metadata = {}
                    
                    metrics.append({
                        'metric_id': metric_id,
                        'name': name,
                        'value': value,
                        'timestamp': timestamp,
                        'category': category,
                        'subcategory': subcategory,
                        'metadata': metadata,
                        'formatted_time': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    })
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to get recent metrics: {e}")
            return []
