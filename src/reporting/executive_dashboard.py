"""
Executive Dashboard System
Provides high-level security metrics, KPIs, and executive-level reporting for AI Antivirus.
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import os

@dataclass
class ExecutiveKPI:
    """Executive-level Key Performance Indicator"""
    name: str
    value: float
    unit: str
    trend: str  # 'up', 'down', 'stable'
    trend_percentage: float
    status: str  # 'good', 'warning', 'critical'
    description: str
    last_updated: str

@dataclass
class SecurityMetric:
    """Security metric for executive dashboard"""
    metric_name: str
    current_value: float
    previous_value: float
    target_value: float
    unit: str
    category: str  # 'threat_detection', 'performance', 'compliance'

@dataclass
class ThreatSummary:
    """High-level threat summary"""
    total_threats: int
    threats_blocked: int
    threats_quarantined: int
    false_positives: int
    detection_rate: float
    response_time_avg: float

@dataclass
class SystemHealth:
    """System health metrics"""
    uptime_percentage: float
    cpu_usage_avg: float
    memory_usage_avg: float
    scan_performance: float
    last_update: str
    system_status: str

class ExecutiveDashboard:
    """Executive Dashboard for AI Antivirus Enterprise Reporting"""
    
    def __init__(self, db_path: str = None):
        """Initialize Executive Dashboard"""
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.reporting.executive_dashboard')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Database setup
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'executive_dashboard.db')
        
        self.db_path = db_path
        self.init_database()
        
        # KPI thresholds and targets
        self.kpi_thresholds = {
            'threat_detection_rate': {'good': 95.0, 'warning': 90.0},
            'false_positive_rate': {'good': 2.0, 'warning': 5.0},
            'system_uptime': {'good': 99.0, 'warning': 95.0},
            'response_time': {'good': 5.0, 'warning': 10.0},
            'scan_performance': {'good': 1000.0, 'warning': 500.0}
        }
        
    def init_database(self):
        """Initialize executive dashboard database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Executive KPIs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS executive_kpis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        value REAL NOT NULL,
                        unit TEXT NOT NULL,
                        trend TEXT NOT NULL,
                        trend_percentage REAL NOT NULL,
                        status TEXT NOT NULL,
                        description TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Security metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS security_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        current_value REAL NOT NULL,
                        previous_value REAL NOT NULL,
                        target_value REAL NOT NULL,
                        unit TEXT NOT NULL,
                        category TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Threat summaries table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_summaries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        total_threats INTEGER NOT NULL,
                        threats_blocked INTEGER NOT NULL,
                        threats_quarantined INTEGER NOT NULL,
                        false_positives INTEGER NOT NULL,
                        detection_rate REAL NOT NULL,
                        response_time_avg REAL NOT NULL,
                        period_start DATETIME NOT NULL,
                        period_end DATETIME NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # System health table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_health (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        uptime_percentage REAL NOT NULL,
                        cpu_usage_avg REAL NOT NULL,
                        memory_usage_avg REAL NOT NULL,
                        scan_performance REAL NOT NULL,
                        system_status TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Executive reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS executive_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        report_type TEXT NOT NULL,
                        report_data TEXT NOT NULL,
                        period_start DATETIME NOT NULL,
                        period_end DATETIME NOT NULL,
                        generated_by TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                self.logger.info("Executive dashboard database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize executive dashboard database: {e}")
            raise
    
    def calculate_executive_kpis(self) -> List[ExecutiveKPI]:
        """Calculate current executive KPIs"""
        try:
            kpis = []
            
            # Get analytics engine data
            analytics_db = os.path.join(os.path.dirname(self.db_path), 'analytics.db')
            
            if os.path.exists(analytics_db):
                with sqlite3.connect(analytics_db) as conn:
                    cursor = conn.cursor()
                    
                    # Threat Detection Rate KPI
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'threat_detection_rate' 
                        AND timestamp >= datetime('now', '-24 hours')
                    ''')
                    result = cursor.fetchone()
                    detection_rate = result[0] if result[0] else 0.0
                    
                    # Calculate trend
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'threat_detection_rate' 
                        AND timestamp >= datetime('now', '-48 hours')
                        AND timestamp < datetime('now', '-24 hours')
                    ''')
                    prev_result = cursor.fetchone()
                    prev_detection_rate = prev_result[0] if prev_result[0] else detection_rate
                    
                    trend_pct = ((detection_rate - prev_detection_rate) / prev_detection_rate * 100) if prev_detection_rate > 0 else 0
                    trend = 'up' if trend_pct > 1 else 'down' if trend_pct < -1 else 'stable'
                    status = self._get_kpi_status('threat_detection_rate', detection_rate)
                    
                    kpis.append(ExecutiveKPI(
                        name="Threat Detection Rate",
                        value=detection_rate,
                        unit="%",
                        trend=trend,
                        trend_percentage=trend_pct,
                        status=status,
                        description="Percentage of threats successfully detected",
                        last_updated=datetime.now().isoformat()
                    ))
                    
                    # False Positive Rate KPI
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'false_positive_rate' 
                        AND timestamp >= datetime('now', '-24 hours')
                    ''')
                    result = cursor.fetchone()
                    fp_rate = result[0] if result[0] else 0.0
                    
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'false_positive_rate' 
                        AND timestamp >= datetime('now', '-48 hours')
                        AND timestamp < datetime('now', '-24 hours')
                    ''')
                    prev_result = cursor.fetchone()
                    prev_fp_rate = prev_result[0] if prev_result[0] else fp_rate
                    
                    trend_pct = ((fp_rate - prev_fp_rate) / prev_fp_rate * 100) if prev_fp_rate > 0 else 0
                    trend = 'down' if trend_pct > 1 else 'up' if trend_pct < -1 else 'stable'  # Inverted for FP rate
                    status = self._get_kpi_status('false_positive_rate', fp_rate)
                    
                    kpis.append(ExecutiveKPI(
                        name="False Positive Rate",
                        value=fp_rate,
                        unit="%",
                        trend=trend,
                        trend_percentage=abs(trend_pct),
                        status=status,
                        description="Percentage of false positive detections",
                        last_updated=datetime.now().isoformat()
                    ))
                    
                    # System Uptime KPI
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'system_uptime' 
                        AND timestamp >= datetime('now', '-24 hours')
                    ''')
                    result = cursor.fetchone()
                    uptime = result[0] if result[0] else 99.0
                    
                    status = self._get_kpi_status('system_uptime', uptime)
                    
                    kpis.append(ExecutiveKPI(
                        name="System Uptime",
                        value=uptime,
                        unit="%",
                        trend='stable',
                        trend_percentage=0.0,
                        status=status,
                        description="System availability percentage",
                        last_updated=datetime.now().isoformat()
                    ))
                    
                    # Response Time KPI
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'avg_scan_time' 
                        AND timestamp >= datetime('now', '-24 hours')
                    ''')
                    result = cursor.fetchone()
                    response_time = result[0] if result[0] else 2.0
                    
                    status = self._get_kpi_status('response_time', response_time)
                    
                    kpis.append(ExecutiveKPI(
                        name="Average Response Time",
                        value=response_time,
                        unit="seconds",
                        trend='stable',
                        trend_percentage=0.0,
                        status=status,
                        description="Average threat response time",
                        last_updated=datetime.now().isoformat()
                    ))
            
            # Save KPIs to database
            self._save_kpis(kpis)
            
            return kpis
            
        except Exception as e:
            self.logger.error(f"Failed to calculate executive KPIs: {e}")
            return []
    
    def _get_kpi_status(self, kpi_name: str, value: float) -> str:
        """Determine KPI status based on thresholds"""
        if kpi_name not in self.kpi_thresholds:
            return 'good'
        
        thresholds = self.kpi_thresholds[kpi_name]
        
        if kpi_name == 'false_positive_rate':
            # Lower is better for false positive rate
            if value <= thresholds['good']:
                return 'good'
            elif value <= thresholds['warning']:
                return 'warning'
            else:
                return 'critical'
        else:
            # Higher is better for other metrics
            if value >= thresholds['good']:
                return 'good'
            elif value >= thresholds['warning']:
                return 'warning'
            else:
                return 'critical'
    
    def _save_kpis(self, kpis: List[ExecutiveKPI]):
        """Save KPIs to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for kpi in kpis:
                    cursor.execute('''
                        INSERT INTO executive_kpis 
                        (name, value, unit, trend, trend_percentage, status, description)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (kpi.name, kpi.value, kpi.unit, kpi.trend, 
                          kpi.trend_percentage, kpi.status, kpi.description))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save KPIs: {e}")
    
    def get_threat_summary(self, period_hours: int = 24) -> ThreatSummary:
        """Get threat summary for specified period"""
        try:
            # Get data from various log sources
            threat_logs_path = os.path.join(os.path.dirname(self.db_path), 'threat_responses')
            quarantine_path = os.path.join(os.path.dirname(self.db_path), '..', 'quarantine')
            
            total_threats = 0
            threats_blocked = 0
            threats_quarantined = 0
            false_positives = 0
            
            # Count quarantined files
            if os.path.exists(quarantine_path):
                quarantine_files = [f for f in os.listdir(quarantine_path) if os.path.isfile(os.path.join(quarantine_path, f))]
                threats_quarantined = len(quarantine_files)
                total_threats = threats_quarantined
            
            # Calculate detection rate
            detection_rate = (threats_blocked + threats_quarantined) / max(total_threats, 1) * 100
            
            # Average response time (mock data for now)
            response_time_avg = 2.5
            
            summary = ThreatSummary(
                total_threats=total_threats,
                threats_blocked=threats_blocked,
                threats_quarantined=threats_quarantined,
                false_positives=false_positives,
                detection_rate=detection_rate,
                response_time_avg=response_time_avg
            )
            
            # Save summary
            self._save_threat_summary(summary, period_hours)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to get threat summary: {e}")
            return ThreatSummary(0, 0, 0, 0, 0.0, 0.0)
    
    def _save_threat_summary(self, summary: ThreatSummary, period_hours: int):
        """Save threat summary to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                period_start = datetime.now() - timedelta(hours=period_hours)
                period_end = datetime.now()
                
                cursor.execute('''
                    INSERT INTO threat_summaries 
                    (total_threats, threats_blocked, threats_quarantined, false_positives,
                     detection_rate, response_time_avg, period_start, period_end)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (summary.total_threats, summary.threats_blocked, summary.threats_quarantined,
                      summary.false_positives, summary.detection_rate, summary.response_time_avg,
                      period_start, period_end))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save threat summary: {e}")
    
    def get_system_health(self) -> SystemHealth:
        """Get current system health metrics"""
        try:
            # Get system metrics from analytics
            analytics_db = os.path.join(os.path.dirname(self.db_path), 'analytics.db')
            
            uptime_percentage = 99.5
            cpu_usage_avg = 15.0
            memory_usage_avg = 45.0
            scan_performance = 1200.0
            
            if os.path.exists(analytics_db):
                with sqlite3.connect(analytics_db) as conn:
                    cursor = conn.cursor()
                    
                    # Get recent system metrics
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'cpu_usage' 
                        AND timestamp >= datetime('now', '-1 hour')
                    ''')
                    result = cursor.fetchone()
                    if result[0]:
                        cpu_usage_avg = result[0]
                    
                    cursor.execute('''
                        SELECT AVG(value) FROM metrics 
                        WHERE name = 'memory_usage' 
                        AND timestamp >= datetime('now', '-1 hour')
                    ''')
                    result = cursor.fetchone()
                    if result[0]:
                        memory_usage_avg = result[0]
            
            # Determine system status
            if uptime_percentage >= 99.0 and cpu_usage_avg < 50.0 and memory_usage_avg < 70.0:
                system_status = 'excellent'
            elif uptime_percentage >= 95.0 and cpu_usage_avg < 70.0 and memory_usage_avg < 85.0:
                system_status = 'good'
            elif uptime_percentage >= 90.0:
                system_status = 'warning'
            else:
                system_status = 'critical'
            
            health = SystemHealth(
                uptime_percentage=uptime_percentage,
                cpu_usage_avg=cpu_usage_avg,
                memory_usage_avg=memory_usage_avg,
                scan_performance=scan_performance,
                last_update=datetime.now().isoformat(),
                system_status=system_status
            )
            
            # Save health metrics
            self._save_system_health(health)
            
            return health
            
        except Exception as e:
            self.logger.error(f"Failed to get system health: {e}")
            return SystemHealth(0.0, 0.0, 0.0, 0.0, datetime.now().isoformat(), 'unknown')
    
    def _save_system_health(self, health: SystemHealth):
        """Save system health to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO system_health 
                    (uptime_percentage, cpu_usage_avg, memory_usage_avg, 
                     scan_performance, system_status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (health.uptime_percentage, health.cpu_usage_avg, 
                      health.memory_usage_avg, health.scan_performance, 
                      health.system_status))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save system health: {e}")
    
    def generate_executive_report(self, period_days: int = 7) -> Dict[str, Any]:
        """Generate comprehensive executive report"""
        try:
            report_data = {
                'report_type': 'executive_summary',
                'period_days': period_days,
                'generated_at': datetime.now().isoformat(),
                'kpis': [],
                'threat_summary': {},
                'system_health': {},
                'recommendations': [],
                'risk_assessment': 'low'
            }
            
            # Get KPIs
            kpis = self.calculate_executive_kpis()
            report_data['kpis'] = [asdict(kpi) for kpi in kpis]
            
            # Get threat summary
            threat_summary = self.get_threat_summary(period_days * 24)
            report_data['threat_summary'] = asdict(threat_summary)
            
            # Get system health
            system_health = self.get_system_health()
            report_data['system_health'] = asdict(system_health)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(kpis, threat_summary, system_health)
            report_data['recommendations'] = recommendations
            
            # Assess overall risk
            risk_level = self._assess_risk_level(kpis, threat_summary, system_health)
            report_data['risk_assessment'] = risk_level
            
            # Save report
            self._save_executive_report(report_data, period_days)
            
            return report_data
            
        except Exception as e:
            self.logger.error(f"Failed to generate executive report: {e}")
            return {}
    
    def _generate_recommendations(self, kpis: List[ExecutiveKPI], 
                                threat_summary: ThreatSummary, 
                                system_health: SystemHealth) -> List[str]:
        """Generate executive recommendations"""
        recommendations = []
        
        # Check KPI status
        for kpi in kpis:
            if kpi.status == 'critical':
                if kpi.name == "Threat Detection Rate":
                    recommendations.append("Critical: Threat detection rate is below acceptable levels. Consider updating threat signatures and AI models.")
                elif kpi.name == "False Positive Rate":
                    recommendations.append("Critical: False positive rate is too high. Review and tune detection algorithms.")
                elif kpi.name == "System Uptime":
                    recommendations.append("Critical: System uptime is below target. Investigate system stability issues.")
            elif kpi.status == 'warning':
                recommendations.append(f"Warning: {kpi.name} requires attention. Monitor closely and consider optimization.")
        
        # System health recommendations
        if system_health.system_status in ['warning', 'critical']:
            if system_health.cpu_usage_avg > 70:
                recommendations.append("High CPU usage detected. Consider system optimization or hardware upgrade.")
            if system_health.memory_usage_avg > 80:
                recommendations.append("High memory usage detected. Review memory allocation and consider upgrade.")
        
        # Threat-based recommendations
        if threat_summary.detection_rate < 95:
            recommendations.append("Threat detection rate below target. Update threat intelligence feeds.")
        
        if not recommendations:
            recommendations.append("System is operating within normal parameters. Continue monitoring.")
        
        return recommendations
    
    def _assess_risk_level(self, kpis: List[ExecutiveKPI], 
                          threat_summary: ThreatSummary, 
                          system_health: SystemHealth) -> str:
        """Assess overall organizational risk level"""
        critical_count = sum(1 for kpi in kpis if kpi.status == 'critical')
        warning_count = sum(1 for kpi in kpis if kpi.status == 'warning')
        
        if critical_count > 0 or system_health.system_status == 'critical':
            return 'high'
        elif warning_count > 1 or system_health.system_status == 'warning':
            return 'medium'
        else:
            return 'low'
    
    def _save_executive_report(self, report_data: Dict[str, Any], period_days: int):
        """Save executive report to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                period_start = datetime.now() - timedelta(days=period_days)
                period_end = datetime.now()
                
                cursor.execute('''
                    INSERT INTO executive_reports 
                    (report_type, report_data, period_start, period_end, generated_by)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('executive_summary', json.dumps(report_data), 
                      period_start, period_end, 'system'))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save executive report: {e}")
    
    def get_historical_kpis(self, days: int = 30) -> Dict[str, List[Dict]]:
        """Get historical KPI data for trending"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                start_date = datetime.now() - timedelta(days=days)
                
                cursor.execute('''
                    SELECT name, value, status, timestamp
                    FROM executive_kpis 
                    WHERE timestamp >= ?
                    ORDER BY name, timestamp
                ''', (start_date,))
                
                results = cursor.fetchall()
                
                # Group by KPI name
                kpi_history = {}
                for name, value, status, timestamp in results:
                    if name not in kpi_history:
                        kpi_history[name] = []
                    
                    kpi_history[name].append({
                        'value': value,
                        'status': status,
                        'timestamp': timestamp
                    })
                
                return kpi_history
                
        except Exception as e:
            self.logger.error(f"Failed to get historical KPIs: {e}")
            return {}
    
    def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old dashboard data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days_to_keep)
                
                # Clean up old records
                tables = ['executive_kpis', 'security_metrics', 'threat_summaries', 
                         'system_health', 'executive_reports']
                
                for table in tables:
                    cursor.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff_date,))
                
                conn.commit()
                self.logger.info(f"Cleaned up dashboard data older than {days_to_keep} days")
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")

if __name__ == "__main__":
    # Test executive dashboard
    dashboard = ExecutiveDashboard()
    
    # Generate sample data
    kpis = dashboard.calculate_executive_kpis()
    print("Executive KPIs:")
    for kpi in kpis:
        print(f"  {kpi.name}: {kpi.value}{kpi.unit} ({kpi.status})")
    
    # Generate executive report
    report = dashboard.generate_executive_report()
    print(f"\nExecutive Report Generated: {len(report)} sections")
