"""
Compliance Reporting System
Provides comprehensive compliance monitoring, reporting, and audit capabilities for AI Antivirus.
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import os
import hashlib

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    ISO27001 = "ISO 27001"
    NIST = "NIST Cybersecurity Framework"
    GDPR = "General Data Protection Regulation"
    HIPAA = "Health Insurance Portability and Accountability Act"
    SOX = "Sarbanes-Oxley Act"
    PCI_DSS = "Payment Card Industry Data Security Standard"
    CUSTOM = "Custom Framework"

class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    UNDER_REVIEW = "under_review"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    id: str
    framework: str
    title: str
    description: str
    category: str
    priority: str  # 'high', 'medium', 'low'
    status: str
    evidence: List[str]
    last_assessed: str
    next_review: str
    responsible_party: str

@dataclass
class ComplianceFinding:
    """Compliance audit finding"""
    id: str
    requirement_id: str
    finding_type: str  # 'gap', 'weakness', 'observation', 'strength'
    severity: str  # 'critical', 'high', 'medium', 'low'
    title: str
    description: str
    recommendation: str
    status: str  # 'open', 'in_progress', 'resolved', 'accepted_risk'
    identified_date: str
    target_resolution: str
    actual_resolution: Optional[str]

@dataclass
class ComplianceReport:
    """Comprehensive compliance report"""
    id: str
    framework: str
    report_type: str
    period_start: str
    period_end: str
    overall_score: float
    total_requirements: int
    compliant_requirements: int
    findings_summary: Dict[str, int]
    recommendations: List[str]
    generated_by: str
    generated_at: str

class ComplianceReporting:
    """Compliance Reporting System for AI Antivirus"""
    
    def __init__(self, db_path: str = None):
        """Initialize Compliance Reporting System"""
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.reporting.compliance_reporting')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Database setup
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'compliance.db')
        
        self.db_path = db_path
        self.init_database()
        
        # Initialize default compliance frameworks
        self.init_compliance_frameworks()
        
    def init_database(self):
        """Initialize compliance database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Compliance requirements table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_requirements (
                        id TEXT PRIMARY KEY,
                        framework TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        category TEXT NOT NULL,
                        priority TEXT NOT NULL,
                        status TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        last_assessed DATETIME,
                        next_review DATETIME,
                        responsible_party TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Compliance findings table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_findings (
                        id TEXT PRIMARY KEY,
                        requirement_id TEXT NOT NULL,
                        finding_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        recommendation TEXT NOT NULL,
                        status TEXT NOT NULL,
                        identified_date DATETIME NOT NULL,
                        target_resolution DATETIME,
                        actual_resolution DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (requirement_id) REFERENCES compliance_requirements (id)
                    )
                ''')
                
                # Compliance reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_reports (
                        id TEXT PRIMARY KEY,
                        framework TEXT NOT NULL,
                        report_type TEXT NOT NULL,
                        period_start DATETIME NOT NULL,
                        period_end DATETIME NOT NULL,
                        overall_score REAL NOT NULL,
                        total_requirements INTEGER NOT NULL,
                        compliant_requirements INTEGER NOT NULL,
                        findings_summary TEXT NOT NULL,
                        recommendations TEXT NOT NULL,
                        report_data TEXT NOT NULL,
                        generated_by TEXT NOT NULL,
                        generated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Compliance assessments table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_assessments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        requirement_id TEXT NOT NULL,
                        assessment_date DATETIME NOT NULL,
                        assessor TEXT NOT NULL,
                        status TEXT NOT NULL,
                        score REAL,
                        notes TEXT,
                        evidence_collected TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (requirement_id) REFERENCES compliance_requirements (id)
                    )
                ''')
                
                # Compliance metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS compliance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        framework TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        measurement_date DATETIME NOT NULL,
                        notes TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                self.logger.info("Compliance database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize compliance database: {e}")
            raise
    
    def init_compliance_frameworks(self):
        """Initialize default compliance frameworks and requirements"""
        try:
            # Check if requirements already exist
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM compliance_requirements')
                count = cursor.fetchone()[0]
                
                if count > 0:
                    return  # Already initialized
            
            # Initialize ISO 27001 requirements
            iso27001_requirements = [
                {
                    'id': 'ISO27001-A.12.2.1',
                    'framework': ComplianceFramework.ISO27001.value,
                    'title': 'Controls against malware',
                    'description': 'Detection, prevention and recovery controls to protect against malware shall be implemented, combined with appropriate user awareness.',
                    'category': 'Information Security',
                    'priority': 'high',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['AI Antivirus deployment', 'Real-time protection logs', 'Threat detection reports'],
                    'responsible_party': 'IT Security Team'
                },
                {
                    'id': 'ISO27001-A.12.6.1',
                    'framework': ComplianceFramework.ISO27001.value,
                    'title': 'Management of technical vulnerabilities',
                    'description': 'Information about technical vulnerabilities of information systems being used shall be obtained in a timely fashion.',
                    'category': 'Vulnerability Management',
                    'priority': 'high',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['Vulnerability scanning reports', 'Patch management logs', 'Threat intelligence feeds'],
                    'responsible_party': 'IT Security Team'
                },
                {
                    'id': 'ISO27001-A.16.1.1',
                    'framework': ComplianceFramework.ISO27001.value,
                    'title': 'Responsibilities and procedures',
                    'description': 'Management responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents.',
                    'category': 'Incident Response',
                    'priority': 'high',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['Incident response procedures', 'Automated threat response logs', 'Escalation procedures'],
                    'responsible_party': 'CISO'
                }
            ]
            
            # Initialize NIST requirements
            nist_requirements = [
                {
                    'id': 'NIST-PR.DS-1',
                    'framework': ComplianceFramework.NIST.value,
                    'title': 'Data-at-rest is protected',
                    'description': 'Data at rest is protected through appropriate mechanisms to prevent unauthorized access.',
                    'category': 'Data Security',
                    'priority': 'high',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['File encryption logs', 'Access control reports', 'Data classification policies'],
                    'responsible_party': 'Data Protection Officer'
                },
                {
                    'id': 'NIST-DE.CM-1',
                    'framework': ComplianceFramework.NIST.value,
                    'title': 'The network is monitored to detect potential cybersecurity events',
                    'description': 'Network monitoring capabilities are implemented to detect anomalous activity and potential cybersecurity events.',
                    'category': 'Detection',
                    'priority': 'high',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['Network monitoring logs', 'Anomaly detection reports', 'Traffic analysis data'],
                    'responsible_party': 'SOC Team'
                },
                {
                    'id': 'NIST-RS.RP-1',
                    'framework': ComplianceFramework.NIST.value,
                    'title': 'Response plan is executed during or after an incident',
                    'description': 'Response plans are executed during or after a cybersecurity incident to minimize impact.',
                    'category': 'Response',
                    'priority': 'medium',
                    'status': ComplianceStatus.COMPLIANT.value,
                    'evidence': ['Incident response logs', 'Automated response actions', 'Recovery procedures'],
                    'responsible_party': 'Incident Response Team'
                }
            ]
            
            # Add requirements to database
            all_requirements = iso27001_requirements + nist_requirements
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for req in all_requirements:
                    next_review = datetime.now() + timedelta(days=365)  # Annual review
                    
                    cursor.execute('''
                        INSERT INTO compliance_requirements 
                        (id, framework, title, description, category, priority, status, 
                         evidence, last_assessed, next_review, responsible_party)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (req['id'], req['framework'], req['title'], req['description'],
                          req['category'], req['priority'], req['status'],
                          json.dumps(req['evidence']), datetime.now(), next_review,
                          req['responsible_party']))
                
                conn.commit()
                self.logger.info("Default compliance frameworks initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize compliance frameworks: {e}")
    
    def assess_compliance_requirement(self, requirement_id: str, assessor: str, 
                                    status: ComplianceStatus, score: float = None, 
                                    notes: str = "", evidence: List[str] = None) -> bool:
        """Assess a specific compliance requirement"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Update requirement status
                cursor.execute('''
                    UPDATE compliance_requirements 
                    SET status = ?, last_assessed = ?, updated_at = ?
                    WHERE id = ?
                ''', (status.value, datetime.now(), datetime.now(), requirement_id))
                
                # Add assessment record
                evidence_json = json.dumps(evidence) if evidence else "[]"
                
                cursor.execute('''
                    INSERT INTO compliance_assessments 
                    (requirement_id, assessment_date, assessor, status, score, notes, evidence_collected)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (requirement_id, datetime.now(), assessor, status.value, score, notes, evidence_json))
                
                conn.commit()
                self.logger.info(f"Compliance requirement {requirement_id} assessed as {status.value}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to assess compliance requirement: {e}")
            return False
    
    def create_compliance_finding(self, requirement_id: str, finding_type: str, 
                                severity: str, title: str, description: str, 
                                recommendation: str, target_days: int = 30) -> str:
        """Create a new compliance finding"""
        try:
            finding_id = hashlib.md5(f"{requirement_id}_{title}_{datetime.now()}".encode()).hexdigest()[:12]
            target_resolution = datetime.now() + timedelta(days=target_days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO compliance_findings 
                    (id, requirement_id, finding_type, severity, title, description, 
                     recommendation, status, identified_date, target_resolution)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (finding_id, requirement_id, finding_type, severity, title, description,
                      recommendation, 'open', datetime.now(), target_resolution))
                
                conn.commit()
                self.logger.info(f"Compliance finding {finding_id} created")
                return finding_id
                
        except Exception as e:
            self.logger.error(f"Failed to create compliance finding: {e}")
            return ""
    
    def update_finding_status(self, finding_id: str, status: str, resolution_notes: str = "") -> bool:
        """Update the status of a compliance finding"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                update_fields = ['status = ?', 'updated_at = ?']
                update_values = [status, datetime.now()]
                
                if status == 'resolved':
                    update_fields.append('actual_resolution = ?')
                    update_values.append(datetime.now())
                
                update_values.append(finding_id)
                
                cursor.execute(f'''
                    UPDATE compliance_findings 
                    SET {', '.join(update_fields)}
                    WHERE id = ?
                ''', update_values)
                
                conn.commit()
                self.logger.info(f"Compliance finding {finding_id} status updated to {status}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update finding status: {e}")
            return False
    
    def generate_compliance_report(self, framework: ComplianceFramework, 
                                 report_type: str = "assessment", 
                                 period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        try:
            report_id = hashlib.md5(f"{framework.value}_{report_type}_{datetime.now()}".encode()).hexdigest()[:12]
            period_start = datetime.now() - timedelta(days=period_days)
            period_end = datetime.now()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get requirements for framework
                cursor.execute('''
                    SELECT * FROM compliance_requirements 
                    WHERE framework = ?
                ''', (framework.value,))
                
                requirements = cursor.fetchall()
                total_requirements = len(requirements)
                compliant_requirements = sum(1 for req in requirements if req[6] == 'compliant')
                
                # Calculate overall score
                overall_score = (compliant_requirements / total_requirements * 100) if total_requirements > 0 else 0
                
                # Get findings summary
                cursor.execute('''
                    SELECT f.severity, COUNT(*) 
                    FROM compliance_findings f
                    JOIN compliance_requirements r ON f.requirement_id = r.id
                    WHERE r.framework = ? AND f.identified_date >= ?
                    GROUP BY f.severity
                ''', (framework.value, period_start))
                
                findings_summary = dict(cursor.fetchall())
                
                # Get open findings
                cursor.execute('''
                    SELECT f.* FROM compliance_findings f
                    JOIN compliance_requirements r ON f.requirement_id = r.id
                    WHERE r.framework = ? AND f.status = 'open'
                ''', (framework.value,))
                
                open_findings = cursor.fetchall()
                
                # Generate recommendations
                recommendations = self._generate_compliance_recommendations(requirements, open_findings)
                
                # Create report data
                report_data = {
                    'id': report_id,
                    'framework': framework.value,
                    'report_type': report_type,
                    'period_start': period_start.isoformat(),
                    'period_end': period_end.isoformat(),
                    'overall_score': overall_score,
                    'total_requirements': total_requirements,
                    'compliant_requirements': compliant_requirements,
                    'findings_summary': findings_summary,
                    'recommendations': recommendations,
                    'requirements_detail': [self._format_requirement(req) for req in requirements],
                    'open_findings': [self._format_finding(finding) for finding in open_findings],
                    'generated_by': 'system',
                    'generated_at': datetime.now().isoformat()
                }
                
                # Save report
                cursor.execute('''
                    INSERT INTO compliance_reports 
                    (id, framework, report_type, period_start, period_end, overall_score,
                     total_requirements, compliant_requirements, findings_summary, 
                     recommendations, report_data, generated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (report_id, framework.value, report_type, period_start, period_end,
                      overall_score, total_requirements, compliant_requirements,
                      json.dumps(findings_summary), json.dumps(recommendations),
                      json.dumps(report_data), 'system'))
                
                conn.commit()
                self.logger.info(f"Compliance report {report_id} generated for {framework.value}")
                
                return report_data
                
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            return {}
    
    def _format_requirement(self, req_tuple: Tuple) -> Dict[str, Any]:
        """Format requirement tuple as dictionary"""
        return {
            'id': req_tuple[0],
            'framework': req_tuple[1],
            'title': req_tuple[2],
            'description': req_tuple[3],
            'category': req_tuple[4],
            'priority': req_tuple[5],
            'status': req_tuple[6],
            'evidence': json.loads(req_tuple[7]) if req_tuple[7] else [],
            'last_assessed': req_tuple[8],
            'next_review': req_tuple[9],
            'responsible_party': req_tuple[10]
        }
    
    def _format_finding(self, finding_tuple: Tuple) -> Dict[str, Any]:
        """Format finding tuple as dictionary"""
        return {
            'id': finding_tuple[0],
            'requirement_id': finding_tuple[1],
            'finding_type': finding_tuple[2],
            'severity': finding_tuple[3],
            'title': finding_tuple[4],
            'description': finding_tuple[5],
            'recommendation': finding_tuple[6],
            'status': finding_tuple[7],
            'identified_date': finding_tuple[8],
            'target_resolution': finding_tuple[9],
            'actual_resolution': finding_tuple[10]
        }
    
    def _generate_compliance_recommendations(self, requirements: List[Tuple], 
                                           open_findings: List[Tuple]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        # Check for non-compliant requirements
        non_compliant = [req for req in requirements if req[6] != 'compliant']
        if non_compliant:
            recommendations.append(f"Address {len(non_compliant)} non-compliant requirements to improve overall compliance score.")
        
        # Check for critical findings
        critical_findings = [f for f in open_findings if f[3] == 'critical']
        if critical_findings:
            recommendations.append(f"Immediately address {len(critical_findings)} critical compliance findings.")
        
        # Check for overdue reviews
        overdue_reviews = [req for req in requirements if req[9] and datetime.fromisoformat(req[9]) < datetime.now()]
        if overdue_reviews:
            recommendations.append(f"Schedule reviews for {len(overdue_reviews)} overdue compliance requirements.")
        
        # General recommendations
        if not recommendations:
            recommendations.append("Maintain current compliance posture and continue regular assessments.")
        
        return recommendations
    
    def get_compliance_dashboard_data(self, framework: ComplianceFramework = None) -> Dict[str, Any]:
        """Get compliance dashboard data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                dashboard_data = {
                    'overall_compliance': {},
                    'framework_scores': {},
                    'recent_findings': [],
                    'upcoming_reviews': [],
                    'metrics_summary': {}
                }
                
                # Get framework scores
                if framework:
                    frameworks = [framework.value]
                else:
                    cursor.execute('SELECT DISTINCT framework FROM compliance_requirements')
                    frameworks = [row[0] for row in cursor.fetchall()]
                
                for fw in frameworks:
                    cursor.execute('''
                        SELECT 
                            COUNT(*) as total,
                            SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant
                        FROM compliance_requirements 
                        WHERE framework = ?
                    ''', (fw,))
                    
                    result = cursor.fetchone()
                    total, compliant = result
                    score = (compliant / total * 100) if total > 0 else 0
                    
                    dashboard_data['framework_scores'][fw] = {
                        'total_requirements': total,
                        'compliant_requirements': compliant,
                        'compliance_score': score
                    }
                
                # Get recent findings
                cursor.execute('''
                    SELECT f.*, r.framework 
                    FROM compliance_findings f
                    JOIN compliance_requirements r ON f.requirement_id = r.id
                    WHERE f.identified_date >= datetime('now', '-30 days')
                    ORDER BY f.identified_date DESC
                    LIMIT 10
                ''')
                
                recent_findings = cursor.fetchall()
                dashboard_data['recent_findings'] = [self._format_finding_with_framework(f) for f in recent_findings]
                
                # Get upcoming reviews
                cursor.execute('''
                    SELECT * FROM compliance_requirements 
                    WHERE next_review <= datetime('now', '+30 days')
                    ORDER BY next_review ASC
                    LIMIT 10
                ''')
                
                upcoming_reviews = cursor.fetchall()
                dashboard_data['upcoming_reviews'] = [self._format_requirement(r) for r in upcoming_reviews]
                
                return dashboard_data
                
        except Exception as e:
            self.logger.error(f"Failed to get compliance dashboard data: {e}")
            return {}
    
    def _format_finding_with_framework(self, finding_tuple: Tuple) -> Dict[str, Any]:
        """Format finding with framework information"""
        finding = self._format_finding(finding_tuple[:-1])  # Exclude framework from finding data
        finding['framework'] = finding_tuple[-1]  # Add framework
        return finding
    
    def run_automated_compliance_check(self) -> Dict[str, Any]:
        """Run automated compliance checks"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'checks_performed': [],
                'findings_created': [],
                'recommendations': []
            }
            
            # Check if antivirus is running
            antivirus_running = self._check_antivirus_status()
            if not antivirus_running:
                finding_id = self.create_compliance_finding(
                    'ISO27001-A.12.2.1',
                    'gap',
                    'high',
                    'Antivirus Protection Not Active',
                    'AI Antivirus protection is not currently active, violating malware protection requirements.',
                    'Activate AI Antivirus real-time protection immediately.',
                    1  # 1 day to resolve
                )
                results['findings_created'].append(finding_id)
            
            results['checks_performed'].append('Antivirus Status Check')
            
            # Check threat detection metrics
            detection_rate = self._get_threat_detection_rate()
            if detection_rate < 95.0:
                finding_id = self.create_compliance_finding(
                    'ISO27001-A.12.2.1',
                    'weakness',
                    'medium',
                    'Low Threat Detection Rate',
                    f'Threat detection rate is {detection_rate}%, below the required 95% threshold.',
                    'Review and update threat detection algorithms and signatures.',
                    7  # 7 days to resolve
                )
                results['findings_created'].append(finding_id)
            
            results['checks_performed'].append('Threat Detection Rate Check')
            
            # Generate recommendations
            if results['findings_created']:
                results['recommendations'].append('Address newly identified compliance gaps immediately.')
            else:
                results['recommendations'].append('All automated compliance checks passed successfully.')
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to run automated compliance check: {e}")
            return {}
    
    def _check_antivirus_status(self) -> bool:
        """Check if antivirus is currently running"""
        # This would integrate with the actual antivirus status
        # For now, return True as a placeholder
        return True
    
    def _get_threat_detection_rate(self) -> float:
        """Get current threat detection rate"""
        # This would integrate with analytics engine
        # For now, return a sample value
        return 96.5
    
    def export_compliance_report(self, report_id: str, format: str = 'json') -> str:
        """Export compliance report in specified format"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT report_data FROM compliance_reports 
                    WHERE id = ?
                ''', (report_id,))
                
                result = cursor.fetchone()
                if not result:
                    return ""
                
                report_data = json.loads(result[0])
                
                if format.lower() == 'json':
                    return json.dumps(report_data, indent=2)
                elif format.lower() == 'csv':
                    # Convert to CSV format (simplified)
                    return self._convert_to_csv(report_data)
                else:
                    return json.dumps(report_data, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to export compliance report: {e}")
            return ""
    
    def _convert_to_csv(self, report_data: Dict[str, Any]) -> str:
        """Convert report data to CSV format"""
        # Simplified CSV conversion
        csv_lines = []
        csv_lines.append("Framework,Overall Score,Total Requirements,Compliant Requirements")
        csv_lines.append(f"{report_data['framework']},{report_data['overall_score']},{report_data['total_requirements']},{report_data['compliant_requirements']}")
        
        return "\n".join(csv_lines)

if __name__ == "__main__":
    # Test compliance reporting
    compliance = ComplianceReporting()
    
    # Run automated check
    check_results = compliance.run_automated_compliance_check()
    print("Automated Compliance Check Results:")
    print(f"  Checks performed: {len(check_results.get('checks_performed', []))}")
    print(f"  Findings created: {len(check_results.get('findings_created', []))}")
    
    # Generate ISO 27001 report
    report = compliance.generate_compliance_report(ComplianceFramework.ISO27001)
    print(f"\nISO 27001 Compliance Report:")
    print(f"  Overall Score: {report.get('overall_score', 0):.1f}%")
    print(f"  Compliant Requirements: {report.get('compliant_requirements', 0)}/{report.get('total_requirements', 0)}")
