"""
Enterprise Reporting Dashboard GUI
Main dashboard interface for AI Antivirus Enterprise Reporting features.
"""

import sys
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QLabel, QPushButton, QComboBox, QSpinBox,
                            QGroupBox, QGridLayout, QScrollArea, QMessageBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

# Import custom widgets
from .reporting_widgets import (KPIWidget, MetricsSummaryWidget, StatusIndicatorWidget,
                               ReportTableWidget, ProgressDialog, ReportViewer,
                               ReportingWorker)

# Import reporting modules
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

class ReportingDashboard(QWidget):
    """Main Enterprise Reporting Dashboard"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.reporting_dashboard')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize reporting engines
        self.init_reporting_engines()
        
        # Setup UI
        self.init_ui()
        
        # Setup timers
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_dashboard)
        self.refresh_timer.start(300000)  # Refresh every 5 minutes
        
        # Load initial data
        self.refresh_dashboard()
    
    def init_reporting_engines(self):
        """Initialize reporting engines"""
        try:
            from reporting.analytics_engine import AnalyticsEngine
            from reporting.executive_dashboard import ExecutiveDashboard
            from reporting.compliance_reporting import ComplianceReporting, ComplianceFramework
            from reporting.trend_analysis import TrendAnalysisEngine
            
            self.analytics_engine = AnalyticsEngine()
            self.executive_dashboard = ExecutiveDashboard()
            self.compliance_reporting = ComplianceReporting()
            self.trend_analysis = TrendAnalysisEngine()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize reporting engines: {e}")
            # Create placeholder engines
            self.analytics_engine = None
            self.executive_dashboard = None
            self.compliance_reporting = None
            self.trend_analysis = None
    
    def init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Enterprise Reporting Dashboard")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_dashboard)
        header_layout.addWidget(refresh_btn)
        
        # Export button
        export_btn = QPushButton("Export Report")
        export_btn.clicked.connect(self.export_report)
        header_layout.addWidget(export_btn)
        
        layout.addLayout(header_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.create_executive_tab()
        self.create_compliance_tab()
        self.create_trend_analysis_tab()
        self.create_analytics_tab()
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
    
    def create_executive_tab(self):
        """Create executive dashboard tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # KPI Section
        kpi_group = QGroupBox("Key Performance Indicators")
        kpi_layout = QHBoxLayout()
        
        self.kpi_container = QWidget()
        self.kpi_container_layout = QHBoxLayout()
        self.kpi_container.setLayout(self.kpi_container_layout)
        
        kpi_scroll = QScrollArea()
        kpi_scroll.setWidget(self.kpi_container)
        kpi_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        kpi_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        kpi_scroll.setFixedHeight(180)
        
        kpi_layout.addWidget(kpi_scroll)
        kpi_group.setLayout(kpi_layout)
        layout.addWidget(kpi_group)
        
        # Summary widgets layout
        summary_layout = QHBoxLayout()
        
        # Threat Summary
        self.threat_summary = MetricsSummaryWidget("Threat Summary")
        summary_layout.addWidget(self.threat_summary)
        
        # System Health
        self.system_health = MetricsSummaryWidget("System Health")
        summary_layout.addWidget(self.system_health)
        
        # Status indicators
        status_layout = QVBoxLayout()
        self.protection_status = StatusIndicatorWidget("Protection Status")
        self.compliance_status = StatusIndicatorWidget("Compliance Status")
        status_layout.addWidget(self.protection_status)
        status_layout.addWidget(self.compliance_status)
        summary_layout.addLayout(status_layout)
        
        layout.addLayout(summary_layout)
        
        # Generate Report Button
        generate_btn = QPushButton("Generate Executive Report")
        generate_btn.clicked.connect(self.generate_executive_report)
        layout.addWidget(generate_btn)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📊 Executive Dashboard")
    
    def create_compliance_tab(self):
        """Create compliance reporting tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Framework:"))
        self.framework_combo = QComboBox()
        frameworks = ["ISO 27001", "NIST Cybersecurity Framework", "GDPR", "HIPAA", "SOX", "PCI DSS"]
        self.framework_combo.addItems(frameworks)
        controls_layout.addWidget(self.framework_combo)
        
        controls_layout.addWidget(QLabel("Period (days):"))
        self.compliance_period_spin = QSpinBox()
        self.compliance_period_spin.setRange(1, 365)
        self.compliance_period_spin.setValue(30)
        controls_layout.addWidget(self.compliance_period_spin)
        
        generate_compliance_btn = QPushButton("Generate Compliance Report")
        generate_compliance_btn.clicked.connect(self.generate_compliance_report)
        controls_layout.addWidget(generate_compliance_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Compliance Overview
        self.compliance_overview = MetricsSummaryWidget("Compliance Overview")
        layout.addWidget(self.compliance_overview)
        
        # Requirements Table
        req_group = QGroupBox("Compliance Requirements")
        req_layout = QVBoxLayout()
        
        self.requirements_table = ReportTableWidget(['ID', 'Title', 'Category', 'Status', 'Priority'])
        req_layout.addWidget(self.requirements_table)
        
        req_group.setLayout(req_layout)
        layout.addWidget(req_group)
        
        # Findings Table
        findings_group = QGroupBox("Recent Findings")
        findings_layout = QVBoxLayout()
        
        self.findings_table = ReportTableWidget(['ID', 'Title', 'Severity', 'Status', 'Date'])
        findings_layout.addWidget(self.findings_table)
        
        findings_group.setLayout(findings_layout)
        layout.addWidget(findings_group)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📋 Compliance")
    
    def create_trend_analysis_tab(self):
        """Create trend analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Analysis Period (days):"))
        self.trend_period_spin = QSpinBox()
        self.trend_period_spin.setRange(7, 365)
        self.trend_period_spin.setValue(30)
        controls_layout.addWidget(self.trend_period_spin)
        
        controls_layout.addWidget(QLabel("Forecast Days:"))
        self.forecast_days_spin = QSpinBox()
        self.forecast_days_spin.setRange(1, 30)
        self.forecast_days_spin.setValue(7)
        controls_layout.addWidget(self.forecast_days_spin)
        
        generate_trend_btn = QPushButton("Generate Trend Analysis")
        generate_trend_btn.clicked.connect(self.generate_trend_analysis)
        controls_layout.addWidget(generate_trend_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Trend Summary
        self.trend_summary = MetricsSummaryWidget("Trend Summary")
        layout.addWidget(self.trend_summary)
        
        # Trends Table
        trends_group = QGroupBox("Trend Analysis Results")
        trends_layout = QVBoxLayout()
        
        self.trends_table = ReportTableWidget(['Metric', 'Direction', 'Strength', 'Change %', 'R²', 'Data Points'])
        trends_layout.addWidget(self.trends_table)
        
        trends_group.setLayout(trends_layout)
        layout.addWidget(trends_group)
        
        # Anomalies Table
        anomalies_group = QGroupBox("Detected Anomalies")
        anomalies_layout = QVBoxLayout()
        
        self.anomalies_table = ReportTableWidget(['Metric', 'Timestamp', 'Value', 'Expected', 'Type'])
        anomalies_layout.addWidget(self.anomalies_table)
        
        anomalies_group.setLayout(anomalies_layout)
        layout.addWidget(anomalies_group)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📈 Trend Analysis")
    
    def create_analytics_tab(self):
        """Create analytics tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        
        collect_btn = QPushButton("Collect Metrics")
        collect_btn.clicked.connect(self.collect_metrics)
        controls_layout.addWidget(collect_btn)
        
        calculate_kpis_btn = QPushButton("Calculate KPIs")
        calculate_kpis_btn.clicked.connect(self.calculate_kpis)
        controls_layout.addWidget(calculate_kpis_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Analytics Summary
        self.analytics_summary = MetricsSummaryWidget("Analytics Summary")
        layout.addWidget(self.analytics_summary)
        
        # Metrics Table
        metrics_group = QGroupBox("Recent Metrics")
        metrics_layout = QVBoxLayout()
        
        self.metrics_table = ReportTableWidget(['Name', 'Value', 'Unit', 'Timestamp'])
        metrics_layout.addWidget(self.metrics_table)
        
        metrics_group.setLayout(metrics_layout)
        layout.addWidget(metrics_group)
        
        # KPIs Table
        kpis_group = QGroupBox("Current KPIs")
        kpis_layout = QVBoxLayout()
        
        self.kpis_table = ReportTableWidget(['Name', 'Value', 'Target', 'Status'])
        kpis_layout.addWidget(self.kpis_table)
        
        kpis_group.setLayout(kpis_layout)
        layout.addWidget(kpis_group)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📊 Analytics")
    
    def refresh_dashboard(self):
        """Refresh dashboard data"""
        try:
            self.refresh_executive_data()
            self.refresh_compliance_data()
            self.refresh_analytics_data()
            self.refresh_trend_data()
            
        except Exception as e:
            self.logger.error(f"Failed to refresh dashboard: {e}")
    
    def refresh_executive_data(self):
        """Refresh executive dashboard data"""
        try:
            if not self.executive_dashboard:
                return
            
            # Get KPIs
            kpis = self.executive_dashboard.calculate_executive_kpis()
            
            # Clear existing KPI widgets
            for i in reversed(range(self.kpi_container_layout.count())):
                child = self.kpi_container_layout.itemAt(i).widget()
                if child:
                    child.setParent(None)
            
            # Add KPI widgets
            for kpi in kpis:
                from dataclasses import asdict
                kpi_widget = KPIWidget(asdict(kpi))
                self.kpi_container_layout.addWidget(kpi_widget)
            
            # Get threat summary
            threat_summary = self.executive_dashboard.get_threat_summary()
            self.threat_summary.update_metric("Total Threats", str(threat_summary.total_threats))
            self.threat_summary.update_metric("Threats Blocked", str(threat_summary.threats_blocked))
            self.threat_summary.update_metric("Detection Rate", f"{threat_summary.detection_rate:.1f}%")
            
            # Get system health
            system_health = self.executive_dashboard.get_system_health()
            self.system_health.update_metric("System Uptime", f"{system_health.uptime_percentage:.1f}%")
            self.system_health.update_metric("CPU Usage", f"{system_health.cpu_usage_avg:.1f}%")
            self.system_health.update_metric("Memory Usage", f"{system_health.memory_usage_avg:.1f}%")
            
            # Update status indicators
            if system_health.system_status == 'excellent':
                self.protection_status.update_status("Excellent", "#28a745")
            elif system_health.system_status == 'good':
                self.protection_status.update_status("Good", "#28a745")
            elif system_health.system_status == 'warning':
                self.protection_status.update_status("Warning", "#ffc107")
            else:
                self.protection_status.update_status("Critical", "#dc3545")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh executive data: {e}")
    
    def refresh_compliance_data(self):
        """Refresh compliance data"""
        try:
            if not self.compliance_reporting:
                return
            
            dashboard_data = self.compliance_reporting.get_compliance_dashboard_data()
            
            # Update overview
            framework_scores = dashboard_data.get('framework_scores', {})
            if framework_scores:
                first_framework = next(iter(framework_scores.values()))
                score = first_framework.get('compliance_score', 0)
                compliant = first_framework.get('compliant_requirements', 0)
                total = first_framework.get('total_requirements', 0)
                
                self.compliance_overview.update_metric("Overall Score", f"{score:.1f}%")
                self.compliance_overview.update_metric("Compliant Requirements", f"{compliant}/{total}")
                
                # Update compliance status
                if score >= 95:
                    self.compliance_status.update_status("Compliant", "#28a745")
                elif score >= 80:
                    self.compliance_status.update_status("Mostly Compliant", "#ffc107")
                else:
                    self.compliance_status.update_status("Non-Compliant", "#dc3545")
            
            # Update findings count
            recent_findings = dashboard_data.get('recent_findings', [])
            open_findings = len(recent_findings)
            critical_findings = len([f for f in recent_findings if f.get('severity') == 'critical'])
            
            self.compliance_overview.update_metric("Open Findings", str(open_findings))
            self.compliance_overview.update_metric("Critical Findings", str(critical_findings))
            
        except Exception as e:
            self.logger.error(f"Failed to refresh compliance data: {e}")
    
    def refresh_analytics_data(self):
        """Refresh analytics data"""
        try:
            if not self.analytics_engine:
                return
            
            # Get recent metrics
            recent_metrics = self.analytics_engine.get_recent_metrics(50)
            
            metrics_data = []
            for metric in recent_metrics:
                metrics_data.append([
                    metric.get('name', ''),
                    str(metric.get('value', 0)),
                    metric.get('unit', ''),
                    metric.get('timestamp', '')
                ])
            
            self.metrics_table.populate_data(metrics_data)
            
            # Get current KPIs
            current_kpis = self.analytics_engine.get_current_kpis()
            
            kpis_data = []
            for kpi in current_kpis:
                kpis_data.append([
                    kpi.get('name', ''),
                    f"{kpi.get('value', 0):.2f}",
                    f"{kpi.get('target', 0):.2f}",
                    kpi.get('status', 'unknown').title()
                ])
            
            self.kpis_table.populate_data(kpis_data, status_column=3)
            
            # Update analytics summary
            self.analytics_summary.update_metric("Total Metrics", str(len(recent_metrics)))
            self.analytics_summary.update_metric("Active KPIs", str(len(current_kpis)))
            
        except Exception as e:
            self.logger.error(f"Failed to refresh analytics data: {e}")
    
    def refresh_trend_data(self):
        """Refresh trend analysis data"""
        try:
            # Update trend summary with placeholder data
            self.trend_summary.update_metric("Trends Detected", "0")
            self.trend_summary.update_metric("Anomalies Found", "0")
            self.trend_summary.update_metric("Forecasts Generated", "0")
            self.trend_summary.update_metric("Metrics Analyzed", "4")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh trend data: {e}")
    
    def generate_executive_report(self):
        """Generate executive report"""
        try:
            if not self.executive_dashboard:
                QMessageBox.warning(self, "Warning", "Executive dashboard not available")
                return
            
            # Create progress dialog
            progress = ProgressDialog("Generating Executive Report...")
            progress.show()
            
            # Start worker thread
            worker = ReportingWorker('executive', {'period_days': 7})
            worker.report_generated.connect(lambda report: self.on_report_generated(report, 'executive', progress))
            worker.error_occurred.connect(lambda error: self.on_report_error(error, progress))
            worker.progress_updated.connect(progress.update_progress)
            worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate executive report: {e}")
    
    def generate_compliance_report(self):
        """Generate compliance report"""
        try:
            if not self.compliance_reporting:
                QMessageBox.warning(self, "Warning", "Compliance reporting not available")
                return
            
            framework = self.framework_combo.currentText()
            period_days = self.compliance_period_spin.value()
            
            progress = ProgressDialog("Generating Compliance Report...")
            progress.show()
            
            worker = ReportingWorker('compliance', {
                'framework': framework,
                'period_days': period_days,
                'report_type': 'assessment'
            })
            worker.report_generated.connect(lambda report: self.on_report_generated(report, 'compliance', progress))
            worker.error_occurred.connect(lambda error: self.on_report_error(error, progress))
            worker.progress_updated.connect(progress.update_progress)
            worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate compliance report: {e}")
    
    def generate_trend_analysis(self):
        """Generate trend analysis"""
        try:
            if not self.trend_analysis:
                QMessageBox.warning(self, "Warning", "Trend analysis not available")
                return
            
            period_days = self.trend_period_spin.value()
            
            progress = ProgressDialog("Generating Trend Analysis...")
            progress.show()
            
            worker = ReportingWorker('trend', {
                'period_days': period_days,
                'metrics': ['threat_detection_rate', 'false_positive_rate', 'system_uptime', 'avg_scan_time']
            })
            worker.report_generated.connect(lambda report: self.on_report_generated(report, 'trend', progress))
            worker.error_occurred.connect(lambda error: self.on_report_error(error, progress))
            worker.progress_updated.connect(progress.update_progress)
            worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate trend analysis: {e}")
    
    def collect_metrics(self):
        """Collect current metrics"""
        try:
            if self.analytics_engine:
                self.analytics_engine.collect_metrics()
                QMessageBox.information(self, "Success", "Metrics collected successfully!")
                self.refresh_analytics_data()
            else:
                QMessageBox.warning(self, "Warning", "Analytics engine not available")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to collect metrics: {e}")
    
    def calculate_kpis(self):
        """Calculate current KPIs"""
        try:
            if self.analytics_engine:
                self.analytics_engine.calculate_kpis()
                QMessageBox.information(self, "Success", "KPIs calculated successfully!")
                self.refresh_analytics_data()
            else:
                QMessageBox.warning(self, "Warning", "Analytics engine not available")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to calculate KPIs: {e}")
    
    def on_report_generated(self, report: Dict[str, Any], report_type: str, progress_dialog):
        """Handle report generation completion"""
        try:
            progress_dialog.set_complete()
            progress_dialog.close()
            
            # Show report viewer
            viewer = ReportViewer()
            viewer.display_report(report, report_type)
            viewer.setWindowTitle(f"{report_type.title()} Report")
            viewer.resize(800, 600)
            viewer.show()
            
            # Store reference to prevent garbage collection
            if not hasattr(self, 'report_viewers'):
                self.report_viewers = []
            self.report_viewers.append(viewer)
            
        except Exception as e:
            self.logger.error(f"Failed to handle report generation: {e}")
            QMessageBox.critical(self, "Error", f"Failed to display report: {e}")
    
    def on_report_error(self, error: str, progress_dialog):
        """Handle report generation error"""
        progress_dialog.close()
        QMessageBox.critical(self, "Report Generation Error", f"Failed to generate report:\n{error}")
    
    def export_report(self):
        """Export current dashboard data"""
        try:
            dashboard_data = {
                'timestamp': datetime.now().isoformat(),
                'executive_data': {},
                'compliance_data': {},
                'analytics_data': {},
                'trend_data': {}
            }
            
            from PyQt5.QtWidgets import QFileDialog
            import json
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Dashboard Data", 
                f"dashboard_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(dashboard_data, f, indent=2)
                
                QMessageBox.information(self, "Success", f"Dashboard data exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export dashboard data: {e}")
