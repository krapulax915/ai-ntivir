"""
Reporting Dashboard Widgets
Base widgets and components for the Enterprise Reporting Dashboard.
"""

import sys
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QFrame, QProgressBar, QTextEdit,
                            QTableWidget, QTableWidgetItem, QGroupBox,
                            QGridLayout, QScrollArea, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

class ReportingWorker(QThread):
    """Background worker for generating reports"""
    report_generated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    progress_updated = pyqtSignal(int)
    
    def __init__(self, report_type: str, parameters: Dict[str, Any]):
        super().__init__()
        self.report_type = report_type
        self.parameters = parameters
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.gui.reporting_widgets')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
    def run(self):
        """Generate report in background"""
        try:
            self.progress_updated.emit(10)
            
            # Import reporting modules
            sys.path.append(os.path.dirname(os.path.dirname(__file__)))
            
            if self.report_type == 'executive':
                from reporting.executive_dashboard import ExecutiveDashboard
                dashboard = ExecutiveDashboard()
                self.progress_updated.emit(30)
                report = dashboard.generate_executive_report(self.parameters.get('period_days', 7))
                self.progress_updated.emit(100)
                
            elif self.report_type == 'compliance':
                from reporting.compliance_reporting import ComplianceReporting, ComplianceFramework
                compliance = ComplianceReporting()
                self.progress_updated.emit(30)
                framework = ComplianceFramework(self.parameters.get('framework', 'ISO 27001'))
                report = compliance.generate_compliance_report(framework, 
                                                             self.parameters.get('report_type', 'assessment'),
                                                             self.parameters.get('period_days', 30))
                self.progress_updated.emit(100)
                
            elif self.report_type == 'trend':
                from reporting.trend_analysis import TrendAnalysisEngine
                trend_engine = TrendAnalysisEngine()
                self.progress_updated.emit(30)
                report = trend_engine.generate_trend_report(
                    self.parameters.get('metrics', None),
                    self.parameters.get('period_days', 30)
                )
                self.progress_updated.emit(100)
                
            else:
                raise ValueError(f"Unknown report type: {self.report_type}")
            
            self.report_generated.emit(report)
            
        except Exception as e:
            self.logger.error(f"Failed to generate {self.report_type} report: {e}")
            self.error_occurred.emit(str(e))

class KPIWidget(QFrame):
    """Widget for displaying KPI metrics"""
    
    def __init__(self, kpi_data: Dict[str, Any]):
        super().__init__()
        self.setFrameStyle(QFrame.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: white;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # KPI Name
        name_label = QLabel(kpi_data.get('name', 'Unknown KPI'))
        name_label.setFont(QFont("Arial", 12, QFont.Bold))
        name_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(name_label)
        
        # KPI Value
        value = kpi_data.get('value', 0)
        unit = kpi_data.get('unit', '')
        value_label = QLabel(f"{value:.1f}{unit}")
        value_label.setFont(QFont("Arial", 18, QFont.Bold))
        value_label.setAlignment(Qt.AlignCenter)
        
        # Color based on status
        status = kpi_data.get('status', 'good')
        if status == 'good':
            value_label.setStyleSheet("color: #28a745;")
        elif status == 'warning':
            value_label.setStyleSheet("color: #ffc107;")
        else:
            value_label.setStyleSheet("color: #dc3545;")
        
        layout.addWidget(value_label)
        
        # Trend indicator
        trend = kpi_data.get('trend', 'stable')
        trend_pct = kpi_data.get('trend_percentage', 0)
        
        if trend == 'up':
            trend_text = f"↗ +{trend_pct:.1f}%"
            trend_color = "#28a745"
        elif trend == 'down':
            trend_text = f"↘ -{trend_pct:.1f}%"
            trend_color = "#dc3545"
        else:
            trend_text = "→ Stable"
            trend_color = "#6c757d"
        
        trend_label = QLabel(trend_text)
        trend_label.setStyleSheet(f"color: {trend_color}; font-weight: bold;")
        trend_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(trend_label)
        
        # Description
        desc_label = QLabel(kpi_data.get('description', ''))
        desc_label.setWordWrap(True)
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("color: #6c757d; font-size: 10px;")
        layout.addWidget(desc_label)
        
        self.setLayout(layout)
        self.setFixedSize(200, 150)

class MetricsSummaryWidget(QGroupBox):
    """Widget for displaying metrics summary"""
    
    def __init__(self, title: str = "Metrics Summary"):
        super().__init__(title)
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QGridLayout()
        
        # Create labels for metrics
        self.metric_labels = {}
        self.value_labels = {}
        
        # Default metrics
        metrics = [
            ('Total Threats', '0'),
            ('Threats Blocked', '0'),
            ('Detection Rate', '0%'),
            ('System Uptime', '0%'),
            ('CPU Usage', '0%'),
            ('Memory Usage', '0%')
        ]
        
        row = 0
        col = 0
        for metric_name, default_value in metrics:
            # Metric label
            metric_label = QLabel(f"{metric_name}:")
            metric_label.setFont(QFont("Arial", 10, QFont.Bold))
            layout.addWidget(metric_label, row, col)
            
            # Value label
            value_label = QLabel(default_value)
            value_label.setFont(QFont("Arial", 10))
            layout.addWidget(value_label, row, col + 1)
            
            self.metric_labels[metric_name] = metric_label
            self.value_labels[metric_name] = value_label
            
            col += 2
            if col >= 6:  # 3 columns of metric-value pairs
                col = 0
                row += 1
        
        self.setLayout(layout)
    
    def update_metric(self, metric_name: str, value: str, color: str = None):
        """Update a specific metric value"""
        if metric_name in self.value_labels:
            self.value_labels[metric_name].setText(value)
            if color:
                self.value_labels[metric_name].setStyleSheet(f"color: {color}; font-weight: bold;")

class StatusIndicatorWidget(QFrame):
    """Widget for displaying system status"""
    
    def __init__(self, title: str = "System Status"):
        super().__init__()
        self.setFrameStyle(QFrame.StyledPanel)
        self.title = title
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(self.title)
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Status indicator
        self.status_label = QLabel("Unknown")
        self.status_label.setFont(QFont("Arial", 14, QFont.Bold))
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("""
            QLabel {
                border: 2px solid #ddd;
                border-radius: 5px;
                padding: 10px;
                background-color: #f8f9fa;
            }
        """)
        layout.addWidget(self.status_label)
        
        # Last updated
        self.updated_label = QLabel("Last updated: Never")
        self.updated_label.setAlignment(Qt.AlignCenter)
        self.updated_label.setStyleSheet("color: #6c757d; font-size: 10px;")
        layout.addWidget(self.updated_label)
        
        self.setLayout(layout)
        self.setFixedSize(180, 120)
    
    def update_status(self, status: str, color: str = "#6c757d"):
        """Update status display"""
        self.status_label.setText(status.title())
        self.status_label.setStyleSheet(f"""
            QLabel {{
                border: 2px solid {color};
                border-radius: 5px;
                padding: 10px;
                background-color: #f8f9fa;
                color: {color};
                font-weight: bold;
            }}
        """)
        self.updated_label.setText(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

class ReportTableWidget(QTableWidget):
    """Enhanced table widget for reports"""
    
    def __init__(self, headers: List[str]):
        super().__init__()
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSortingEnabled(True)
        
        # Style
        self.setStyleSheet("""
            QTableWidget {
                gridline-color: #ddd;
                background-color: white;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #007bff;
                color: white;
            }
        """)
    
    def populate_data(self, data: List[List[str]], status_column: int = None):
        """Populate table with data"""
        self.setRowCount(len(data))
        
        for row, row_data in enumerate(data):
            for col, cell_data in enumerate(row_data):
                item = QTableWidgetItem(str(cell_data))
                
                # Color code status column
                if status_column is not None and col == status_column:
                    status = str(cell_data).lower()
                    if status in ['good', 'compliant', 'excellent']:
                        item.setBackground(QColor(40, 167, 69, 50))
                    elif status in ['warning', 'partially_compliant']:
                        item.setBackground(QColor(255, 193, 7, 50))
                    elif status in ['critical', 'non_compliant', 'error']:
                        item.setBackground(QColor(220, 53, 69, 50))
                
                self.setItem(row, col, item)
        
        # Auto-resize columns
        self.resizeColumnsToContents()

class ProgressDialog(QWidget):
    """Progress dialog for long-running operations"""
    
    def __init__(self, title: str = "Processing..."):
        super().__init__()
        self.setWindowTitle(title)
        self.setFixedSize(400, 100)
        self.setWindowFlags(Qt.Dialog | Qt.WindowTitleHint)
        
        layout = QVBoxLayout()
        
        # Progress label
        self.progress_label = QLabel("Initializing...")
        layout.addWidget(self.progress_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        layout.addWidget(self.cancel_button)
        
        self.setLayout(layout)
    
    def update_progress(self, value: int, text: str = None):
        """Update progress"""
        self.progress_bar.setValue(value)
        if text:
            self.progress_label.setText(text)
    
    def set_complete(self):
        """Mark as complete"""
        self.progress_bar.setValue(100)
        self.progress_label.setText("Complete!")
        self.cancel_button.setText("Close")

class ReportViewer(QWidget):
    """Widget for viewing generated reports"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        self.title_label = QLabel("Report Viewer")
        self.title_label.setFont(QFont("Arial", 14, QFont.Bold))
        header_layout.addWidget(self.title_label)
        
        header_layout.addStretch()
        
        # Export button
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_report)
        header_layout.addWidget(self.export_button)
        
        layout.addLayout(header_layout)
        
        # Content area
        self.content_area = QTextEdit()
        self.content_area.setReadOnly(True)
        self.content_area.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #ddd;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.content_area)
        
        self.setLayout(layout)
        
        # Store current report data
        self.current_report = None
    
    def display_report(self, report_data: Dict[str, Any], report_type: str):
        """Display report data"""
        self.current_report = report_data
        self.title_label.setText(f"{report_type.title()} Report")
        
        # Format report for display
        formatted_report = self.format_report(report_data, report_type)
        self.content_area.setHtml(formatted_report)
    
    def format_report(self, report_data: Dict[str, Any], report_type: str) -> str:
        """Format report data as HTML"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #007bff; border-bottom: 2px solid #007bff; }}
                h2 {{ color: #28a745; }}
                .metric {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-left: 4px solid #007bff; }}
                .good {{ color: #28a745; font-weight: bold; }}
                .warning {{ color: #ffc107; font-weight: bold; }}
                .critical {{ color: #dc3545; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
        """
        
        html += f"<h1>{report_type.title()} Report</h1>"
        html += f"<p><strong>Generated:</strong> {report_data.get('generated_at', 'Unknown')}</p>"
        
        if report_type == 'executive':
            html += self.format_executive_report(report_data)
        elif report_type == 'compliance':
            html += self.format_compliance_report(report_data)
        elif report_type == 'trend':
            html += self.format_trend_report(report_data)
        
        html += "</body></html>"
        return html
    
    def format_executive_report(self, report_data: Dict[str, Any]) -> str:
        """Format executive report"""
        html = "<h2>Key Performance Indicators</h2>"
        
        kpis = report_data.get('kpis', [])
        for kpi in kpis:
            status_class = kpi.get('status', 'good')
            html += f"""
            <div class="metric">
                <strong>{kpi.get('name', 'Unknown')}</strong>: 
                <span class="{status_class}">{kpi.get('value', 0):.1f}{kpi.get('unit', '')}</span>
                ({kpi.get('trend', 'stable')} {kpi.get('trend_percentage', 0):.1f}%)
            </div>
            """
        
        # Threat Summary
        threat_summary = report_data.get('threat_summary', {})
        if threat_summary:
            html += "<h2>Threat Summary</h2>"
            html += f"""
            <div class="metric">
                <strong>Total Threats:</strong> {threat_summary.get('total_threats', 0)}<br>
                <strong>Detection Rate:</strong> {threat_summary.get('detection_rate', 0):.1f}%<br>
                <strong>Response Time:</strong> {threat_summary.get('response_time_avg', 0):.1f}s
            </div>
            """
        
        # Recommendations
        recommendations = report_data.get('recommendations', [])
        if recommendations:
            html += "<h2>Recommendations</h2><ul>"
            for rec in recommendations:
                html += f"<li>{rec}</li>"
            html += "</ul>"
        
        return html
    
    def format_compliance_report(self, report_data: Dict[str, Any]) -> str:
        """Format compliance report"""
        html = f"<h2>Compliance Overview</h2>"
        html += f"""
        <div class="metric">
            <strong>Framework:</strong> {report_data.get('framework', 'Unknown')}<br>
            <strong>Overall Score:</strong> {report_data.get('overall_score', 0):.1f}%<br>
            <strong>Compliant Requirements:</strong> {report_data.get('compliant_requirements', 0)}/{report_data.get('total_requirements', 0)}
        </div>
        """
        
        # Findings Summary
        findings_summary = report_data.get('findings_summary', {})
        if findings_summary:
            html += "<h2>Findings Summary</h2>"
            for severity, count in findings_summary.items():
                html += f"<div class='metric'><strong>{severity.title()}:</strong> {count}</div>"
        
        return html
    
    def format_trend_report(self, report_data: Dict[str, Any]) -> str:
        """Format trend report"""
        summary = report_data.get('summary', {})
        html = f"""
        <h2>Trend Analysis Summary</h2>
        <div class="metric">
            <strong>Metrics Analyzed:</strong> {summary.get('metrics_analyzed', 0)}<br>
            <strong>Trends Detected:</strong> {summary.get('trends_detected', 0)}<br>
            <strong>Anomalies Found:</strong> {summary.get('anomalies_found', 0)}<br>
            <strong>Forecasts Generated:</strong> {summary.get('forecasts_generated', 0)}
        </div>
        """
        
        # Trend analyses
        trend_analyses = report_data.get('trend_analyses', {})
        if trend_analyses:
            html += "<h2>Trend Analysis Results</h2>"
            html += "<table><tr><th>Metric</th><th>Direction</th><th>Strength</th><th>Change %</th></tr>"
            for metric, analysis in trend_analyses.items():
                html += f"""
                <tr>
                    <td>{metric}</td>
                    <td>{analysis.get('trend_direction', 'unknown')}</td>
                    <td>{analysis.get('trend_strength', 0):.2f}</td>
                    <td>{analysis.get('percentage_change', 0):.1f}%</td>
                </tr>
                """
            html += "</table>"
        
        return html
    
    def export_report(self):
        """Export current report"""
        if not self.current_report:
            QMessageBox.warning(self, "Warning", "No report to export")
            return
        
        try:
            from PyQt5.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Report", 
                f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json);;HTML Files (*.html)"
            )
            
            if filename:
                if filename.endswith('.html'):
                    # Export as HTML
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(self.content_area.toHtml())
                else:
                    # Export as JSON
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(self.current_report, f, indent=2)
                
                QMessageBox.information(self, "Success", f"Report exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {e}")
