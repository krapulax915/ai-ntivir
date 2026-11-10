# Real-time Monitoring Service
import threading
import time
from .realtime_monitoring import RealTimeFileMonitor
from ..core.ai_engine import AIEngine
from ..detection.signature_engine import SignatureEngine
from ..detection.anomaly_detector import AnomalyDetector

class MonitoringService:
    """Real-time monitoring service for main application"""
    
    def __init__(self):
        self.ai_engine = AIEngine()
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        
        self.monitor = RealTimeFileMonitor(
            self.ai_engine, 
            self.signature_engine, 
            self.anomaly_detector
        )
        
        self.running = False
    
    def start(self):
        """Start monitoring service"""
        if not self.running:
            success = self.monitor.start_monitoring()
            if success:
                self.running = True
                return True
        return False
    
    def stop(self):
        """Stop monitoring service"""
        if self.running:
            self.monitor.stop_monitoring()
            self.running = False
    
    def get_stats(self):
        """Get monitoring statistics"""
        return self.monitor.get_monitoring_stats()
    
    def is_running(self):
        """Check if monitoring is running"""
        return self.running
