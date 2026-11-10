#!/usr/bin/env python3
"""
Minimal stub for deep_packet_inspector.py - disabled for performance
"""

import logging

class DeepPacketInspector:
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"{self.__class__.__name__} disabled for performance")
        self.threat_callbacks = []
    
    def start(self):
        pass
    
    def stop(self):
        pass
    
    def start_monitoring(self):
        pass
    
    def stop_monitoring(self):
        pass
    
    def add_threat_callback(self, callback):
        """Add threat detection callback"""
        pass
    
    def remove_threat_callback(self, callback):
        """Remove threat detection callback"""
        pass
    
    def start_capture(self, interface=None):
        """Start packet capture"""
        pass
    
    def stop_capture(self):
        """Stop packet capture"""
        pass
    
    def get_capture_statistics(self):
        """Get packet capture statistics"""
        return {
            'packets_captured': 0,
            'threats_detected': 0,
            'bytes_processed': 0,
            'capture_active': False,
            'interface': None
        }
    
    def get_recent_packets(self, limit=50):
        """Get recent captured packets"""
        return []

# Aliases for common class names
Deeppacketinspector = DeepPacketInspector
