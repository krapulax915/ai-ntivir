#!/usr/bin/env python3
"""
Traffic Pattern Analysis System
Advanced network traffic pattern recognition and analysis
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
import hashlib

try:
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import silhouette_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

@dataclass
class TrafficPattern:
    """Traffic pattern structure"""
    pattern_id: str
    pattern_type: str
    name: str
    description: str
    characteristics: Dict[str, Any]
    confidence: float
    frequency: int
    first_seen: float
    last_seen: float
    associated_ips: List[str]

@dataclass
class PatternMatch:
    """Pattern matching result"""
    match_id: str
    timestamp: float
    pattern_id: str
    confidence: float
    src_ip: str
    dst_ip: str
    evidence: Dict[str, Any]

class TrafficPatternAnalyzer:
    """Advanced traffic pattern analysis and recognition system"""
    
    def __init__(self, db_path: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.network.traffic_pattern_analyzer')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), "..", "..", "models", "traffic_patterns.db")
        
        # Initialize database
        self.init_database()
        
        # Pattern analysis settings
        self.analysis_window = 300  # 5 minutes
        self.pattern_threshold = 0.7
        self.min_pattern_frequency = 3
        
        # Traffic data storage
        self.traffic_sessions = defaultdict(list)
        self.connection_flows = defaultdict(dict)
        self.temporal_patterns = deque(maxlen=1000)
        
        # Known patterns
        self.known_patterns = {}
        self.load_known_patterns()
        
        # Analysis components
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.kmeans_model = None
        
        # Callbacks
        self.pattern_callbacks = []
        
        # Analysis thread
        self.analysis_running = False
        self.analysis_thread = None
        
        self.logger.info("Traffic Pattern Analyzer initialized")
    
    def init_database(self):
        """Initialize SQLite database for pattern analysis"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Traffic patterns table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS traffic_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_id TEXT UNIQUE,
                        pattern_type TEXT,
                        name TEXT,
                        description TEXT,
                        characteristics TEXT,
                        confidence REAL,
                        frequency INTEGER,
                        first_seen REAL,
                        last_seen REAL,
                        associated_ips TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Pattern matches table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pattern_matches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        match_id TEXT UNIQUE,
                        timestamp REAL,
                        pattern_id TEXT,
                        confidence REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        evidence TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_patterns_type ON traffic_patterns(pattern_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_matches_timestamp ON pattern_matches(timestamp)')
                
                conn.commit()
                
            self.logger.info("Traffic pattern analysis database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def load_known_patterns(self):
        """Load known traffic patterns from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT pattern_id, pattern_type, name, description, characteristics,
                           confidence, frequency, first_seen, last_seen, associated_ips
                    FROM traffic_patterns
                ''')
                
                for row in cursor.fetchall():
                    pattern = TrafficPattern(
                        pattern_id=row[0],
                        pattern_type=row[1],
                        name=row[2],
                        description=row[3],
                        characteristics=json.loads(row[4]) if row[4] else {},
                        confidence=row[5],
                        frequency=row[6],
                        first_seen=row[7],
                        last_seen=row[8],
                        associated_ips=json.loads(row[9]) if row[9] else []
                    )
                    self.known_patterns[pattern.pattern_id] = pattern
                
                # Create default patterns if none exist
                if not self.known_patterns:
                    self.create_default_patterns()
                
                self.logger.info(f"Loaded {len(self.known_patterns)} known patterns")
                
        except Exception as e:
            self.logger.error(f"Failed to load known patterns: {e}")
    
    def create_default_patterns(self):
        """Create default traffic patterns"""
        default_patterns = [
            {
                'pattern_id': 'port_scan',
                'pattern_type': 'suspicious',
                'name': 'Port Scanning',
                'description': 'Port scanning attack pattern',
                'characteristics': {
                    'multiple_ports': True,
                    'syn_packets': True,
                    'short_connections': True,
                    'sequential_ports': True
                }
            },
            {
                'pattern_id': 'ddos_attack',
                'pattern_type': 'malicious',
                'name': 'DDoS Attack',
                'description': 'Distributed denial of service attack',
                'characteristics': {
                    'high_packet_rate': True,
                    'multiple_sources': True,
                    'same_destination': True,
                    'small_packets': True
                }
            },
            {
                'pattern_id': 'data_exfiltration',
                'pattern_type': 'malicious',
                'name': 'Data Exfiltration',
                'description': 'Suspicious data exfiltration pattern',
                'characteristics': {
                    'large_outbound_transfer': True,
                    'unusual_hours': True,
                    'encrypted_traffic': True,
                    'external_destination': True
                }
            }
        ]
        
        try:
            for pattern_data in default_patterns:
                pattern = TrafficPattern(
                    pattern_id=pattern_data['pattern_id'],
                    pattern_type=pattern_data['pattern_type'],
                    name=pattern_data['name'],
                    description=pattern_data['description'],
                    characteristics=pattern_data['characteristics'],
                    confidence=0.8,
                    frequency=0,
                    first_seen=time.time(),
                    last_seen=time.time(),
                    associated_ips=[]
                )
                
                self.known_patterns[pattern.pattern_id] = pattern
                self.store_pattern(pattern)
            
            self.logger.info("Created default traffic patterns")
            
        except Exception as e:
            self.logger.error(f"Failed to create default patterns: {e}")
    
    def start_analysis(self):
        """Start continuous pattern analysis"""
        if self.analysis_running:
            self.logger.warning("Pattern analysis already running")
            return
        
        self.analysis_running = True
        self.analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        self.analysis_thread.start()
        
        self.logger.info("Started traffic pattern analysis")
    
    def stop_analysis(self):
        """Stop pattern analysis"""
        self.analysis_running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        self.logger.info("Stopped traffic pattern analysis")
    
    def _analysis_loop(self):
        """Main pattern analysis loop"""
        while self.analysis_running:
            try:
                self.analyze_current_patterns()
                time.sleep(60)  # Analyze every minute
                
            except Exception as e:
                self.logger.error(f"Pattern analysis loop error: {e}")
                time.sleep(120)  # Wait longer on error
    
    def add_traffic_data(self, packet_info):
        """Add traffic data for pattern analysis"""
        try:
            # Add to temporal patterns
            self.temporal_patterns.append({
                'timestamp': packet_info.timestamp,
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'protocol': packet_info.protocol,
                'size': packet_info.size,
                'src_port': getattr(packet_info, 'src_port', 0),
                'dst_port': getattr(packet_info, 'dst_port', 0)
            })
            
            # Analyze immediate patterns
            self.analyze_immediate_patterns(packet_info)
            
        except Exception as e:
            self.logger.error(f"Failed to add traffic data: {e}")
    
    def analyze_immediate_patterns(self, packet_info):
        """Analyze immediate traffic patterns"""
        try:
            # Check for port scanning
            self.detect_port_scanning(packet_info)
            
            # Check for DDoS patterns
            self.detect_ddos_patterns(packet_info)
            
            # Check for suspicious protocols
            self.detect_suspicious_protocols(packet_info)
            
        except Exception as e:
            self.logger.error(f"Immediate pattern analysis error: {e}")
    
    def detect_port_scanning(self, packet_info):
        """Detect port scanning patterns"""
        try:
            current_time = packet_info.timestamp
            window_start = current_time - 60  # 1 minute window
            
            # Count recent connections from same source to different ports
            recent_connections = defaultdict(set)
            
            for pattern in self.temporal_patterns:
                if (pattern['timestamp'] >= window_start and 
                    pattern['src_ip'] == packet_info.src_ip):
                    
                    dst_key = f"{pattern['dst_ip']}:{pattern['dst_port']}"
                    recent_connections[pattern['src_ip']].add(dst_key)
            
            # Check if this looks like port scanning
            if len(recent_connections[packet_info.src_ip]) > 10:  # More than 10 different destinations
                match = PatternMatch(
                    match_id=f"portscan_{int(current_time)}_{packet_info.src_ip}",
                    timestamp=current_time,
                    pattern_id='port_scan',
                    confidence=0.8,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    evidence={
                        'unique_destinations': len(recent_connections[packet_info.src_ip]),
                        'time_window': 60
                    }
                )
                self.handle_pattern_match(match)
            
        except Exception as e:
            self.logger.error(f"Port scan detection error: {e}")
    
    def detect_ddos_patterns(self, packet_info):
        """Detect DDoS attack patterns"""
        try:
            current_time = packet_info.timestamp
            window_start = current_time - 30  # 30 second window
            
            # Count packets to same destination
            target_packets = [
                p for p in self.temporal_patterns
                if (p['timestamp'] >= window_start and 
                    p['dst_ip'] == packet_info.dst_ip)
            ]
            
            # Count unique sources
            unique_sources = len(set(p['src_ip'] for p in target_packets))
            packet_rate = len(target_packets) / 30
            
            # Check for DDoS characteristics
            if packet_rate > 100 and unique_sources > 10:  # High rate from multiple sources
                match = PatternMatch(
                    match_id=f"ddos_{int(current_time)}_{packet_info.dst_ip}",
                    timestamp=current_time,
                    pattern_id='ddos_attack',
                    confidence=0.9,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    evidence={
                        'packet_rate': packet_rate,
                        'unique_sources': unique_sources,
                        'target_ip': packet_info.dst_ip
                    }
                )
                self.handle_pattern_match(match)
            
        except Exception as e:
            self.logger.error(f"DDoS detection error: {e}")
    
    def detect_suspicious_protocols(self, packet_info):
        """Detect suspicious protocol usage"""
        try:
            # Check for suspicious ports
            suspicious_ports = [4444, 6666, 1337, 31337, 12345, 54321]
            dst_port = getattr(packet_info, 'dst_port', 0)
            
            if dst_port in suspicious_ports:
                match = PatternMatch(
                    match_id=f"suspicious_port_{int(packet_info.timestamp)}_{dst_port}",
                    timestamp=packet_info.timestamp,
                    pattern_id='suspicious_protocol',
                    confidence=0.7,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    evidence={
                        'suspicious_port': dst_port,
                        'protocol': packet_info.protocol
                    }
                )
                self.handle_pattern_match(match)
            
        except Exception as e:
            self.logger.error(f"Suspicious protocol detection error: {e}")
    
    def analyze_current_patterns(self):
        """Analyze current traffic against known patterns"""
        try:
            current_time = time.time()
            window_start = current_time - self.analysis_window
            
            # Get recent traffic
            recent_traffic = [
                p for p in self.temporal_patterns
                if p['timestamp'] >= window_start
            ]
            
            if len(recent_traffic) < 10:
                return
            
            # Check for data exfiltration patterns
            self.detect_data_exfiltration(recent_traffic)
            
        except Exception as e:
            self.logger.error(f"Current pattern analysis error: {e}")
    
    def detect_data_exfiltration(self, traffic_data: List[Dict]):
        """Detect data exfiltration patterns"""
        try:
            # Look for large outbound transfers
            outbound_data = defaultdict(int)
            
            for packet in traffic_data:
                # Assume internal IPs start with 192.168, 10., or 172.16-31
                src_internal = self.is_internal_ip(packet['src_ip'])
                dst_internal = self.is_internal_ip(packet['dst_ip'])
                
                if src_internal and not dst_internal:  # Outbound traffic
                    outbound_data[packet['src_ip']] += packet['size']
            
            # Check for suspicious outbound volumes
            for src_ip, total_bytes in outbound_data.items():
                if total_bytes > 10000000:  # > 10MB outbound
                    match = PatternMatch(
                        match_id=f"exfiltration_{int(time.time())}_{src_ip}",
                        timestamp=time.time(),
                        pattern_id='data_exfiltration',
                        confidence=0.8,
                        src_ip=src_ip,
                        dst_ip="external",
                        evidence={
                            'outbound_bytes': total_bytes,
                            'pattern_type': 'data_exfiltration'
                        }
                    )
                    self.handle_pattern_match(match)
            
        except Exception as e:
            self.logger.error(f"Exfiltration detection error: {e}")
    
    def is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            return (ip.startswith('192.168.') or 
                    ip.startswith('10.') or 
                    ip.startswith('172.16.') or 
                    ip.startswith('172.17.') or 
                    ip.startswith('172.18.') or 
                    ip.startswith('172.19.') or 
                    ip.startswith('172.2') or 
                    ip.startswith('172.30.') or 
                    ip.startswith('172.31.') or
                    ip.startswith('127.'))
        except:
            return False
    
    def handle_pattern_match(self, match: PatternMatch):
        """Handle detected pattern match"""
        try:
            # Store match in database
            self.store_pattern_match(match)
            
            # Log pattern match
            self.logger.warning(
                f"Traffic pattern detected: {match.pattern_id} "
                f"from {match.src_ip} to {match.dst_ip} "
                f"(confidence: {match.confidence:.2f})"
            )
            
            # Notify callbacks
            for callback in self.pattern_callbacks:
                try:
                    callback(match)
                except Exception as e:
                    self.logger.error(f"Pattern callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle pattern match: {e}")
    
    def store_pattern(self, pattern: TrafficPattern):
        """Store traffic pattern in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO traffic_patterns 
                    (pattern_id, pattern_type, name, description, characteristics,
                     confidence, frequency, first_seen, last_seen, associated_ips)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id, pattern.pattern_type, pattern.name,
                    pattern.description, json.dumps(pattern.characteristics),
                    pattern.confidence, pattern.frequency, pattern.first_seen,
                    pattern.last_seen, json.dumps(pattern.associated_ips)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store pattern: {e}")
    
    def store_pattern_match(self, match: PatternMatch):
        """Store pattern match in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO pattern_matches 
                    (match_id, timestamp, pattern_id, confidence, src_ip, dst_ip, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    match.match_id, match.timestamp, match.pattern_id,
                    match.confidence, match.src_ip, match.dst_ip,
                    json.dumps(match.evidence)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store pattern match: {e}")
    
    def add_pattern_callback(self, callback):
        """Add pattern detection callback"""
        self.pattern_callbacks.append(callback)
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get pattern analysis statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Recent matches count
                recent_time = time.time() - 3600  # Last hour
                cursor.execute('''
                    SELECT COUNT(*) FROM pattern_matches WHERE timestamp >= ?
                ''', (recent_time,))
                recent_matches = cursor.fetchone()[0]
                
                # Matches by pattern
                cursor.execute('''
                    SELECT pattern_id, COUNT(*) 
                    FROM pattern_matches 
                    WHERE timestamp >= ? 
                    GROUP BY pattern_id
                ''', (recent_time,))
                pattern_counts = dict(cursor.fetchall())
                
                return {
                    'recent_matches': recent_matches,
                    'pattern_counts': pattern_counts,
                    'known_patterns': len(self.known_patterns),
                    'analysis_running': self.analysis_running,
                    'temporal_patterns_count': len(self.temporal_patterns)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def get_recent_matches(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent pattern matches"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT match_id, timestamp, pattern_id, confidence,
                           src_ip, dst_ip, evidence
                    FROM pattern_matches 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                matches = []
                for row in cursor.fetchall():
                    match_data = {
                        'match_id': row[0],
                        'timestamp': row[1],
                        'pattern_id': row[2],
                        'confidence': row[3],
                        'src_ip': row[4],
                        'dst_ip': row[5],
                        'evidence': json.loads(row[6]) if row[6] else {}
                    }
                    matches.append(match_data)
                
                return matches
                
        except Exception as e:
            self.logger.error(f"Failed to get recent matches: {e}")
            return []
    
    def get_recent_patterns(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent traffic patterns for GUI display"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT pattern_id, pattern_type, name, description,
                           confidence, frequency, last_seen
                    FROM traffic_patterns 
                    ORDER BY last_seen DESC 
                    LIMIT ?
                ''', (limit,))
                
                patterns = []
                for row in cursor.fetchall():
                    pattern_data = {
                        'pattern_id': row[0],
                        'pattern_type': row[1],
                        'name': row[2],
                        'description': row[3],
                        'confidence': row[4],
                        'frequency': row[5],
                        'last_seen': row[6]
                    }
                    patterns.append(pattern_data)
                
                return patterns
                
        except Exception as e:
            self.logger.error(f"Failed to get recent patterns: {e}")
            return []
