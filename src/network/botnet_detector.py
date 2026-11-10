#!/usr/bin/env python3
"""
Botnet Communication Detection System
Advanced detection of botnet command & control communications
"""

import os
import sys
import json
import time
import logging
import sqlite3
import threading
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class BotnetSignature:
    """Botnet communication signature"""
    signature_id: str
    botnet_family: str
    communication_type: str
    patterns: List[str]
    ports: List[int]
    protocols: List[str]
    indicators: Dict[str, Any]
    severity: str
    confidence: float

@dataclass
class BotnetDetection:
    """Botnet detection result"""
    detection_id: str
    timestamp: float
    botnet_family: str
    communication_type: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    confidence: float
    evidence: Dict[str, Any]
    indicators: List[str]

class BotnetDetector:
    """Advanced botnet communication detection system"""
    
    def __init__(self, db_path: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.network.botnet_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), "..", "..", "models", "botnet_detection.db")
        
        # Initialize database
        self.init_database()
        
        # Detection settings
        self.analysis_window = 300  # 5 minutes
        self.beacon_threshold = 3  # Minimum beacons to detect
        
        # Communication tracking
        self.communication_sessions = defaultdict(list)
        self.beacon_patterns = defaultdict(list)
        self.dns_queries = deque(maxlen=1000)
        
        # Botnet signatures
        self.botnet_signatures = []
        self.load_botnet_signatures()
        
        # Known malicious domains/IPs
        self.malicious_domains = set()
        self.malicious_ips = set()
        self.load_threat_intelligence()
        
        # Callbacks
        self.detection_callbacks = []
        
        # Analysis thread
        self.analysis_running = False
        self.analysis_thread = None
        
        self.logger.info("Botnet Detector initialized")
    
    def init_database(self):
        """Initialize SQLite database for botnet detection"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Botnet signatures table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS botnet_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_id TEXT UNIQUE,
                        botnet_family TEXT,
                        communication_type TEXT,
                        patterns TEXT,
                        ports TEXT,
                        protocols TEXT,
                        indicators TEXT,
                        severity TEXT,
                        confidence REAL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Botnet detections table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS botnet_detections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        detection_id TEXT UNIQUE,
                        timestamp REAL,
                        botnet_family TEXT,
                        communication_type TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        protocol TEXT,
                        confidence REAL,
                        evidence TEXT,
                        indicators TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON botnet_detections(timestamp)')
                
                conn.commit()
                
            self.logger.info("Botnet detection database initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def load_botnet_signatures(self):
        """Load botnet signatures from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT signature_id, botnet_family, communication_type, patterns,
                           ports, protocols, indicators, severity, confidence
                    FROM botnet_signatures
                ''')
                
                self.botnet_signatures = []
                for row in cursor.fetchall():
                    signature = BotnetSignature(
                        signature_id=row[0],
                        botnet_family=row[1],
                        communication_type=row[2],
                        patterns=json.loads(row[3]) if row[3] else [],
                        ports=json.loads(row[4]) if row[4] else [],
                        protocols=json.loads(row[5]) if row[5] else [],
                        indicators=json.loads(row[6]) if row[6] else {},
                        severity=row[7],
                        confidence=row[8]
                    )
                    self.botnet_signatures.append(signature)
                
                # Create default signatures if none exist
                if not self.botnet_signatures:
                    self.create_default_signatures()
                
                self.logger.info(f"Loaded {len(self.botnet_signatures)} botnet signatures")
                
        except Exception as e:
            self.logger.error(f"Failed to load botnet signatures: {e}")
    
    def create_default_signatures(self):
        """Create default botnet signatures"""
        default_signatures = [
            {
                'signature_id': 'zeus_c2',
                'botnet_family': 'Zeus',
                'communication_type': 'command_control',
                'patterns': [r'POST.*\/[a-f0-9]{32}\.php', r'gate\.php'],
                'ports': [80, 443, 8080],
                'protocols': ['HTTP', 'HTTPS'],
                'indicators': {
                    'user_agent_patterns': ['Mozilla/4.0.*Windows NT'],
                    'uri_patterns': ['/gate.php', '/config.bin']
                },
                'severity': 'critical',
                'confidence': 0.9
            },
            {
                'signature_id': 'conficker_beacon',
                'botnet_family': 'Conficker',
                'communication_type': 'beacon',
                'patterns': [r'[a-z]{5,10}\.(com|net|org|info)'],
                'ports': [80, 443],
                'protocols': ['HTTP', 'HTTPS'],
                'indicators': {
                    'domain_generation': True,
                    'periodic_beacons': True
                },
                'severity': 'high',
                'confidence': 0.8
            },
            {
                'signature_id': 'mirai_scan',
                'botnet_family': 'Mirai',
                'communication_type': 'scanning',
                'patterns': [r'telnet.*23', r'ssh.*22'],
                'ports': [23, 22, 2323],
                'protocols': ['TCP'],
                'indicators': {
                    'brute_force': True,
                    'iot_targets': True
                },
                'severity': 'high',
                'confidence': 0.85
            }
        ]
        
        try:
            for sig_data in default_signatures:
                signature = BotnetSignature(**sig_data)
                self.botnet_signatures.append(signature)
                self.store_signature(signature)
            
            self.logger.info("Created default botnet signatures")
            
        except Exception as e:
            self.logger.error(f"Failed to create default signatures: {e}")
    
    def load_threat_intelligence(self):
        """Load threat intelligence data"""
        try:
            # Add some default malicious indicators
            self.malicious_domains.update([
                'malware-traffic-analysis.net',
                'zeus-tracker.abuse.ch',
                'feodotracker.abuse.ch'
            ])
            
            self.malicious_ips.update([
                '192.168.100.100',
                '10.0.0.100'
            ])
            
            self.logger.info(f"Loaded {len(self.malicious_domains)} malicious domains and {len(self.malicious_ips)} malicious IPs")
            
        except Exception as e:
            self.logger.error(f"Failed to load threat intelligence: {e}")
    
    def start_analysis(self):
        """Start continuous botnet analysis"""
        if self.analysis_running:
            self.logger.warning("Botnet analysis already running")
            return
        
        self.analysis_running = True
        self.analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True
        )
        self.analysis_thread.start()
        
        self.logger.info("Started botnet communication analysis")
    
    def stop_analysis(self):
        """Stop botnet analysis"""
        self.analysis_running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        self.logger.info("Stopped botnet communication analysis")
    
    def _analysis_loop(self):
        """Main botnet analysis loop"""
        while self.analysis_running:
            try:
                self.analyze_beacon_patterns()
                self.analyze_dga_domains()
                time.sleep(60)  # Analyze every minute
                
            except Exception as e:
                self.logger.error(f"Botnet analysis loop error: {e}")
                time.sleep(120)  # Wait longer on error
    
    def add_network_data(self, packet_info):
        """Add network data for botnet analysis"""
        try:
            # Track communication sessions
            self.track_communication_session(packet_info)
            
            # Analyze DNS queries
            if packet_info.protocol == 'UDP' and getattr(packet_info, 'dst_port', 0) == 53:
                self.analyze_dns_query(packet_info)
            
            # Check against botnet signatures
            self.check_botnet_signatures(packet_info)
            
        except Exception as e:
            self.logger.error(f"Failed to add network data: {e}")
    
    def track_communication_session(self, packet_info):
        """Track communication sessions for beacon analysis"""
        try:
            session_key = f"{packet_info.src_ip}:{packet_info.dst_ip}:{getattr(packet_info, 'dst_port', 0)}"
            current_time = packet_info.timestamp
            
            if session_key not in self.communication_sessions:
                self.communication_sessions[session_key] = {
                    'start_time': current_time,
                    'last_seen': current_time,
                    'packet_count': 0,
                    'intervals': [],
                    'src_ip': packet_info.src_ip,
                    'dst_ip': packet_info.dst_ip,
                    'dst_port': getattr(packet_info, 'dst_port', 0),
                    'protocol': packet_info.protocol
                }
            
            session = self.communication_sessions[session_key]
            
            # Calculate interval since last packet
            if session['last_seen'] > 0:
                interval = current_time - session['last_seen']
                session['intervals'].append(interval)
                
                # Keep only recent intervals
                if len(session['intervals']) > 50:
                    session['intervals'] = session['intervals'][-25:]
            
            session['last_seen'] = current_time
            session['packet_count'] += 1
            
        except Exception as e:
            self.logger.error(f"Failed to track communication session: {e}")
    
    def analyze_dns_query(self, packet_info):
        """Analyze DNS queries for suspicious patterns"""
        try:
            # Extract domain from DNS query (simplified)
            payload_str = packet_info.payload.decode('utf-8', errors='ignore')
            
            # Look for domain patterns in payload
            domain_patterns = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload_str)
            
            for domain in domain_patterns:
                self.dns_queries.append({
                    'timestamp': packet_info.timestamp,
                    'src_ip': packet_info.src_ip,
                    'domain': domain
                })
                
                # Check for DGA patterns
                if self.is_dga_domain(domain):
                    self.detect_dga_communication(packet_info, domain)
                
                # Check against threat intelligence
                if domain in self.malicious_domains:
                    self.detect_malicious_domain_communication(packet_info, domain)
            
        except Exception as e:
            self.logger.error(f"DNS query analysis error: {e}")
    
    def is_dga_domain(self, domain: str) -> bool:
        """Check if domain appears to be algorithmically generated"""
        try:
            domain_parts = domain.split('.')
            if len(domain_parts) < 2:
                return False
            
            subdomain = domain_parts[0]
            
            # Check for DGA characteristics
            if len(subdomain) < 6:
                return False
            
            # Calculate entropy
            entropy = self.calculate_entropy(subdomain)
            
            # DGA domains often have high entropy
            return entropy > 3.5 and len(subdomain) > 10
            
        except Exception as e:
            self.logger.error(f"DGA domain analysis error: {e}")
            return False
    
    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        try:
            import math
            
            char_counts = {}
            for char in string:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            entropy = 0
            string_length = len(string)
            
            for count in char_counts.values():
                probability = count / string_length
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            self.logger.error(f"Entropy calculation error: {e}")
            return 0.0
    
    def check_botnet_signatures(self, packet_info):
        """Check packet against botnet signatures"""
        try:
            dst_port = getattr(packet_info, 'dst_port', 0)
            
            for signature in self.botnet_signatures:
                # Check port match
                if signature.ports and dst_port not in signature.ports:
                    continue
                
                # Check protocol match
                if signature.protocols and packet_info.protocol not in signature.protocols:
                    continue
                
                # Check payload patterns
                payload_str = packet_info.payload.decode('utf-8', errors='ignore')
                
                for pattern in signature.patterns:
                    if re.search(pattern, payload_str, re.IGNORECASE):
                        self.detect_botnet_communication(packet_info, signature)
                        break
            
        except Exception as e:
            self.logger.error(f"Signature check error: {e}")
    
    def analyze_beacon_patterns(self):
        """Analyze communication sessions for beacon patterns"""
        try:
            current_time = time.time()
            
            for session_key, session in self.communication_sessions.items():
                if len(session['intervals']) < self.beacon_threshold:
                    continue
                
                # Calculate beacon score
                beacon_score = self.calculate_beacon_score(session['intervals'])
                
                if beacon_score > 0.7:  # High beacon score
                    detection = BotnetDetection(
                        detection_id=f"beacon_{int(current_time)}_{session_key}",
                        timestamp=current_time,
                        botnet_family="Unknown",
                        communication_type="beacon",
                        src_ip=session['src_ip'],
                        dst_ip=session['dst_ip'],
                        dst_port=session['dst_port'],
                        protocol=session['protocol'],
                        confidence=beacon_score,
                        evidence={
                            'beacon_score': beacon_score,
                            'interval_count': len(session['intervals'])
                        },
                        indicators=['regular_intervals', 'beacon_pattern']
                    )
                    
                    self.handle_botnet_detection(detection)
            
        except Exception as e:
            self.logger.error(f"Beacon pattern analysis error: {e}")
    
    def calculate_beacon_score(self, intervals: List[float]) -> float:
        """Calculate beacon score based on interval regularity"""
        try:
            if len(intervals) < 3:
                return 0.0
            
            import statistics
            
            mean_interval = statistics.mean(intervals)
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            
            # Calculate coefficient of variation
            cv = std_dev / mean_interval if mean_interval > 0 else float('inf')
            
            # Lower CV indicates more regular intervals (beacon-like)
            if cv < 0.1:
                return 0.9
            elif cv < 0.2:
                return 0.7
            elif cv < 0.5:
                return 0.5
            else:
                return 0.2
            
        except Exception as e:
            self.logger.error(f"Beacon score calculation error: {e}")
            return 0.0
    
    def analyze_dga_domains(self):
        """Analyze DNS queries for DGA patterns"""
        try:
            current_time = time.time()
            window_start = current_time - 300  # 5 minute window
            
            # Group recent DNS queries by source IP
            recent_queries = defaultdict(list)
            
            for query in self.dns_queries:
                if query['timestamp'] >= window_start:
                    recent_queries[query['src_ip']].append(query)
            
            # Analyze each source for DGA patterns
            for src_ip, queries in recent_queries.items():
                dga_domains = [q for q in queries if self.is_dga_domain(q['domain'])]
                
                if len(dga_domains) >= 3:  # Multiple DGA domains from same source
                    detection = BotnetDetection(
                        detection_id=f"dga_{int(current_time)}_{src_ip}",
                        timestamp=current_time,
                        botnet_family="Unknown",
                        communication_type="domain_generation",
                        src_ip=src_ip,
                        dst_ip="DNS_SERVER",
                        dst_port=53,
                        protocol="DNS",
                        confidence=0.8,
                        evidence={
                            'dga_domain_count': len(dga_domains),
                            'total_queries': len(queries)
                        },
                        indicators=['domain_generation_algorithm']
                    )
                    
                    self.handle_botnet_detection(detection)
            
        except Exception as e:
            self.logger.error(f"DGA domain analysis error: {e}")
    
    def detect_botnet_communication(self, packet_info, signature: BotnetSignature):
        """Detect botnet communication based on signature match"""
        try:
            detection = BotnetDetection(
                detection_id=f"sig_{int(packet_info.timestamp)}_{signature.signature_id}",
                timestamp=packet_info.timestamp,
                botnet_family=signature.botnet_family,
                communication_type=signature.communication_type,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                dst_port=getattr(packet_info, 'dst_port', 0),
                protocol=packet_info.protocol,
                confidence=signature.confidence,
                evidence={'signature_id': signature.signature_id},
                indicators=[signature.communication_type]
            )
            
            self.handle_botnet_detection(detection)
            
        except Exception as e:
            self.logger.error(f"Botnet communication detection error: {e}")
    
    def detect_dga_communication(self, packet_info, domain: str):
        """Detect DGA domain communication"""
        try:
            detection = BotnetDetection(
                detection_id=f"dga_domain_{int(packet_info.timestamp)}_{domain}",
                timestamp=packet_info.timestamp,
                botnet_family="Unknown",
                communication_type="domain_generation",
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                dst_port=getattr(packet_info, 'dst_port', 0),
                protocol=packet_info.protocol,
                confidence=0.7,
                evidence={'dga_domain': domain},
                indicators=['dga_domain']
            )
            
            self.handle_botnet_detection(detection)
            
        except Exception as e:
            self.logger.error(f"DGA communication detection error: {e}")
    
    def detect_malicious_domain_communication(self, packet_info, domain: str):
        """Detect communication with known malicious domain"""
        try:
            detection = BotnetDetection(
                detection_id=f"malicious_domain_{int(packet_info.timestamp)}_{domain}",
                timestamp=packet_info.timestamp,
                botnet_family="Unknown",
                communication_type="malicious_communication",
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                dst_port=getattr(packet_info, 'dst_port', 0),
                protocol=packet_info.protocol,
                confidence=0.9,
                evidence={'malicious_domain': domain},
                indicators=['known_malicious_domain']
            )
            
            self.handle_botnet_detection(detection)
            
        except Exception as e:
            self.logger.error(f"Malicious domain detection error: {e}")
    
    def handle_botnet_detection(self, detection: BotnetDetection):
        """Handle detected botnet communication"""
        try:
            # Store detection in database
            self.store_detection(detection)
            
            # Log detection
            self.logger.warning(
                f"Botnet communication detected: {detection.botnet_family} "
                f"{detection.communication_type} from {detection.src_ip} "
                f"(confidence: {detection.confidence:.2f})"
            )
            
            # Notify callbacks
            for callback in self.detection_callbacks:
                try:
                    callback(detection)
                except Exception as e:
                    self.logger.error(f"Detection callback error: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle botnet detection: {e}")
    
    def store_signature(self, signature: BotnetSignature):
        """Store botnet signature in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO botnet_signatures 
                    (signature_id, botnet_family, communication_type, patterns,
                     ports, protocols, indicators, severity, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    signature.signature_id, signature.botnet_family,
                    signature.communication_type, json.dumps(signature.patterns),
                    json.dumps(signature.ports), json.dumps(signature.protocols),
                    json.dumps(signature.indicators), signature.severity,
                    signature.confidence
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store signature: {e}")
    
    def store_detection(self, detection: BotnetDetection):
        """Store botnet detection in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO botnet_detections 
                    (detection_id, timestamp, botnet_family, communication_type,
                     src_ip, dst_ip, dst_port, protocol, confidence, evidence, indicators)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    detection.detection_id, detection.timestamp, detection.botnet_family,
                    detection.communication_type, detection.src_ip, detection.dst_ip,
                    detection.dst_port, detection.protocol, detection.confidence,
                    json.dumps(detection.evidence), json.dumps(detection.indicators)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store detection: {e}")
    
    def add_detection_callback(self, callback):
        """Add botnet detection callback"""
        self.detection_callbacks.append(callback)
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get botnet detection statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Recent detections count
                recent_time = time.time() - 3600  # Last hour
                cursor.execute('''
                    SELECT COUNT(*) FROM botnet_detections WHERE timestamp >= ?
                ''', (recent_time,))
                recent_detections = cursor.fetchone()[0]
                
                # Detections by family
                cursor.execute('''
                    SELECT botnet_family, COUNT(*) 
                    FROM botnet_detections 
                    WHERE timestamp >= ? 
                    GROUP BY botnet_family
                ''', (recent_time,))
                family_counts = dict(cursor.fetchall())
                
                return {
                    'recent_detections': recent_detections,
                    'family_counts': family_counts,
                    'signatures_loaded': len(self.botnet_signatures),
                    'analysis_running': self.analysis_running,
                    'communication_sessions': len(self.communication_sessions)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def get_recent_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent botnet detections"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT detection_id, timestamp, botnet_family, communication_type,
                           src_ip, dst_ip, dst_port, protocol, confidence, evidence, indicators
                    FROM botnet_detections 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                detections = []
                for row in cursor.fetchall():
                    detection_data = {
                        'detection_id': row[0],
                        'timestamp': row[1],
                        'botnet_family': row[2],
                        'communication_type': row[3],
                        'src_ip': row[4],
                        'dst_ip': row[5],
                        'dst_port': row[6],
                        'protocol': row[7],
                        'confidence': row[8],
                        'evidence': json.loads(row[9]) if row[9] else {},
                        'indicators': json.loads(row[10]) if row[10] else []
                    }
                    detections.append(detection_data)
                
                return detections
                
        except Exception as e:
            self.logger.error(f"Failed to get recent detections: {e}")
            return []
