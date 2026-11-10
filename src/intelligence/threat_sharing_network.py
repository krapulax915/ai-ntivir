#!/usr/bin/env python3
"""
Threat Sharing Network
Secure cloud-based threat intelligence sharing system
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import requests
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import hmac
import base64
from cryptography.fernet import Fernet

class ShareLevel(Enum):
    PRIVATE = "private"
    COMMUNITY = "community"
    PUBLIC = "public"
    EMERGENCY = "emergency"

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SharedThreat:
    threat_id: str
    threat_type: str
    severity: ThreatSeverity
    share_level: ShareLevel
    file_hash: str
    file_size: int
    detection_method: str
    confidence_score: float
    behavioral_indicators: List[str]
    network_indicators: List[str]
    file_indicators: List[str]
    timestamp: datetime
    source_id: str
    metadata: Dict[str, Any]

class ThreatSharingNetwork:
    """Secure threat intelligence sharing network"""
    
    def __init__(self, intelligence_engine=None, predictive_engine=None):
        self.intelligence_engine = intelligence_engine
        self.predictive_engine = predictive_engine
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.intelligence.threat_sharing_network')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Network configuration
        self.node_id = self.generate_node_id()
        self.node_name = f"AIAntivirus_{self.node_id[:8]}"
        self.version = "1.0.0"
        
        # Database for shared threats and network nodes
        self.db_path = os.path.join(os.path.dirname(__file__), "threat_sharing.db")
        self.init_database()
        
        # Encryption and security
        self.encryption_key = self.load_or_generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Network endpoints (configurable in production)
        self.sharing_endpoints = [
            "https://threat-intel.aintivirus.com/api/v1",
            "https://backup-intel.aintivirus.com/api/v1"
        ]
        
        # Network state
        self.connected_nodes = {}
        self.sharing_enabled = True
        self.auto_share = True
        
        # Background threads
        self.sharing_thread = None
        self.sync_thread = None
        self.running = False
        
        # Rate limiting
        self.last_share_time = {}
        self.share_rate_limit = 10  # max shares per minute
        
        # Statistics
        self.stats = {
            'threats_shared': 0,
            'threats_received': 0,
            'verified_threats': 0,
            'false_positives': 0,
            'network_nodes': 0,
            'last_sync': None
        }
        
        self.logger.info(f"Threat Sharing Network initialized - Node ID: {self.node_id}")
    
    def init_database(self):
        """Initialize SQLite database for threat sharing"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Shared threats table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS shared_threats (
                        threat_id TEXT PRIMARY KEY,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        share_level TEXT NOT NULL,
                        file_hash TEXT,
                        file_size INTEGER,
                        detection_method TEXT,
                        confidence_score REAL,
                        behavioral_indicators TEXT,
                        network_indicators TEXT,
                        file_indicators TEXT,
                        timestamp TIMESTAMP,
                        source_id TEXT,
                        metadata TEXT,
                        verified BOOLEAN DEFAULT 0,
                        false_positive BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Network nodes table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS network_nodes (
                        node_id TEXT PRIMARY KEY,
                        node_name TEXT,
                        version TEXT,
                        last_seen TIMESTAMP,
                        trust_score REAL DEFAULT 0.5,
                        shared_threats INTEGER DEFAULT 0,
                        verified_threats INTEGER DEFAULT 0,
                        false_positives INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Sharing history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sharing_history (
                        history_id TEXT PRIMARY KEY,
                        action_type TEXT NOT NULL,
                        threat_id TEXT,
                        node_id TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN,
                        error_message TEXT,
                        metadata TEXT
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_shared_threats_hash ON shared_threats(file_hash)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_shared_threats_timestamp ON shared_threats(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_nodes_trust ON network_nodes(trust_score)')
                
                conn.commit()
                self.logger.info("Threat sharing database initialized")
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
    
    def generate_node_id(self) -> str:
        """Generate unique node identifier"""
        try:
            import platform
            import uuid
            
            machine_info = f"{platform.node()}_{platform.machine()}_{uuid.getnode()}"
            node_hash = hashlib.sha256(machine_info.encode()).hexdigest()
            return node_hash[:16]  # 16-character node ID
            
        except Exception as e:
            self.logger.error(f"Node ID generation failed: {e}")
            return hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
    
    def load_or_generate_key(self) -> bytes:
        """Load or generate encryption key"""
        try:
            key_file = os.path.join(os.path.dirname(__file__), "network_key.key")
            
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                return key
                
        except Exception as e:
            self.logger.error(f"Key management failed: {e}")
            return Fernet.generate_key()
    
    def start(self):
        """Start threat sharing network"""
        try:
            if self.running:
                return
            
            self.running = True
            
            # Skip background threads for memory optimization
            self.sync_thread = None
            self.cleanup_thread = None
            self.logger.info("Background sync and cleanup threads disabled for memory optimization")
            
            # Register this node
            self.register_node()
            
            self.logger.info("Threat sharing network started")
            
        except Exception as e:
            self.logger.error(f"Failed to start threat sharing network: {e}")
    
    def stop(self):
        """Stop threat sharing network"""
        try:
            self.running = False
            
            if self.sharing_thread:
                self.sharing_thread.join(timeout=5)
            
            if self.sync_thread:
                self.sync_thread.join(timeout=5)
            
            self.logger.info("Threat sharing network stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping threat sharing network: {e}")
    
    def _sharing_loop(self):
        """Main sharing loop for outbound threat data"""
        try:
            while self.running:
                try:
                    if self.sharing_enabled and self.auto_share:
                        self.share_pending_threats()
                    
                    self.update_node_status()
                    time.sleep(30)  # 30-second interval
                    
                except Exception as e:
                    self.logger.error(f"Sharing loop error: {e}")
                    time.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"Sharing loop failed: {e}")
    
    def _sync_loop(self):
        """Main sync loop for inbound threat data"""
        try:
            while self.running:
                try:
                    if self.sharing_enabled:
                        self.sync_network_threats()
                        self.update_trust_scores()
                        self.cleanup_old_data()
                    
                    time.sleep(300)  # 5-minute interval
                    
                except Exception as e:
                    self.logger.error(f"Sync loop error: {e}")
                    time.sleep(120)
                    
        except Exception as e:
            self.logger.error(f"Sync loop failed: {e}")
    
    def share_threat(self, threat_data: Dict[str, Any], share_level: ShareLevel = ShareLevel.COMMUNITY) -> bool:
        """Share threat with network"""
        try:
            if not self.sharing_enabled:
                return False
            
            # Check rate limiting
            current_time = time.time()
            minute_key = int(current_time // 60)
            
            if minute_key in self.last_share_time:
                if self.last_share_time[minute_key] >= self.share_rate_limit:
                    self.logger.warning("Rate limit exceeded for threat sharing")
                    return False
                self.last_share_time[minute_key] += 1
            else:
                self.last_share_time = {minute_key: 1}
            
            # Create shared threat object
            shared_threat = self.create_shared_threat(threat_data, share_level)
            
            if not shared_threat:
                return False
            
            # Save to local database
            self.save_shared_threat(shared_threat)
            
            # Share with network endpoints
            success = self.send_to_network(shared_threat)
            
            if success:
                self.stats['threats_shared'] += 1
                self.log_sharing_action("share", shared_threat.threat_id, success=True)
                self.logger.info(f"Threat shared successfully: {shared_threat.threat_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Threat sharing failed: {e}")
            return False
    
    def create_shared_threat(self, threat_data: Dict[str, Any], share_level: ShareLevel) -> Optional[SharedThreat]:
        """Create shared threat object from threat data"""
        try:
            # Generate threat ID
            threat_content = f"{threat_data.get('file_path', '')}_{threat_data.get('threat_score', 0)}_{time.time()}"
            threat_id = hashlib.sha256(threat_content.encode()).hexdigest()
            
            # Determine severity
            threat_score = threat_data.get('threat_score', 0.0)
            if threat_score >= 0.9:
                severity = ThreatSeverity.CRITICAL
            elif threat_score >= 0.7:
                severity = ThreatSeverity.HIGH
            elif threat_score >= 0.5:
                severity = ThreatSeverity.MEDIUM
            else:
                severity = ThreatSeverity.LOW
            
            # Extract indicators
            behavioral_indicators = threat_data.get('behavioral_indicators', [])
            network_indicators = threat_data.get('network_indicators', [])
            file_indicators = threat_data.get('file_indicators', [])
            
            # Get file hash
            file_hash = threat_data.get('file_hash', '')
            if not file_hash and threat_data.get('file_path'):
                file_hash = self.calculate_file_hash(threat_data['file_path'])
            
            shared_threat = SharedThreat(
                threat_id=threat_id,
                threat_type=threat_data.get('threat_type', 'unknown'),
                severity=severity,
                share_level=share_level,
                file_hash=file_hash,
                file_size=threat_data.get('file_size', 0),
                detection_method=threat_data.get('detection_method', 'unknown'),
                confidence_score=threat_data.get('confidence_score', threat_score),
                behavioral_indicators=behavioral_indicators,
                network_indicators=network_indicators,
                file_indicators=file_indicators,
                timestamp=datetime.now(),
                source_id=self.node_id,
                metadata={
                    'version': self.version,
                    'classification': threat_data.get('classification', {}),
                    'scan_context': threat_data.get('scan_context', 'unknown')
                }
            )
            
            return shared_threat
            
        except Exception as e:
            self.logger.error(f"Shared threat creation failed: {e}")
            return None
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            if not os.path.exists(file_path):
                return ""
            
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return sha256_hash.hexdigest()
            
        except Exception as e:
            self.logger.debug(f"File hash calculation failed: {e}")
            return ""
    
    def save_shared_threat(self, shared_threat: SharedThreat):
        """Save shared threat to local database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO shared_threats 
                    (threat_id, threat_type, severity, share_level, file_hash, file_size,
                     detection_method, confidence_score, behavioral_indicators, network_indicators,
                     file_indicators, timestamp, source_id, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    shared_threat.threat_id,
                    shared_threat.threat_type,
                    shared_threat.severity.value,
                    shared_threat.share_level.value,
                    shared_threat.file_hash,
                    shared_threat.file_size,
                    shared_threat.detection_method,
                    shared_threat.confidence_score,
                    json.dumps(shared_threat.behavioral_indicators),
                    json.dumps(shared_threat.network_indicators),
                    json.dumps(shared_threat.file_indicators),
                    shared_threat.timestamp,
                    shared_threat.source_id,
                    json.dumps(shared_threat.metadata)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save shared threat: {e}")
    
    def send_to_network(self, shared_threat: SharedThreat) -> bool:
        """Send threat to network endpoints"""
        try:
            # Encrypt threat data
            threat_data = asdict(shared_threat)
            threat_data['timestamp'] = shared_threat.timestamp.isoformat()
            
            encrypted_data = self.encrypt_data(json.dumps(threat_data))
            
            # Prepare request payload
            payload = {
                'node_id': self.node_id,
                'node_name': self.node_name,
                'version': self.version,
                'data': encrypted_data,
                'signature': self.sign_data(encrypted_data)
            }
            
            # Try each endpoint
            for endpoint in self.sharing_endpoints:
                try:
                    response = requests.post(
                        f"{endpoint}/threats/share",
                        json=payload,
                        timeout=30,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 200:
                        return True
                        
                except requests.RequestException as e:
                    self.logger.warning(f"Failed to reach endpoint {endpoint}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            self.logger.error(f"Network send failed: {e}")
            return False
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt data for network transmission"""
        try:
            encrypted_bytes = self.cipher_suite.encrypt(data.encode())
            return base64.b64encode(encrypted_bytes).decode()
            
        except Exception as e:
            self.logger.error(f"Data encryption failed: {e}")
            return ""
    
    def sign_data(self, data: str) -> str:
        """Create HMAC signature for data"""
        try:
            signature = hmac.new(
                self.encryption_key,
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            return signature
            
        except Exception as e:
            self.logger.error(f"Data signing failed: {e}")
            return ""
    
    def share_pending_threats(self):
        """Share pending threats from intelligence engine"""
        try:
            if not self.intelligence_engine:
                return
            
            # Get recent high-confidence threats
            recent_threats = self.get_recent_threats_for_sharing()
            
            for threat in recent_threats:
                if not self.is_threat_shared(threat['threat_id']):
                    share_level = self.determine_share_level(threat)
                    self.share_threat(threat, share_level)
                    time.sleep(1)  # Rate limiting
            
        except Exception as e:
            self.logger.error(f"Pending threat sharing failed: {e}")
    
    def get_recent_threats_for_sharing(self) -> List[Dict[str, Any]]:
        """Get recent threats suitable for sharing"""
        try:
            # Placeholder - would integrate with intelligence engine
            return []
            
        except Exception as e:
            self.logger.error(f"Failed to get recent threats: {e}")
            return []
    
    def is_threat_shared(self, threat_id: str) -> bool:
        """Check if threat has already been shared"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT COUNT(*) FROM shared_threats 
                    WHERE threat_id = ? AND source_id = ?
                ''', (threat_id, self.node_id))
                
                count = cursor.fetchone()[0]
                return count > 0
                
        except Exception as e:
            return False
    
    def determine_share_level(self, threat: Dict[str, Any]) -> ShareLevel:
        """Determine appropriate sharing level for threat"""
        try:
            threat_score = threat.get('threat_score', 0.0)
            confidence = threat.get('confidence_score', 0.0)
            
            if threat_score >= 0.95 and confidence >= 0.9:
                return ShareLevel.EMERGENCY
            elif threat_score >= 0.8 and confidence >= 0.7:
                return ShareLevel.PUBLIC
            elif threat_score >= 0.6 and confidence >= 0.5:
                return ShareLevel.COMMUNITY
            else:
                return ShareLevel.PRIVATE
                
        except Exception as e:
            return ShareLevel.PRIVATE
    
    def sync_network_threats(self):
        """Sync threats from network"""
        try:
            for endpoint in self.sharing_endpoints:
                try:
                    response = requests.get(
                        f"{endpoint}/threats/sync",
                        params={
                            'node_id': self.node_id,
                            'since': self.get_last_sync_time().isoformat()
                        },
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        threats_data = response.json()
                        self.process_received_threats(threats_data.get('threats', []))
                        self.stats['last_sync'] = datetime.now()
                        break
                        
                except requests.RequestException as e:
                    self.logger.warning(f"Sync failed for endpoint {endpoint}: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Network threat sync failed: {e}")
    
    def get_last_sync_time(self) -> datetime:
        """Get last successful sync time"""
        try:
            if self.stats['last_sync']:
                return self.stats['last_sync']
            else:
                return datetime.now() - timedelta(hours=24)
                
        except Exception as e:
            return datetime.now() - timedelta(hours=24)
    
    def process_received_threats(self, threats: List[Dict[str, Any]]):
        """Process threats received from network"""
        try:
            for threat_data in threats:
                try:
                    if self.verify_received_threat(threat_data):
                        # Process valid threat
                        self.stats['threats_received'] += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to process received threat: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Received threat processing failed: {e}")
    
    def verify_received_threat(self, threat_data: Dict[str, Any]) -> bool:
        """Verify received threat data"""
        try:
            required_fields = ['node_id', 'data', 'signature']
            return all(field in threat_data for field in required_fields)
            
        except Exception as e:
            return False
    
    def register_node(self):
        """Register this node with the network"""
        try:
            node_data = {
                'node_id': self.node_id,
                'node_name': self.node_name,
                'version': self.version,
                'capabilities': ['threat_sharing', 'predictive_analysis'],
                'timestamp': datetime.now().isoformat()
            }
            
            for endpoint in self.sharing_endpoints:
                try:
                    response = requests.post(
                        f"{endpoint}/nodes/register",
                        json=node_data,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        self.logger.info(f"Node registered with {endpoint}")
                        break
                        
                except requests.RequestException as e:
                    self.logger.warning(f"Node registration failed for {endpoint}: {e}")
                    continue
            
        except Exception as e:
            self.logger.error(f"Node registration failed: {e}")
    
    def update_node_status(self):
        """Update node status with network"""
        try:
            status_data = {
                'node_id': self.node_id,
                'last_seen': datetime.now().isoformat(),
                'stats': self.stats,
                'health': 'healthy'
            }
            
            for endpoint in self.sharing_endpoints:
                try:
                    response = requests.put(
                        f"{endpoint}/nodes/{self.node_id}/status",
                        json=status_data,
                        timeout=15
                    )
                    
                    if response.status_code == 200:
                        break
                        
                except requests.RequestException:
                    continue
            
        except Exception as e:
            self.logger.error(f"Node status update failed: {e}")
    
    def update_trust_scores(self):
        """Update trust scores for network nodes"""
        try:
            # Placeholder for trust score calculation
            pass
            
        except Exception as e:
            self.logger.error(f"Trust score update failed: {e}")
    
    def cleanup_old_data(self):
        """Clean up old data from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Remove old shared threats (older than 30 days)
                cursor.execute('''
                    DELETE FROM shared_threats 
                    WHERE timestamp < datetime('now', '-30 days')
                ''')
                
                # Remove old sharing history (older than 7 days)
                cursor.execute('''
                    DELETE FROM sharing_history 
                    WHERE timestamp < datetime('now', '-7 days')
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Data cleanup failed: {e}")
    
    def log_sharing_action(self, action_type: str, threat_id: str, success: bool, error: str = None):
        """Log sharing action to history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                history_id = hashlib.md5(f"{action_type}_{threat_id}_{time.time()}".encode()).hexdigest()
                
                cursor.execute('''
                    INSERT INTO sharing_history 
                    (history_id, action_type, threat_id, node_id, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    history_id,
                    action_type,
                    threat_id,
                    self.node_id,
                    success,
                    error
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log sharing action: {e}")
    
    def get_sharing_statistics(self) -> Dict[str, Any]:
        """Get threat sharing statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get threat counts
                cursor.execute('SELECT COUNT(*) FROM shared_threats WHERE source_id = ?', (self.node_id,))
                local_threats = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM shared_threats WHERE source_id != ?', (self.node_id,))
                received_threats = cursor.fetchone()[0]
                
                # Get node count
                cursor.execute('SELECT COUNT(*) FROM network_nodes')
                node_count = cursor.fetchone()[0]
                
                return {
                    'local_threats_shared': local_threats,
                    'threats_received': received_threats,
                    'connected_nodes': node_count,
                    'sharing_enabled': self.sharing_enabled,
                    'auto_share': self.auto_share,
                    'node_id': self.node_id,
                    'node_name': self.node_name,
                    'last_sync': self.stats.get('last_sync'),
                    'network_status': 'active' if self.running else 'inactive'
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get sharing statistics: {e}")
            return {}
    
    def enable_sharing(self, enabled: bool):
        """Enable or disable threat sharing"""
        self.sharing_enabled = enabled
        self.logger.info(f"Threat sharing {'enabled' if enabled else 'disabled'}")
    
    def set_auto_share(self, auto_share: bool):
        """Enable or disable automatic threat sharing"""
        self.auto_share = auto_share
        self.logger.info(f"Auto-sharing {'enabled' if auto_share else 'disabled'}")
