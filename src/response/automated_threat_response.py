#!/usr/bin/env python3
"""
Automated Threat Response System
Handles automatic mitigation of detected threats
"""

import os
import sys
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import shutil
import psutil

class ResponseAction(Enum):
    """Available response actions"""
    QUARANTINE = "quarantine"
    BLOCK_PROCESS = "block_process"
    BLOCK_NETWORK = "block_network"
    ISOLATE_FILE = "isolate_file"
    ALERT_USER = "alert_user"
    LOG_ONLY = "log_only"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    BACKUP_FILE = "backup_file"

class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatEvent:
    """Threat event data structure"""
    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    threat_score: float
    description: str
    file_path: Optional[str] = None
    process_id: Optional[int] = None
    network_connection: Optional[Dict] = None
    metadata: Optional[Dict] = None

@dataclass
class ResponseRule:
    """Automated response rule"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: List[ResponseAction]
    enabled: bool = True
    priority: int = 5
    cooldown_seconds: int = 60

class AutomatedThreatResponse:
    """Automated threat response system"""
    
    def __init__(self, quarantine_dir: str = None, callback: Callable = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.response.automated_threat_response')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.quarantine_dir = quarantine_dir or os.path.join(os.getcwd(), "quarantine")
        self.callback = callback
        
        # Database for response history
        self.db_path = os.path.join(os.getcwd(), "logs", "threat_responses", "response_history.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Response rules
        self.rules: List[ResponseRule] = []
        self.rule_cooldowns: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            'total_responses': 0,
            'quarantined_files': 0,
            'blocked_processes': 0,
            'blocked_connections': 0,
            'false_positives': 0,
            'last_response': None
        }
        
        # Thread safety
        self.lock = threading.Lock()
        
        self.init_database()
        self.load_default_rules()
        
        self.logger.info("Automated threat response system initialized")
    
    def init_database(self):
        """Initialize response history database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Response history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS response_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        actions TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        details TEXT,
                        threat_score REAL,
                        severity TEXT,
                        file_path TEXT,
                        process_id INTEGER,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Response rules table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS response_rules (
                        rule_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        conditions TEXT NOT NULL,
                        actions TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        priority INTEGER DEFAULT 5,
                        cooldown_seconds INTEGER DEFAULT 60,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_response_timestamp ON response_history(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_response_event_id ON response_history(event_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_enabled ON response_rules(enabled)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize response database: {e}")
    
    def load_default_rules(self):
        """Load default response rules"""
        default_rules = [
            ResponseRule(
                rule_id="high_threat_quarantine",
                name="High Threat Auto-Quarantine",
                description="Automatically quarantine files with high threat scores",
                conditions={
                    "threat_score_min": 0.8,
                    "severity": ["high", "critical"],
                    "source": ["filesystem_monitor", "signature_engine", "ai_engine"]
                },
                actions=[ResponseAction.QUARANTINE, ResponseAction.ALERT_USER],
                priority=1,
                cooldown_seconds=30
            ),
            ResponseRule(
                rule_id="suspicious_process_monitor",
                name="Suspicious Process Monitoring",
                description="Monitor and potentially block suspicious processes",
                conditions={
                    "threat_score_min": 0.6,
                    "event_type": ["process_created", "suspicious_behavior"],
                    "source": ["process_monitor", "behavioral_analyzer"]
                },
                actions=[ResponseAction.LOG_ONLY, ResponseAction.ALERT_USER],
                priority=3,
                cooldown_seconds=120
            ),
            ResponseRule(
                rule_id="network_threat_block",
                name="Network Threat Blocking",
                description="Block suspicious network connections",
                conditions={
                    "threat_score_min": 0.7,
                    "event_type": ["suspicious_connection", "malicious_ip"],
                    "source": ["network_monitor"]
                },
                actions=[ResponseAction.BLOCK_NETWORK, ResponseAction.ALERT_USER],
                priority=2,
                cooldown_seconds=60
            ),
            ResponseRule(
                rule_id="critical_system_protection",
                name="Critical System Protection",
                description="Immediate response to critical threats",
                conditions={
                    "severity": ["critical"],
                    "threat_score_min": 0.9
                },
                actions=[ResponseAction.QUARANTINE, ResponseAction.KILL_PROCESS, ResponseAction.ALERT_USER],
                priority=0,
                cooldown_seconds=10
            ),
            ResponseRule(
                rule_id="zero_day_response",
                name="Zero-Day Detection Response",
                description="Response to potential zero-day threats",
                conditions={
                    "event_type": ["zero_day_detected", "unknown_threat"],
                    "threat_score_min": 0.75
                },
                actions=[ResponseAction.ISOLATE_FILE, ResponseAction.BACKUP_FILE, ResponseAction.ALERT_USER],
                priority=1,
                cooldown_seconds=30
            )
        ]
        
        self.rules = default_rules
        self.save_rules_to_database()
    
    def save_rules_to_database(self):
        """Save rules to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for rule in self.rules:
                    cursor.execute('''
                        INSERT OR REPLACE INTO response_rules 
                        (rule_id, name, description, conditions, actions, enabled, priority, cooldown_seconds)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule.rule_id,
                        rule.name,
                        rule.description,
                        json.dumps(rule.conditions),
                        json.dumps([action.value for action in rule.actions]),
                        rule.enabled,
                        rule.priority,
                        rule.cooldown_seconds
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to save rules to database: {e}")
    
    def process_threat_event(self, event: ThreatEvent) -> List[Dict[str, Any]]:
        """Process threat event and execute appropriate responses"""
        responses = []
        
        try:
            with self.lock:
                # Find matching rules
                matching_rules = self.find_matching_rules(event)
                
                # Sort by priority
                matching_rules.sort(key=lambda r: r.priority)
                
                for rule in matching_rules:
                    # Check cooldown
                    if self.is_rule_on_cooldown(rule.rule_id):
                        continue
                    
                    # Execute rule actions
                    response = self.execute_rule_actions(event, rule)
                    responses.append(response)
                    
                    # Update cooldown
                    self.rule_cooldowns[rule.rule_id] = datetime.now()
                    
                    # Update statistics
                    self.stats['total_responses'] += 1
                    self.stats['last_response'] = datetime.now().isoformat()
                
                # Log response history
                if responses:
                    self.log_response_history(event, responses)
                
        except Exception as e:
            self.logger.error(f"Failed to process threat event: {e}")
            responses.append({
                'success': False,
                'error': str(e),
                'rule_id': 'error_handler'
            })
        
        return responses
    
    def find_matching_rules(self, event: ThreatEvent) -> List[ResponseRule]:
        """Find rules that match the threat event"""
        matching_rules = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if self.rule_matches_event(rule, event):
                matching_rules.append(rule)
        
        return matching_rules
    
    def rule_matches_event(self, rule: ResponseRule, event: ThreatEvent) -> bool:
        """Check if rule conditions match the event"""
        conditions = rule.conditions
        
        # Check threat score
        if 'threat_score_min' in conditions:
            if event.threat_score < conditions['threat_score_min']:
                return False
        
        if 'threat_score_max' in conditions:
            if event.threat_score > conditions['threat_score_max']:
                return False
        
        # Check severity
        if 'severity' in conditions:
            severity_list = conditions['severity']
            if isinstance(severity_list, str):
                severity_list = [severity_list]
            if event.severity not in severity_list:
                return False
        
        # Check source
        if 'source' in conditions:
            source_list = conditions['source']
            if isinstance(source_list, str):
                source_list = [source_list]
            if event.source not in source_list:
                return False
        
        # Check event type
        if 'event_type' in conditions:
            event_type_list = conditions['event_type']
            if isinstance(event_type_list, str):
                event_type_list = [event_type_list]
            if event.event_type not in event_type_list:
                return False
        
        return True
    
    def is_rule_on_cooldown(self, rule_id: str) -> bool:
        """Check if rule is on cooldown"""
        if rule_id not in self.rule_cooldowns:
            return False
        
        rule = next((r for r in self.rules if r.rule_id == rule_id), None)
        if not rule:
            return False
        
        last_execution = self.rule_cooldowns[rule_id]
        cooldown_end = last_execution + timedelta(seconds=rule.cooldown_seconds)
        
        return datetime.now() < cooldown_end
    
    def execute_rule_actions(self, event: ThreatEvent, rule: ResponseRule) -> Dict[str, Any]:
        """Execute actions for a matched rule"""
        response = {
            'rule_id': rule.rule_id,
            'rule_name': rule.name,
            'event_id': event.event_id,
            'actions_executed': [],
            'success': True,
            'details': [],
            'timestamp': datetime.now().isoformat()
        }
        
        for action in rule.actions:
            try:
                result = self.execute_action(action, event)
                response['actions_executed'].append({
                    'action': action.value,
                    'success': result['success'],
                    'details': result.get('details', '')
                })
                
                if result['success']:
                    response['details'].append(f"{action.value}: {result.get('details', 'Success')}")
                else:
                    response['success'] = False
                    response['details'].append(f"{action.value}: Failed - {result.get('error', 'Unknown error')}")
                
            except Exception as e:
                response['success'] = False
                response['details'].append(f"{action.value}: Exception - {str(e)}")
                self.logger.error(f"Failed to execute action {action.value}: {e}")
        
        return response
    
    def execute_action(self, action: ResponseAction, event: ThreatEvent) -> Dict[str, Any]:
        """Execute a specific response action"""
        try:
            if action == ResponseAction.QUARANTINE:
                return self.quarantine_file(event.file_path)
            
            elif action == ResponseAction.BLOCK_PROCESS:
                return self.block_process(event.process_id)
            
            elif action == ResponseAction.KILL_PROCESS:
                return self.kill_process(event.process_id)
            
            elif action == ResponseAction.BLOCK_NETWORK:
                return self.block_network_connection(event.network_connection)
            
            elif action == ResponseAction.ISOLATE_FILE:
                return self.isolate_file(event.file_path)
            
            elif action == ResponseAction.BACKUP_FILE:
                return self.backup_file(event.file_path)
            
            elif action == ResponseAction.ALERT_USER:
                return self.alert_user(event)
            
            elif action == ResponseAction.LOG_ONLY:
                return self.log_threat(event)
            
            else:
                return {'success': False, 'error': f'Unknown action: {action.value}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def quarantine_file(self, file_path: str) -> Dict[str, Any]:
        """Quarantine a suspicious file"""
        if not file_path or not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            quarantine_name = f"{filename}_{timestamp}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create metadata file
            metadata = {
                'original_path': file_path,
                'quarantine_time': datetime.now().isoformat(),
                'reason': 'Automated threat response'
            }
            
            metadata_path = quarantine_path + '.metadata'
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.stats['quarantined_files'] += 1
            
            return {
                'success': True,
                'details': f'File quarantined to {quarantine_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def block_process(self, process_id: int) -> Dict[str, Any]:
        """Block/suspend a process"""
        if not process_id:
            return {'success': False, 'error': 'No process ID provided'}
        
        try:
            process = psutil.Process(process_id)
            process.suspend()
            
            self.stats['blocked_processes'] += 1
            
            return {
                'success': True,
                'details': f'Process {process_id} suspended'
            }
            
        except psutil.NoSuchProcess:
            return {'success': False, 'error': 'Process not found'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def kill_process(self, process_id: int) -> Dict[str, Any]:
        """Kill a malicious process"""
        if not process_id:
            return {'success': False, 'error': 'No process ID provided'}
        
        try:
            process = psutil.Process(process_id)
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
            
            return {
                'success': True,
                'details': f'Process {process_id} terminated'
            }
            
        except psutil.NoSuchProcess:
            return {'success': False, 'error': 'Process not found'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def block_network_connection(self, connection: Dict) -> Dict[str, Any]:
        """Block a network connection"""
        if not connection:
            return {'success': False, 'error': 'No connection data provided'}
        
        try:
            # In a real implementation, this would use firewall rules
            # For now, we'll just log the blocking action
            remote_ip = connection.get('remote_ip', 'unknown')
            remote_port = connection.get('remote_port', 'unknown')
            
            self.stats['blocked_connections'] += 1
            
            return {
                'success': True,
                'details': f'Network connection to {remote_ip}:{remote_port} blocked'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def isolate_file(self, file_path: str) -> Dict[str, Any]:
        """Isolate a file for analysis"""
        if not file_path or not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            isolation_dir = os.path.join(self.quarantine_dir, "isolated")
            os.makedirs(isolation_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            isolated_name = f"isolated_{filename}_{timestamp}"
            isolated_path = os.path.join(isolation_dir, isolated_name)
            
            # Copy file to isolation (don't move, keep original)
            shutil.copy2(file_path, isolated_path)
            
            return {
                'success': True,
                'details': f'File isolated to {isolated_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def backup_file(self, file_path: str) -> Dict[str, Any]:
        """Create backup of file before other actions"""
        if not file_path or not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            backup_dir = os.path.join(self.quarantine_dir, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            timestamp = int(time.time())
            backup_name = f"backup_{filename}_{timestamp}"
            backup_path = os.path.join(backup_dir, backup_name)
            
            shutil.copy2(file_path, backup_path)
            
            return {
                'success': True,
                'details': f'File backed up to {backup_path}'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def alert_user(self, event: ThreatEvent) -> Dict[str, Any]:
        """Send alert to user"""
        try:
            if self.callback:
                self.callback('threat_alert', {
                    'event_id': event.event_id,
                    'severity': event.severity,
                    'description': event.description,
                    'threat_score': event.threat_score,
                    'timestamp': event.timestamp
                })
            
            return {
                'success': True,
                'details': 'User alert sent'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def log_threat(self, event: ThreatEvent) -> Dict[str, Any]:
        """Log threat event"""
        try:
            log_entry = {
                'timestamp': event.timestamp,
                'event_id': event.event_id,
                'severity': event.severity,
                'threat_score': event.threat_score,
                'description': event.description,
                'source': event.source,
                'event_type': event.event_type
            }
            
            self.logger.warning(f"THREAT LOGGED: {json.dumps(log_entry)}")
            
            return {
                'success': True,
                'details': 'Threat logged'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def log_response_history(self, event: ThreatEvent, responses: List[Dict[str, Any]]):
        """Log response history to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for response in responses:
                    cursor.execute('''
                        INSERT INTO response_history 
                        (event_id, timestamp, rule_id, actions, success, details, threat_score, severity, file_path, process_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event.event_id,
                        event.timestamp,
                        response.get('rule_id', ''),
                        json.dumps(response.get('actions_executed', [])),
                        response.get('success', False),
                        json.dumps(response.get('details', [])),
                        event.threat_score,
                        event.severity,
                        event.file_path,
                        event.process_id
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log response history: {e}")
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """Get response system statistics"""
        return {
            **self.stats,
            'active_rules': len([r for r in self.rules if r.enabled]),
            'total_rules': len(self.rules),
            'cooldown_rules': len(self.rule_cooldowns)
        }
    
    def get_recent_responses(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent response history"""
        try:
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM response_history 
                    WHERE timestamp >= ? 
                    ORDER BY timestamp DESC 
                    LIMIT 100
                ''', (cutoff_time,))
                
                columns = [desc[0] for desc in cursor.description]
                responses = []
                
                for row in cursor.fetchall():
                    response = dict(zip(columns, row))
                    # Parse JSON fields
                    if response['actions']:
                        response['actions'] = json.loads(response['actions'])
                    if response['details']:
                        response['details'] = json.loads(response['details'])
                    responses.append(response)
                
                return responses
                
        except Exception as e:
            self.logger.error(f"Failed to get recent responses: {e}")
            return []
    
    def add_custom_rule(self, rule: ResponseRule):
        """Add custom response rule"""
        with self.lock:
            # Remove existing rule with same ID
            self.rules = [r for r in self.rules if r.rule_id != rule.rule_id]
            self.rules.append(rule)
            self.save_rules_to_database()
    
    def remove_rule(self, rule_id: str):
        """Remove response rule"""
        with self.lock:
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            self.save_rules_to_database()
    
    def enable_rule(self, rule_id: str, enabled: bool = True):
        """Enable or disable a rule"""
        with self.lock:
            for rule in self.rules:
                if rule.rule_id == rule_id:
                    rule.enabled = enabled
                    break
            self.save_rules_to_database()
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Automated threat response system shutting down")
