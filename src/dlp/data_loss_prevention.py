import os
import re
import time
import logging
import threading
import psutil
from typing import Dict, List, Set, Optional, Callable
from pathlib import Path
import json
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class DLPEngine:
    """Data Loss Prevention engine for monitoring sensitive data"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.dlp.data_loss_prevention')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.observers = []
        self.rules = self._load_dlp_rules()
        self.sensitive_patterns = self._load_sensitive_patterns()
        self.alert_callbacks = []
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'violations_detected': 0,
            'data_transfers_blocked': 0,
            'alerts_sent': 0
        }
        
    def start_monitoring(self):
        """Start DLP monitoring"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        
        # Monitor file system for data transfers
        self._start_file_monitoring()
        
        # Monitor network for data exfiltration
        self._start_network_monitoring()
        
        # Monitor USB/removable devices
        self._start_usb_monitoring()
        
        self.logger.info("DLP monitoring started")
    
    def start(self):
        """Start the DLP engine"""
        self.start_monitoring()
        
    def stop(self):
        """Stop the DLP engine"""
        self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop DLP monitoring"""
        self.is_monitoring = False
        
        # Stop file system observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        self.observers.clear()
        
        self.logger.info("DLP monitoring stopped")
    
    def add_alert_callback(self, callback: Callable):
        """Add callback for DLP alerts"""
        self.alert_callbacks.append(callback)
    
    def scan_file_for_sensitive_data(self, file_path: str) -> Dict:
        """Scan file for sensitive data patterns"""
        try:
            scan_result = {
                'file_path': file_path,
                'violations': [],
                'risk_level': 'low',
                'sensitive_data_found': False,
                'timestamp': time.time()
            }
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.csv']:
                return scan_result
            
            # Read and analyze file content
            content = self._read_file_safely(file_path)
            if not content:
                return scan_result
            
            # Check for sensitive patterns
            for pattern_name, pattern_info in self.sensitive_patterns.items():
                matches = self._find_pattern_matches(content, pattern_info)
                if matches:
                    scan_result['violations'].append({
                        'pattern': pattern_name,
                        'matches': len(matches),
                        'severity': pattern_info['severity'],
                        'description': pattern_info['description']
                    })
                    scan_result['sensitive_data_found'] = True
            
            # Calculate risk level
            scan_result['risk_level'] = self._calculate_risk_level(scan_result['violations'])
            
            self.stats['files_scanned'] += 1
            if scan_result['sensitive_data_found']:
                self.stats['violations_detected'] += 1
            
            return scan_result
            
        except Exception as e:
            self.logger.error(f"File scan error for {file_path}: {e}")
            return {
                'file_path': file_path,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def check_data_transfer(self, source_path: str, destination_path: str, 
                           transfer_type: str) -> Dict:
        """Check if data transfer should be allowed"""
        try:
            check_result = {
                'source': source_path,
                'destination': destination_path,
                'transfer_type': transfer_type,
                'allowed': True,
                'violations': [],
                'blocked_reason': None,
                'timestamp': time.time()
            }
            
            # Check transfer rules
            for rule in self.rules:
                if self._rule_applies(rule, source_path, destination_path, transfer_type):
                    violation = self._evaluate_rule(rule, source_path, destination_path)
                    if violation:
                        check_result['violations'].append(violation)
                        
                        if rule['action'] == 'block':
                            check_result['allowed'] = False
                            check_result['blocked_reason'] = violation['reason']
                            self.stats['data_transfers_blocked'] += 1
                            break
            
            # Send alert if violations found
            if check_result['violations']:
                self._send_dlp_alert(check_result)
            
            return check_result
            
        except Exception as e:
            self.logger.error(f"Data transfer check error: {e}")
            return {
                'allowed': True,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _start_file_monitoring(self):
        """Start monitoring file system for data transfers"""
        try:
            # Monitor common transfer locations
            monitor_paths = [
                os.path.expanduser("~\\Desktop"),
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Documents"),
                "C:\\Temp",
                "C:\\Windows\\Temp"
            ]
            
            for path in monitor_paths:
                if os.path.exists(path):
                    observer = Observer()
                    event_handler = DLPFileHandler(self)
                    observer.schedule(event_handler, path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
            
        except Exception as e:
            self.logger.error(f"File monitoring setup error: {e}")
    
    def _start_network_monitoring(self):
        """Start monitoring network for data exfiltration"""
        def network_monitor():
            while self.is_monitoring:
                try:
                    # Monitor network connections
                    connections = psutil.net_connections()
                    for conn in connections:
                        if conn.raddr and conn.status == 'ESTABLISHED':
                            self._check_network_connection(conn)
                    
                    time.sleep(10)  # Check every 10 seconds
                    
                except Exception as e:
                    self.logger.error(f"Network monitoring error: {e}")
        
        monitor_thread = threading.Thread(target=network_monitor, daemon=True)
        monitor_thread.start()
    
    def _start_usb_monitoring(self):
        """Start monitoring USB/removable device connections"""
        def usb_monitor():
            known_drives = set()
            
            while self.is_monitoring:
                try:
                    current_drives = set()
                    
                    # Check for removable drives
                    for partition in psutil.disk_partitions():
                        if 'removable' in partition.opts:
                            current_drives.add(partition.device)
                    
                    # Detect new removable drives
                    new_drives = current_drives - known_drives
                    for drive in new_drives:
                        self._handle_usb_connection(drive)
                    
                    known_drives = current_drives
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    self.logger.error(f"USB monitoring error: {e}")
        
        monitor_thread = threading.Thread(target=usb_monitor, daemon=True)
        monitor_thread.start()
    
    def _read_file_safely(self, file_path: str, max_size: int = 10 * 1024 * 1024) -> str:
        """Safely read file content with size limit"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                self.logger.warning(f"File too large for DLP scan: {file_path}")
                return ""
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
                
        except Exception as e:
            self.logger.error(f"File read error: {e}")
            return ""
    
    def _find_pattern_matches(self, content: str, pattern_info: Dict) -> List[str]:
        """Find matches for sensitive data pattern"""
        matches = []
        
        try:
            pattern = pattern_info['regex']
            flags = re.IGNORECASE if pattern_info.get('case_insensitive', True) else 0
            
            found_matches = re.findall(pattern, content, flags)
            
            # Validate matches if validator function exists
            if 'validator' in pattern_info:
                validator = pattern_info['validator']
                matches = [match for match in found_matches if validator(match)]
            else:
                matches = found_matches
                
        except Exception as e:
            self.logger.error(f"Pattern matching error: {e}")
        
        return matches
    
    def _calculate_risk_level(self, violations: List[Dict]) -> str:
        """Calculate overall risk level based on violations"""
        if not violations:
            return 'low'
        
        high_severity_count = sum(1 for v in violations if v['severity'] == 'high')
        medium_severity_count = sum(1 for v in violations if v['severity'] == 'medium')
        
        if high_severity_count > 0:
            return 'critical'
        elif medium_severity_count > 2:
            return 'high'
        elif medium_severity_count > 0:
            return 'medium'
        else:
            return 'low'
    
    def _rule_applies(self, rule: Dict, source: str, destination: str, transfer_type: str) -> bool:
        """Check if DLP rule applies to transfer"""
        # Check transfer type
        if rule.get('transfer_types') and transfer_type not in rule['transfer_types']:
            return False
        
        # Check source patterns
        if rule.get('source_patterns'):
            source_match = any(re.search(pattern, source, re.IGNORECASE) 
                             for pattern in rule['source_patterns'])
            if not source_match:
                return False
        
        # Check destination patterns
        if rule.get('destination_patterns'):
            dest_match = any(re.search(pattern, destination, re.IGNORECASE) 
                           for pattern in rule['destination_patterns'])
            if not dest_match:
                return False
        
        return True
    
    def _evaluate_rule(self, rule: Dict, source: str, destination: str) -> Optional[Dict]:
        """Evaluate DLP rule and return violation if found"""
        try:
            # Check file content if rule requires it
            if rule.get('scan_content', False):
                scan_result = self.scan_file_for_sensitive_data(source)
                if scan_result.get('sensitive_data_found', False):
                    return {
                        'rule_name': rule['name'],
                        'reason': f"Sensitive data found in file: {rule['description']}",
                        'severity': rule.get('severity', 'medium'),
                        'violations': scan_result['violations']
                    }
            
            # Check file size limits
            if rule.get('max_file_size'):
                try:
                    file_size = os.path.getsize(source)
                    if file_size > rule['max_file_size']:
                        return {
                            'rule_name': rule['name'],
                            'reason': f"File size exceeds limit: {file_size} bytes",
                            'severity': rule.get('severity', 'medium')
                        }
                except:
                    pass
            
            return None
            
        except Exception as e:
            self.logger.error(f"Rule evaluation error: {e}")
            return None
    
    def _check_network_connection(self, connection):
        """Check network connection for data exfiltration"""
        try:
            if connection.raddr:
                remote_ip = connection.raddr.ip
                remote_port = connection.raddr.port
                
                # Check for suspicious network activity
                if self._is_suspicious_connection(remote_ip, remote_port):
                    alert = {
                        'type': 'network_exfiltration',
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'local_port': connection.laddr.port,
                        'timestamp': time.time()
                    }
                    self._send_dlp_alert(alert)
        
        except Exception as e:
            self.logger.error(f"Network connection check error: {e}")
    
    def _handle_usb_connection(self, drive_path: str):
        """Handle USB device connection"""
        try:
            alert = {
                'type': 'usb_connection',
                'drive_path': drive_path,
                'timestamp': time.time(),
                'message': f"Removable device connected: {drive_path}"
            }
            self._send_dlp_alert(alert)
            
        except Exception as e:
            self.logger.error(f"USB connection handling error: {e}")
    
    def _is_suspicious_connection(self, ip: str, port: int) -> bool:
        """Check if network connection is suspicious"""
        # Skip localhost connections (too many false positives)
        if ip == '127.0.0.1' or ip == '::1':
            return False
        
        # Skip common legitimate services
        legitimate_ports = [80, 443, 53, 993, 995, 587, 465, 143, 110]
        if port in legitimate_ports:
            return False
        
        # Skip private IP ranges (internal network traffic)
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.'
        ]
        
        if any(ip.startswith(range_) for range_ in private_ranges):
            return False
        
        # Only flag truly suspicious connections
        # - Non-standard ports for data exfiltration
        # - Known malicious IP ranges (would need threat intel feed)
        suspicious_ports = [21, 22, 23, 25, 1337, 31337, 4444, 6666, 9999]
        
        return port in suspicious_ports or (port > 8000 and port < 9000)
    
    def _send_dlp_alert(self, alert_data: Dict):
        """Send DLP alert to registered callbacks"""
        try:
            for callback in self.alert_callbacks:
                callback(alert_data)
            
            self.stats['alerts_sent'] += 1
            self.logger.warning(f"DLP Alert: {alert_data}")
            
        except Exception as e:
            self.logger.error(f"Alert sending error: {e}")
    
    def _load_dlp_rules(self) -> List[Dict]:
        """Load DLP rules configuration"""
        return [
            {
                'name': 'USB Data Transfer',
                'description': 'Monitor data transfers to USB devices',
                'transfer_types': ['usb', 'removable'],
                'action': 'alert',
                'severity': 'medium',
                'scan_content': True
            },
            {
                'name': 'Large File Transfer',
                'description': 'Monitor large file transfers',
                'max_file_size': 100 * 1024 * 1024,  # 100MB
                'action': 'alert',
                'severity': 'low'
            },
            {
                'name': 'Email Attachment',
                'description': 'Monitor email attachments',
                'destination_patterns': ['.*@.*\\..*'],
                'action': 'alert',
                'severity': 'medium',
                'scan_content': True
            },
            {
                'name': 'Cloud Upload',
                'description': 'Monitor uploads to cloud services',
                'destination_patterns': [
                    '.*dropbox.*', '.*drive\\.google.*', '.*onedrive.*',
                    '.*icloud.*', '.*box\\.com.*'
                ],
                'action': 'alert',
                'severity': 'high',
                'scan_content': True
            }
        ]
    
    def _load_sensitive_patterns(self) -> Dict:
        """Load sensitive data patterns"""
        return {
            'credit_card': {
                'regex': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                'description': 'Credit card numbers',
                'severity': 'high',
                'validator': self._validate_credit_card
            },
            'ssn': {
                'regex': r'\b\d{3}-?\d{2}-?\d{4}\b',
                'description': 'Social Security Numbers',
                'severity': 'high'
            },
            'email': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email addresses',
                'severity': 'medium'
            },
            'phone': {
                'regex': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'description': 'Phone numbers',
                'severity': 'low'
            },
            'ip_address': {
                'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IP addresses',
                'severity': 'medium'
            },
            'password': {
                'regex': r'(?i)(password|pwd|pass)\s*[:=]\s*\S+',
                'description': 'Passwords in text',
                'severity': 'high'
            }
        }
    
    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        try:
            # Remove spaces and dashes
            number = re.sub(r'[-\s]', '', number)
            
            # Check if all digits
            if not number.isdigit():
                return False
            
            # Luhn algorithm
            digits = [int(d) for d in number]
            for i in range(len(digits) - 2, -1, -2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] -= 9
            
            return sum(digits) % 10 == 0
            
        except:
            return False
    
    def get_stats(self) -> Dict:
        """Get DLP statistics"""
        return self.stats.copy()

class DLPFileHandler(FileSystemEventHandler):
    """File system event handler for DLP monitoring"""
    
    def __init__(self, dlp_engine: DLPEngine):
        super().__init__()
        self.dlp_engine = dlp_engine
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.dlp.data_loss_prevention')
        except ImportError:
            self.logger = logging.getLogger(__name__)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._check_file_transfer(event.src_path, 'created')
    
    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            self._check_file_transfer(event.dest_path, 'moved')
    
    def _check_file_transfer(self, file_path: str, event_type: str):
        """Check file transfer for DLP violations"""
        try:
            # Check if file is in a monitored location
            path_lower = file_path.lower()
            
            # Check for transfers to removable media
            if any(drive in path_lower for drive in ['d:', 'e:', 'f:', 'g:']):
                # This is a simplified check - in reality would verify if drive is removable
                transfer_check = self.dlp_engine.check_data_transfer(
                    file_path, file_path, 'usb'
                )
                
                if not transfer_check['allowed']:
                    self.logger.warning(f"Blocked file transfer: {file_path}")
                    # In a real implementation, would actually block the transfer
            
        except Exception as e:
            self.logger.error(f"File transfer check error: {e}")
