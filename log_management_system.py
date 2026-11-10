#!/usr/bin/env python3
"""
Log Management System for AI Antivirus
Handles log file creation, cleanup, and central server uploads
"""

import os
import sys
import time
import json
import glob
import shutil
import logging
import threading
# FIX: removed the unused 'requests' import - the module is imported
# unconditionally at application startup and performed no network calls.
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib

class LogManagementSystem:
    """Comprehensive log management system"""

    # FIX: class-level guard attribute for _start_cleanup_timer (see below).
    _cleanup_started = False

    def __init__(self, log_dir: Optional[str] = None):
        """
        FIX: accept an optional log_dir parameter (tests redirect logs via this
        kwarg; previously the constructor took no arguments at all).
        """
        self.logger = logging.getLogger(__name__)
        self.log_retention_hours = 24
        self.central_server_url = "https://ai-antivirus-central.com/api/logs"

        # FIX: the log directory used to be a CWD-relative path into the
        # developer's 'logok' test folder. Under C:\Program Files\AI_Antivirus it
        # tried to create 'C:\Program Files\logok' (PermissionError, silently
        # swallowed) so every threat/scan log was silently lost. Anchor to
        # %PROGRAMDATA%\AI_Antivirus\logs by default.
        if log_dir:
            self.log_directory = os.path.abspath(log_dir)
        else:
            self.log_directory = os.path.join(
                os.environ.get('PROGRAMDATA', os.path.dirname(os.path.abspath(__file__))),
                'AI_Antivirus', 'logs')

        # FIX: consent file was written to CWD; anchor it to the log directory
        self.user_consent_file = os.path.join(self.log_directory, 'user_consent.json')
        
        # Initialize log management
        self._init_log_management()
        
        # Start cleanup timer
        self._start_cleanup_timer()

    def _init_log_management(self):
        """Initialize log management system"""
        try:
            # Create log directories
            os.makedirs(self.log_directory, exist_ok=True)
            os.makedirs(os.path.join(self.log_directory, 'scan_logs'), exist_ok=True)
            os.makedirs(os.path.join(self.log_directory, 'threat_logs'), exist_ok=True)
            os.makedirs(os.path.join(self.log_directory, 'system_logs'), exist_ok=True)
            
            # Create initial log files if they don't exist
            threat_log_file = os.path.join(self.log_directory, 'threat_logs', 'threats.log')
            system_log_file = os.path.join(self.log_directory, 'system_logs', 'system.log')
            
            if not os.path.exists(threat_log_file):
                with open(threat_log_file, 'w') as f:
                    f.write(f"# Threat Log - Created {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
            if not os.path.exists(system_log_file):
                with open(system_log_file, 'w') as f:
                    f.write(f"# System Log - Created {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            self.logger.info("📁 Log management system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize log management: {e}")
    
    def log_threat_detection(self, threat_data: Dict[str, Any]):
        """Log threat detection to threat log"""
        try:
            threat_log_file = f"{self.log_directory}/threat_logs/threats.log"
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            with open(threat_log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n[{timestamp}] THREAT DETECTED\n")
                f.write(f"File: {threat_data.get('file_path', 'Unknown')}\n")
                f.write(f"Threat Level: {threat_data.get('threat_level', 'Unknown')}\n")
                f.write(f"Threat Type: {threat_data.get('threat_type', 'Unknown')}\n")
                f.write(f"Detection Method: {threat_data.get('detection_method', 'Unknown')}\n")
                f.write(f"Threat Score: {threat_data.get('threat_score', 0.0)}\n")
                f.write(f"Action Taken: {threat_data.get('action', 'None')}\n")
                f.write("-" * 50 + "\n")
                
            self.logger.info(f"🚨 Threat logged: {threat_data.get('file_path', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"Failed to log threat: {e}")
    
    def log_system_event(self, event_data: Dict[str, Any]):
        """Log system event to system log"""
        try:
            system_log_file = f"{self.log_directory}/system_logs/system.log"
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            with open(system_log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n[{timestamp}] SYSTEM EVENT\n")
                f.write(f"Event Type: {event_data.get('event_type', 'Unknown')}\n")
                f.write(f"Component: {event_data.get('component', 'Unknown')}\n")
                f.write(f"Description: {event_data.get('description', 'No description')}\n")
                f.write(f"Severity: {event_data.get('severity', 'INFO')}\n")
                if 'details' in event_data:
                    f.write(f"Details: {event_data['details']}\n")
                f.write("-" * 50 + "\n")
                
            self.logger.info(f"📋 System event logged: {event_data.get('event_type', 'Unknown')}")
            
        except Exception as e:
            self.logger.error(f"Failed to log system event: {e}")

    def create_scan_log(self, scan_type: str, scan_data: Dict[str, Any]) -> str:
        """Create detailed log file for any scan type"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_filename = f"{self.log_directory}/scan_logs/{scan_type}_scan_{timestamp}.log"
            
            # FIX: derive the logger name from the log file basename so that
            # log_scan_progress()/finalize_scan_log() (which rebuild the name
            # from the basename) find the SAME logger. Previously the names
            # differed and scan progress/summary were never written to the file.
            scan_logger = logging.getLogger(f"scan_{os.path.basename(log_filename).replace('.log', '')}")
            scan_logger.setLevel(logging.DEBUG)
            
            # Create file handler
            file_handler = logging.FileHandler(log_filename, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            scan_logger.addHandler(file_handler)
            
            # Log scan header
            scan_logger.info("=" * 80)
            scan_logger.info(f"AI ANTIVIRUS - {scan_type.upper()} SCAN LOG")
            scan_logger.info("=" * 80)
            scan_logger.info(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            scan_logger.info(f"Scan type: {scan_type}")
            scan_logger.info(f"Log file: {log_filename}")
            scan_logger.info("-" * 80)
            
            # Log scan configuration
            if 'config' in scan_data:
                scan_logger.info("SCAN CONFIGURATION:")
                for key, value in scan_data['config'].items():
                    scan_logger.info(f"  {key}: {value}")
                scan_logger.info("-" * 80)
            
            # Log scan areas/targets
            if 'targets' in scan_data:
                scan_logger.info("SCAN TARGETS:")
                for target in scan_data['targets']:
                    scan_logger.info(f"  - {target}")
                scan_logger.info("-" * 80)
            
            # FIX: write the scan data itself so the log content contains
            # e.g. 'files_scanned' even before finalize_scan_log is called
            try:
                scan_logger.info("SCAN DATA: " + json.dumps(scan_data, default=str))
            except Exception:
                pass

            self.logger.info(f"📄 Created scan log: {log_filename}")

            # FIX: persist the scan data as a JSON sidecar so get_scan_logs() /
            # get_latest_scan_log() can return structured results.
            try:
                json_path = log_filename + '.json'
                with open(json_path, 'w', encoding='utf-8') as jf:
                    json.dump({'scan_type': scan_type, **scan_data}, jf, indent=2, default=str)
            except Exception as e:
                self.logger.error(f"Failed to write scan log JSON sidecar: {e}")

            return log_filename
            
        except Exception as e:
            self.logger.error(f"Failed to create scan log: {e}")
            return None
    
    def log_scan_progress(self, log_filename: str, progress_data: Dict[str, Any]):
        """Log scan progress to existing log file"""
        try:
            if not os.path.exists(log_filename):
                return
            
            # Get logger for this log file
            log_id = os.path.basename(log_filename).replace('.log', '')
            scan_logger = logging.getLogger(f"scan_{log_id}")
            
            if 'current_file' in progress_data:
                scan_logger.info(f"🔍 Scanning: {progress_data['current_file']}")
            
            if 'current_directory' in progress_data:
                scan_logger.info(f"📁 Directory: {progress_data['current_directory']}")

            if 'current_status' in progress_data:
                scan_logger.info(f"ℹ️ Status: {progress_data['current_status']}")

            if 'progress' in progress_data:
                scan_logger.info(f"📊 Progress: {progress_data['progress']}%")
            
            if 'threat_detected' in progress_data:
                threat = progress_data['threat_detected']
                scan_logger.warning(f"🚨 THREAT DETECTED: {threat['file_path']}")
                scan_logger.warning(f"   Threat Level: {threat.get('threat_level', 'Unknown')}")
                scan_logger.warning(f"   Detection Method: {threat.get('detection_method', 'Unknown')}")
                scan_logger.warning(f"   Threat Score: {threat.get('threat_score', 0.0)}")
            
            if 'suspicious_file' in progress_data:
                suspicious = progress_data['suspicious_file']
                scan_logger.warning(f"⚠️ SUSPICIOUS: {suspicious['file_path']}")
                scan_logger.warning(f"   Suspicion Score: {suspicious.get('suspicion_score', 0.0)}")
            
        except Exception as e:
            self.logger.error(f"Failed to log scan progress: {e}")
    
    def finalize_scan_log(self, log_filename: str, scan_results: Dict[str, Any]):
        """Finalize scan log with results summary"""
        try:
            if not os.path.exists(log_filename):
                return
            
            # Get logger for this log file
            log_id = os.path.basename(log_filename).replace('.log', '')
            scan_logger = logging.getLogger(f"scan_{log_id}")
            
            # Log final results
            scan_logger.info("=" * 80)
            scan_logger.info("SCAN COMPLETED - FINAL SUMMARY")
            scan_logger.info("=" * 80)
            
            summary = scan_results.get('summary', {})
            scan_logger.info(f"Scan duration: {summary.get('scan_time', 0):.2f} seconds")
            scan_logger.info(f"Files scanned: {summary.get('files_scanned', 0)}")
            scan_logger.info(f"Threats found: {summary.get('threats_found', 0)}")
            scan_logger.info(f"Suspicious files: {summary.get('suspicious_files', 0)}")
            
            if 'areas_scanned' in summary:
                scan_logger.info(f"Areas scanned: {', '.join(summary['areas_scanned'])}")
            
            # Log threats in detail
            if 'threats' in scan_results and scan_results['threats']:
                scan_logger.info("-" * 80)
                scan_logger.info("THREATS DETECTED:")
                for i, threat in enumerate(scan_results['threats'], 1):
                    scan_logger.warning(f"{i}. {threat.get('file_path', 'Unknown')}")
                    scan_logger.warning(f"   Type: {threat.get('threat_type', 'Unknown')}")
                    scan_logger.warning(f"   Level: {threat.get('threat_level', 'Unknown')}")
                    scan_logger.warning(f"   Action: {threat.get('action_taken', 'None')}")
            
            scan_logger.info("=" * 80)
            scan_logger.info(f"Log completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # FIX: close and remove the handlers so the log file is flushed and
            # the file handle is released (previously it stayed open forever).
            for h in scan_logger.handlers[:]:
                try:
                    h.close()
                except Exception:
                    pass
                scan_logger.removeHandler(h)

            # Check if we need to upload logs due to threats
            if summary.get('threats_found', 0) > 0:
                self._trigger_log_upload_check(log_filename, scan_results)
            
        except Exception as e:
            self.logger.error(f"Failed to finalize scan log: {e}")
    
    def get_scan_logs(self) -> List[str]:
        """
        FIX: new accessor - list all scan log files (.log and .json) in the
        scan_logs directory, oldest first.
        """
        try:
            scan_dir = f"{self.log_directory}/scan_logs"
            return sorted(glob.glob(f"{scan_dir}/*.log") + glob.glob(f"{scan_dir}/*.json"))
        except Exception as e:
            self.logger.error(f"Failed to list scan logs: {e}")
            return []

    def get_latest_scan_log(self) -> Optional[Dict[str, Any]]:
        """
        FIX: new accessor - parse the newest scan log JSON sidecar and return it
        as a dict (None if there are no scan logs).
        """
        try:
            json_files = [f for f in self.get_scan_logs() if f.endswith('.json')]
            if not json_files:
                return None
            with open(json_files[-1], 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to read latest scan log: {e}")
            return None

    def create_threat_log(self, threat_data: Dict[str, Any]) -> str:
        """Create specific log for threat detection"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_filename = f"{self.log_directory}/threat_logs/threat_detection_{timestamp}.log"
            
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("AI ANTIVIRUS - THREAT DETECTION LOG\n")
                f.write("=" * 80 + "\n")
                f.write(f"Detection time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Log file: {log_filename}\n")
                f.write("-" * 80 + "\n")
                
                f.write("THREAT DETAILS:\n")
                f.write(f"File path: {threat_data.get('file_path', 'Unknown')}\n")
                f.write(f"Threat type: {threat_data.get('threat_type', 'Unknown')}\n")
                f.write(f"Threat level: {threat_data.get('threat_level', 'Unknown')}\n")
                f.write(f"Detection method: {threat_data.get('detection_method', 'Unknown')}\n")
                f.write(f"Threat score: {threat_data.get('threat_score', 0.0)}\n")
                f.write(f"File size: {threat_data.get('file_size', 0)} bytes\n")
                f.write(f"File hash: {threat_data.get('file_hash', 'Unknown')}\n")
                
                if 'additional_info' in threat_data:
                    f.write("-" * 80 + "\n")
                    f.write("ADDITIONAL INFORMATION:\n")
                    for key, value in threat_data['additional_info'].items():
                        f.write(f"{key}: {value}\n")
                
                f.write("=" * 80 + "\n")
            
            self.logger.info(f"🚨 Created threat log: {log_filename}")
            return log_filename
            
        except Exception as e:
            self.logger.error(f"Failed to create threat log: {e}")
            return None
    
    def cleanup_old_logs(self):
        """Remove log files older than retention period"""
        try:
            current_time = time.time()
            retention_seconds = self.log_retention_hours * 3600
            
            # FIX: patterns are now anchored to self.log_directory (previously
            # two patterns were CWD-relative and scanned the working directory).
            log_patterns = [
                f"{self.log_directory}/**/*.log",
                f"{self.log_directory}/**/*.json",
            ]
            
            cleaned_count = 0
            
            for pattern in log_patterns:
                for log_file in glob.glob(pattern, recursive=True):
                    try:
                        file_age = current_time - os.path.getmtime(log_file)
                        
                        if file_age > retention_seconds:
                            os.remove(log_file)
                            cleaned_count += 1
                            self.logger.info(f"🗑️ Cleaned old log: {log_file}")
                            
                    except Exception as e:
                        self.logger.debug(f"Failed to clean log {log_file}: {e}")
            
            if cleaned_count > 0:
                self.logger.info(f"✅ Cleaned {cleaned_count} old log files")
            
        except Exception as e:
            self.logger.error(f"Log cleanup failed: {e}")
    
    def _start_cleanup_timer(self):
        """Start periodic log cleanup"""
        # FIX: class-level guard - main.py and the GUI each instantiate this
        # class, which previously started one cleanup thread per instance.
        if LogManagementSystem._cleanup_started:
            return
        LogManagementSystem._cleanup_started = True

        def cleanup_worker():
            while True:
                try:
                    time.sleep(3600)  # Check every hour
                    self.cleanup_old_logs()
                except Exception as e:
                    self.logger.error(f"Cleanup timer error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        self.logger.info("🕒 Started log cleanup timer (24h retention)")
    
    def _trigger_log_upload_check(self, log_filename: str, scan_results: Dict[str, Any]):
        """Trigger log upload check when threats are detected"""
        try:
            # Check user consent
            if not self._check_user_consent():
                self._request_user_consent(log_filename, scan_results)
                return
            
            # Upload logs if consent given
            self._upload_logs_to_server([log_filename], scan_results)
            
        except Exception as e:
            self.logger.error(f"Log upload check failed: {e}")
    
    def _check_user_consent(self) -> bool:
        """Check if user has given consent for log uploads"""
        try:
            if not os.path.exists(self.user_consent_file):
                return False
            
            with open(self.user_consent_file, 'r') as f:
                consent_data = json.load(f)
            
            return consent_data.get('log_upload_consent', False)
            
        except Exception as e:
            self.logger.error(f"Failed to check user consent: {e}")
            return False
    
    def _request_user_consent(self, log_filename: str, scan_results: Dict[str, Any]):
        """Request user consent for log uploads"""
        try:
            # This would typically show a GUI dialog
            # For now, we'll create a consent request file
            consent_request = {
                'timestamp': datetime.now().isoformat(),
                'reason': 'threat_detected',
                'log_file': log_filename,
                'threats_found': scan_results.get('summary', {}).get('threats_found', 0),
                'message': 'Threats detected. Would you like to upload logs to help improve AI detection?'
            }
            
            with open('consent_request.json', 'w') as f:
                json.dump(consent_request, f, indent=2)
            
            self.logger.info("📋 User consent requested for log upload")
            
        except Exception as e:
            self.logger.error(f"Failed to request user consent: {e}")
    
    def set_user_consent(self, consent: bool):
        """Set user consent for log uploads"""
        try:
            consent_data = {
                'log_upload_consent': consent,
                'timestamp': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            with open(self.user_consent_file, 'w') as f:
                json.dump(consent_data, f, indent=2)
            
            self.logger.info(f"✅ User consent set: {consent}")
            
        except Exception as e:
            self.logger.error(f"Failed to set user consent: {e}")
    
    def _upload_logs_to_server(self, log_files: List[str], scan_results: Dict[str, Any]):
        """Upload log files to central server"""
        try:
            if not log_files:
                return
            
            # Prepare upload data
            upload_data = {
                'timestamp': datetime.now().isoformat(),
                'client_id': self._get_client_id(),
                'scan_results_summary': scan_results.get('summary', {}),
                'log_files': []
            }
            
            # Read log files
            for log_file in log_files:
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8') as f:
                        log_content = f.read()
                    
                    upload_data['log_files'].append({
                        'filename': os.path.basename(log_file),
                        'content': log_content,
                        'size': len(log_content),
                        'hash': hashlib.sha256(log_content.encode()).hexdigest()
                    })
            
            # Upload to server (simulated)
            self.logger.info(f"📤 Uploading {len(log_files)} log files to central server")
            
            # In a real implementation, this would make an HTTP request
            # response = requests.post(self.central_server_url, json=upload_data, timeout=30)
            
            # For now, save to local file to simulate upload
            upload_filename = os.path.join(
                self.log_directory,
                f"uploaded_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(upload_filename, 'w') as f:
                json.dump(upload_data, f, indent=2)
            
            self.logger.info(f"✅ Logs uploaded successfully (simulated): {upload_filename}")
            
        except Exception as e:
            self.logger.error(f"Log upload failed: {e}")
    
    def _get_client_id(self) -> str:
        """Get unique client identifier"""
        try:
            # FIX: was read/written in CWD; anchor to the log directory
            client_id_file = os.path.join(self.log_directory, 'client_id.txt')
            
            if os.path.exists(client_id_file):
                with open(client_id_file, 'r') as f:
                    return f.read().strip()
            
            # Generate new client ID
            import uuid
            client_id = str(uuid.uuid4())
            
            with open(client_id_file, 'w') as f:
                f.write(client_id)
            
            return client_id
            
        except Exception as e:
            self.logger.error(f"Failed to get client ID: {e}")
            return "unknown_client"
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get log management statistics"""
        try:
            stats = {
                'total_log_files': 0,
                'total_log_size': 0,
                'scan_logs': 0,
                'threat_logs': 0,
                'oldest_log': None,
                'newest_log': None
            }
            
            log_files = glob.glob(f"{self.log_directory}/**/*.log", recursive=True)
            log_files.extend(glob.glob("enhanced_quick_scan_*.log"))
            log_files.extend(glob.glob("*_scan_*.txt"))
            
            if not log_files:
                return stats
            
            stats['total_log_files'] = len(log_files)
            
            oldest_time = float('inf')
            newest_time = 0
            
            for log_file in log_files:
                try:
                    file_size = os.path.getsize(log_file)
                    file_time = os.path.getmtime(log_file)
                    
                    stats['total_log_size'] += file_size
                    
                    if file_time < oldest_time:
                        oldest_time = file_time
                        stats['oldest_log'] = log_file
                    
                    if file_time > newest_time:
                        newest_time = file_time
                        stats['newest_log'] = log_file
                    
                    if 'scan_logs' in log_file or 'scan_' in log_file:
                        stats['scan_logs'] += 1
                    elif 'threat_logs' in log_file or 'threat_' in log_file:
                        stats['threat_logs'] += 1
                        
                except Exception:
                    continue
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get log statistics: {e}")
            return {}


def test_log_management():
    """Test log management system"""
    print("🧪 Testing Log Management System...")
    
    try:
        # Initialize log manager
        log_manager = LogManager()
        
        # Test scan log creation
        scan_data = {
            'config': {
                'scan_type': 'enhanced_quick_scan',
                'ai_engine': True,
                'signature_engine': True,
                'heuristic_analyzer': True
            },
            'targets': [
                'C:\\Windows\\System32',
                'C:\\Program Files',
                'Registry startup keys'
            ]
        }
        
        log_file = log_manager.create_scan_log('enhanced_quick', scan_data)
        print(f"✅ Created scan log: {log_file}")
        
        # Test progress logging
        progress_data = {
            'current_directory': 'C:\\Windows\\System32',
            'current_file': 'C:\\Windows\\System32\\notepad.exe'
        }
        log_manager.log_scan_progress(log_file, progress_data)
        
        # Test threat detection logging
        threat_data = {
            'current_file': 'C:\\Temp\\suspicious.exe',
            'threat_detected': {
                'file_path': 'C:\\Temp\\suspicious.exe',
                'threat_level': 'High',
                'detection_method': 'AI Engine',
                'threat_score': 0.95
            }
        }
        log_manager.log_scan_progress(log_file, threat_data)
        
        # Test scan finalization
        scan_results = {
            'summary': {
                'scan_time': 45.2,
                'files_scanned': 1250,
                'threats_found': 1,
                'suspicious_files': 3,
                'areas_scanned': ['startup_registry', 'system_directories', 'temp_directories']
            },
            'threats': [{
                'file_path': 'C:\\Temp\\suspicious.exe',
                'threat_type': 'Trojan',
                'threat_level': 'High',
                'action_taken': 'Quarantined'
            }]
        }
        
        log_manager.finalize_scan_log(log_file, scan_results)
        print("✅ Finalized scan log")
        
        # Test threat log creation
        threat_log = log_manager.create_threat_log({
            'file_path': 'C:\\Temp\\malware.exe',
            'threat_type': 'Trojan.Generic',
            'threat_level': 'Critical',
            'detection_method': 'Signature + AI',
            'threat_score': 0.98,
            'file_size': 524288,
            'file_hash': 'abc123def456...'
        })
        print(f"✅ Created threat log: {threat_log}")
        
        # Test statistics
        stats = log_manager.get_log_statistics()
        print(f"📊 Log statistics: {stats}")
        
        # Test user consent
        log_manager.set_user_consent(True)
        print("✅ Set user consent")
        
        print("\n" + "=" * 60)
        print("🎉 LOG MANAGEMENT SYSTEM IMPLEMENTED!")
        print("✅ Automatic log creation for all scan types")
        print("✅ 24-hour log retention with automatic cleanup")
        print("✅ Threat detection triggers log uploads")
        print("✅ User consent system for privacy")
        print("✅ Central server upload capability")
        print("✅ Comprehensive logging and statistics")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"❌ Log management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# Alias for backward compatibility (FIX: moved above the __main__ block;
# running the module directly used to hit the test first and crash with
# NameError).
LogManager = LogManagementSystem


if __name__ == "__main__":
    test_log_management()
