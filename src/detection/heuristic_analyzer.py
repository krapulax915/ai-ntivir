import os
import re
import time
import logging
import threading
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
import psutil
import subprocess
import json

class HeuristicAnalyzer:
    """Heuristic analysis engine for behavioral threat detection"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.heuristic_analyzer')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.behavioral_rules = self._load_behavioral_rules()
        self.process_monitor = ProcessMonitor()
        
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze file for threats - main interface method"""
        return self.analyze_file_behavior(file_path)
    
    def analyze_file_behavior(self, file_path: str) -> Dict:
        """Analyze file for suspicious behavioral patterns with Windows system file protection"""
        try:
            analysis_result = {
                'file_path': file_path,
                'heuristic_score': 0.0,
                'suspicious_indicators': [],
                'behavioral_flags': [],
                'risk_factors': [],
                'timestamp': time.time(),
                'is_threat': False,
                'is_suspicious': False
            }
            
            # PRIORITY 1: Always whitelist Windows system files
            file_path_lower = file_path.lower()
            safe_system_dirs = [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\winsxs\\',
                'c:\\program files\\',
                'c:\\program files (x86)\\',
                'c:\\programdata\\microsoft\\'
            ]
            
            if any(file_path_lower.startswith(safe_dir) for safe_dir in safe_system_dirs):
                analysis_result['heuristic_score'] = 0.0
                analysis_result['suspicious_indicators'] = ['Windows system file - safe']
                analysis_result['is_threat'] = False
                analysis_result['is_suspicious'] = False
                return analysis_result
            
            # Static analysis
            static_score = self._analyze_static_properties(file_path, analysis_result)
            
            # Content analysis
            content_score = self._analyze_file_content(file_path, analysis_result)
            
            # Location analysis
            location_score = self._analyze_file_location(file_path, analysis_result)
            
            # Calculate combined heuristic score
            combined_score = (static_score + content_score + location_score) / 3.0
            # FIX (v1.0.5): cap the heuristic score at 0.6. Static heuristics
            # (size/age/entropy of compressed installers) cannot distinguish a
            # packed-but-legitimate setup (our own 131 MB installer scored
            # 1.00!) from real malware - ONLY signature hits may declare a
            # threat. 0.6 keeps the file "suspicious" (visible in results)
            # without triggering quarantine.
            analysis_result['heuristic_score'] = min(combined_score, 0.6)

            # Set threat/suspicious flags based on score
            if analysis_result['heuristic_score'] > 0.8:
                analysis_result['is_threat'] = True
            elif analysis_result['heuristic_score'] >= 0.55:
                analysis_result['is_suspicious'] = True
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed for {file_path}: {e}")
            return {
                'file_path': file_path,
                'heuristic_score': 0.0,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def analyze_process_behavior(self, process_info: Dict) -> Dict:
        """Analyze process behavior for suspicious activities"""
        try:
            analysis_result = {
                'process_id': process_info.get('pid'),
                'process_name': process_info.get('name'),
                'behavioral_score': 0.0,
                'suspicious_activities': [],
                'network_activities': [],
                'file_activities': [],
                'timestamp': time.time()
            }
            
            # Check process behavior patterns
            behavior_score = self._check_process_patterns(process_info, analysis_result)
            
            # Check network behavior
            network_score = self._check_network_behavior(process_info, analysis_result)
            
            # Check file system behavior
            file_score = self._check_file_behavior(process_info, analysis_result)
            
            analysis_result['behavioral_score'] = min(
                (behavior_score + network_score + file_score) / 3.0, 1.0
            )
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Process behavior analysis failed: {e}")
            return {
                'behavioral_score': 0.0,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _analyze_static_properties(self, file_path: str, result: Dict) -> float:
        """Analyze static file properties with Windows system file protection"""
        score = 0.0
        
        try:
            if not os.path.exists(file_path):
                return 0.0
            
            # PRIORITY 1: Always whitelist Windows system directories
            file_path_lower = file_path.lower()
            safe_system_dirs = [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\winsxs\\',
                'c:\\program files\\',
                'c:\\program files (x86)\\',
                'c:\\programdata\\microsoft\\'
            ]
            
            if any(file_path_lower.startswith(safe_dir) for safe_dir in safe_system_dirs):
                # Windows system files get minimal score
                result['suspicious_indicators'].append('Windows system file - safe')
                return 0.0
            
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_ext = Path(file_path).suffix.lower()
            
            # Safe extensions that should never be flagged
            safe_extensions = {
                '.dll', '.sys', '.mui', '.exe', '.msc', '.cpl', '.ocx', '.drv',
                '.pdf', '.txt', '.doc', '.docx', '.jpg', '.png', '.mp3', '.mp4'
            }
            
            if file_ext in safe_extensions and any(file_path_lower.startswith(safe_dir) for safe_dir in safe_system_dirs):
                return 0.0
            
            # Size-based scoring (only for non-system files)
            if file_size == 0:
                score += 0.3
                result['suspicious_indicators'].append('Zero-byte file')
            elif file_size > 100 * 1024 * 1024:  # >100MB
                score += 0.2
                result['suspicious_indicators'].append('Unusually large file')
            
            # Extension-based scoring (reduced for system locations)
            suspicious_extensions = ['.scr', '.bat', '.cmd', '.pif', '.com', '.vbs', '.js']
            if file_ext in suspicious_extensions:
                # Lower score for files in safe directories
                if any('program files' in file_path_lower or 'windows' in file_path_lower):
                    score += 0.1  # Reduced score for system locations
                else:
                    score += 0.3
                result['suspicious_indicators'].append(f'Suspicious extension: {file_ext}')
            
            # Recently created files (skip for system directories)
            if not any(file_path_lower.startswith(safe_dir) for safe_dir in safe_system_dirs):
                current_time = time.time()
                if current_time - file_stat.st_ctime < 3600:  # Created within last hour
                    score += 0.2
                    result['suspicious_indicators'].append('Recently created file')
            
            # Check for hidden attributes
            if self._is_hidden_file(file_path):
                score += 0.1
                result['suspicious_indicators'].append('Hidden file attributes')
            
            return score
        
        except Exception as e:
            self.logger.error(f"Static analysis error: {e}")
        
        return score
    
    def _analyze_file_content(self, file_path: str, result: Dict) -> float:
        """Analyze file content for suspicious patterns"""
        score = 0.0
        
        try:
            file_ext = Path(file_path).suffix.lower()
            
            # Analyze executable files
            if file_ext in ['.exe', '.dll', '.scr']:
                score += self._analyze_pe_content(file_path, result)
            
            # Analyze script files
            elif file_ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js']:
                score += self._analyze_script_content(file_path, result)
            
            # Analyze document files
            elif file_ext in ['.doc', '.docx', '.pdf', '.xls', '.xlsx']:
                score += self._analyze_document_content(file_path, result)
            
        except Exception as e:
            self.logger.error(f"Content analysis error: {e}")
        
        return score
    
    def _analyze_pe_content(self, file_path: str, result: Dict) -> float:
        """Analyze PE file content"""
        score = 0.0
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
                
                # Check for suspicious strings
                suspicious_strings = [
                    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
                    b'SetWindowsHookEx', b'GetProcAddress', b'LoadLibrary',
                    b'RegCreateKey', b'RegSetValue', b'CreateService',
                    b'StartService', b'CryptEncrypt', b'CryptDecrypt'
                ]
                
                for sus_string in suspicious_strings:
                    if sus_string in content:
                        score += 0.1
                        result['suspicious_indicators'].append(f'Suspicious API: {sus_string.decode("utf-8", errors="ignore")}')
                
                # Check for packing indicators
                if b'UPX' in content or b'PECompact' in content:
                    score += 0.3
                    result['suspicious_indicators'].append('Packed executable detected')
                
        except PermissionError:
            # FIX (v1.0.5): protected system files are normal - debug only
            self.logger.debug(f"PE analysis skipped (permission denied)")
        except OSError as e:
            if e.errno in (2, 22):
                # reparse points (AppExecutionAlias) / vanished files - normal
                self.logger.debug(f"PE analysis skipped (errno {e.errno})")
            else:
                self.logger.error(f"PE analysis error: {e}")
        except Exception as e:
            self.logger.error(f"PE analysis error: {e}")
        
        return min(score, 1.0)
    
    def _analyze_script_content(self, file_path: str, result: Dict) -> float:
        """Analyze script file content"""
        score = 0.0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10240)  # Read first 10KB
                content_lower = content.lower()
                
                # Suspicious PowerShell patterns
                powershell_patterns = [
                    r'invoke-expression', r'iex\s+', r'downloadstring',
                    r'bypass.*executionpolicy', r'hidden.*windowstyle',
                    r'encodedcommand', r'frombase64string'
                ]
                
                for pattern in powershell_patterns:
                    if re.search(pattern, content_lower):
                        score += 0.2
                        result['suspicious_indicators'].append(f'Suspicious PowerShell pattern: {pattern}')
                
                # Suspicious batch patterns
                batch_patterns = [
                    r'del\s+/q\s+/s', r'rmdir\s+/s\s+/q', r'format\s+c:',
                    r'reg\s+delete', r'schtasks.*create', r'net\s+user.*add'
                ]
                
                for pattern in batch_patterns:
                    if re.search(pattern, content_lower):
                        score += 0.2
                        result['suspicious_indicators'].append(f'Suspicious batch command: {pattern}')
                
                # Check for obfuscation
                if self._detect_obfuscation(content):
                    score += 0.3
                    result['suspicious_indicators'].append('Script obfuscation detected')
                
        except Exception as e:
            self.logger.error(f"Script analysis error: {e}")
        
        return min(score, 1.0)
    
    def _analyze_document_content(self, file_path: str, result: Dict) -> float:
        """Analyze document file content"""
        score = 0.0
        
        try:
            # Check for macro-enabled documents
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ['.docm', '.xlsm', '.pptm']:
                score += 0.2
                result['suspicious_indicators'].append('Macro-enabled document')
            
            # Check file size vs extension
            file_size = os.path.getsize(file_path)
            if file_ext == '.pdf' and file_size > 50 * 1024 * 1024:  # >50MB PDF
                score += 0.2
                result['suspicious_indicators'].append('Unusually large PDF file')
            
        except Exception as e:
            self.logger.error(f"Document analysis error: {e}")
        
        return score
    
    def _analyze_file_location(self, file_path: str, result: Dict) -> float:
        """Analyze file location for suspicious patterns"""
        score = 0.0
        
        try:
            path_lower = file_path.lower()
            
            # Suspicious locations
            suspicious_paths = [
                'temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp',
                'programdata', 'users\\public', 'recycle.bin'
            ]
            
            for sus_path in suspicious_paths:
                if sus_path in path_lower:
                    score += 0.2
                    result['risk_factors'].append(f'Suspicious location: {sus_path}')
            
            # System directory executables (non-system files)
            system_paths = ['windows\\system32', 'windows\\syswow64']
            for sys_path in system_paths:
                if sys_path in path_lower and not self._is_system_file(file_path):
                    score += 0.4
                    result['risk_factors'].append('Non-system file in system directory')
            
            # Check for double extensions
            if self._has_double_extension(file_path):
                score += 0.3
                result['risk_factors'].append('Double file extension detected')
            
        except Exception as e:
            self.logger.error(f"Location analysis error: {e}")
        
        return score
    
    def _check_process_patterns(self, process_info: Dict, result: Dict) -> float:
        """Check process for suspicious patterns"""
        score = 0.0
        
        try:
            process_name = process_info.get('name', '').lower()
            command_line = process_info.get('cmdline', [])
            
            # Suspicious process names
            suspicious_names = [
                'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe'
            ]
            
            if process_name in suspicious_names:
                # Check if running from correct location
                exe_path = process_info.get('exe', '').lower()
                if 'system32' not in exe_path and 'syswow64' not in exe_path:
                    score += 0.5
                    result['suspicious_activities'].append(f'System process from wrong location: {process_name}')
            
            # Check command line arguments
            if command_line:
                cmd_string = ' '.join(command_line).lower()
                
                suspicious_args = [
                    'bypass', 'hidden', 'encodedcommand', 'downloadstring',
                    'invoke-expression', 'iex', 'net user', 'schtasks'
                ]
                
                for arg in suspicious_args:
                    if arg in cmd_string:
                        score += 0.2
                        result['suspicious_activities'].append(f'Suspicious command argument: {arg}')
            
        except Exception as e:
            self.logger.error(f"Process pattern check error: {e}")
        
        return score
    
    def _check_network_behavior(self, process_info: Dict, result: Dict) -> float:
        """Check process network behavior"""
        score = 0.0
        
        try:
            pid = process_info.get('pid')
            if pid:
                # Get network connections for process
                connections = psutil.Process(pid).connections()
                
                for conn in connections:
                    if conn.raddr:  # Remote address exists
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check for suspicious ports
                        suspicious_ports = [4444, 5555, 6666, 1337, 31337]
                        if remote_port in suspicious_ports:
                            score += 0.3
                            result['network_activities'].append(f'Connection to suspicious port: {remote_port}')
                        
                        # Check for non-standard HTTP/HTTPS ports
                        if remote_port not in [80, 443, 8080, 8443] and conn.type == 1:  # TCP
                            score += 0.1
                            result['network_activities'].append(f'Non-standard port connection: {remote_port}')
        
        except Exception as e:
            self.logger.error(f"Network behavior check error: {e}")
        
        return score
    
    def _check_file_behavior(self, process_info: Dict, result: Dict) -> float:
        """Check process file system behavior"""
        score = 0.0
        
        try:
            # This would require more advanced monitoring
            # For now, basic checks based on process info
            
            exe_path = process_info.get('exe', '').lower()
            
            # Check if process is writing to system directories
            if 'system32' in exe_path or 'program files' in exe_path:
                # System processes should not be user-initiated
                if process_info.get('username') != 'SYSTEM':
                    score += 0.2
                    result['file_activities'].append('User process in system directory')
        
        except Exception as e:
            self.logger.error(f"File behavior check error: {e}")
        
        return score
    
    def _load_suspicious_patterns(self) -> Dict:
        """Load suspicious pattern definitions"""
        return {
            'file_extensions': ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js'],
            'suspicious_strings': [
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                'SetWindowsHookEx', 'RegCreateKey', 'CryptEncrypt'
            ],
            'obfuscation_indicators': [
                'base64', 'gzip', 'deflate', 'char codes', 'string replace'
            ]
        }
    
    def _load_behavioral_rules(self) -> List[Dict]:
        """Load behavioral analysis rules"""
        return [
            {
                'name': 'Rapid file creation',
                'description': 'Multiple files created in short time',
                'threshold': 10,
                'timeframe': 60,
                'score': 0.4
            },
            {
                'name': 'System file modification',
                'description': 'Modification of system files',
                'score': 0.6
            },
            {
                'name': 'Registry modification',
                'description': 'Suspicious registry modifications',
                'score': 0.3
            }
        ]
    
    def _check_extension_mismatch(self, file_path: str) -> bool:
        """Check for file extension mismatch"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                
            file_ext = Path(file_path).suffix.lower()
            
            # Check PE header vs extension
            if header[:2] == b'MZ' and file_ext not in ['.exe', '.dll', '.scr']:
                return True
            
            # Check PDF header vs extension
            if header[:4] == b'%PDF' and file_ext != '.pdf':
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_hidden_file(self, file_path: str) -> bool:
        """Check if file has hidden attributes"""
        try:
            import stat
            file_stat = os.stat(file_path)
            return bool(file_stat.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
        except:
            return False
    
    def _detect_obfuscation(self, content: str) -> bool:
        """Detect script obfuscation"""
        # Simple obfuscation detection
        obfuscation_indicators = [
            len(re.findall(r'[A-Za-z0-9+/]{20,}', content)) > 5,  # Base64-like strings
            content.count('chr(') > 10,  # Character codes
            content.count('String.fromCharCode') > 5,  # JS char codes
            len(content) > 1000 and content.count(' ') < len(content) * 0.1  # Minified
        ]
        
        return sum(obfuscation_indicators) >= 2
    
    def _is_system_file(self, file_path: str) -> bool:
        """Check if file is a legitimate system file"""
        # Simplified check - in reality would verify digital signatures
        system_files = [
            'ntdll.dll', 'kernel32.dll', 'user32.dll', 'advapi32.dll',
            'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe'
        ]
        
        filename = Path(file_path).name.lower()
        return filename in system_files
    
    def _has_double_extension(self, file_path: str) -> bool:
        """Check for double file extensions"""
        filename = Path(file_path).name
        extensions = re.findall(r'\.[a-zA-Z0-9]+', filename)
        return len(extensions) > 1

class ProcessMonitor:
    """Monitor running processes for suspicious behavior"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.heuristic_analyzer')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.monitored_processes = {}
        self.is_monitoring = False
    
    def start_monitoring(self):
        """Start process monitoring"""
        self.is_monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.is_monitoring = False
    
    def _monitor_processes(self):
        """Monitor process activities"""
        while self.is_monitoring:
            try:
                current_processes = {p.pid: p for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username'])}
                
                # Check for new processes
                for pid, process in current_processes.items():
                    if pid not in self.monitored_processes:
                        self._analyze_new_process(process)
                
                self.monitored_processes = current_processes
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
    
    def _analyze_new_process(self, process):
        """Analyze newly started process"""
        try:
            process_info = process.info
            self.logger.debug(f"New process detected: {process_info.get('name')} (PID: {process_info.get('pid')})")
            
            # Basic suspicious process detection would go here
            # This would integrate with the main heuristic analyzer
            
        except Exception as e:
            self.logger.error(f"New process analysis error: {e}")
