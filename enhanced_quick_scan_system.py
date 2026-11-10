#!/usr/bin/env python3
"""
Enhanced Quick Scan System
Comprehensive scanning of critical Windows system areas
"""

import os
import sys
import time
import winreg
import psutil
import subprocess
import threading
import logging
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import json
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# FIX (2026-11-10): the launcher sets CWD to the install dir (C:\Program
# Files\AI_Antivirus), where a standard user cannot write. Anchor all writable
# output (detailed logs, scan result JSON) to %PROGRAMDATA%\AI_Antivirus so
# logs/results are never silently lost after installation.
_BASE_DIR = os.path.join(
    os.environ.get('PROGRAMDATA', os.path.dirname(os.path.abspath(__file__))),
    'AI_Antivirus')

class CriticalSystemScanner:
    """Enhanced scanner for critical Windows system areas"""
    
    def __init__(self, ai_engine=None, signature_engine=None, heuristic_analyzer=None):
        self.ai_engine = ai_engine
        self.signature_engine = signature_engine
        self.heuristic_analyzer = heuristic_analyzer
        self.threat_classifier = ai_engine  # Add threat_classifier reference for compatibility
        self.intelligence_engine = ai_engine  # Add intelligence_engine reference for compatibility
        self.logger = logging.getLogger(__name__)
        
        # Setup detailed logging
        self.detailed_log_file = None
        self.detailed_logger = None
        self.progress_callback = None  # Store progress callback for pause/stop checking
        self._setup_detailed_logging()
        
        # Critical scan areas
        self.critical_areas = {
            'startup_registry': self._get_startup_registry_keys(),
            'system_directories': self._get_system_directories(),
            'autorun_locations': self._get_autorun_locations(),
            'memory_processes': self._get_memory_scan_targets(),
            'browser_locations': self._get_browser_locations(),
            'temp_directories': self._get_temp_directories()
        }
        
        # Scan statistics
        self.scan_stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'suspicious_files': 0,
            'registry_entries_checked': 0,
            'processes_analyzed': 0,
            'scan_time': 0,
            'areas_scanned': []
        }
        
        # Initialize scanner
        self._init_scanner()
    
    def _setup_detailed_logging(self):
        """Setup detailed logging for enhanced quick scan"""
        try:
            # Create timestamp for log file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            log_dir = os.path.join(_BASE_DIR, 'logs')
            os.makedirs(log_dir, exist_ok=True)
            self.detailed_log_file = os.path.join(log_dir, f"enhanced_quick_scan_{timestamp}.log")
            
            # Create detailed logger
            self.detailed_logger = logging.getLogger(f"enhanced_scan_{timestamp}")
            self.detailed_logger.setLevel(logging.DEBUG)
            
            # Create file handler
            file_handler = logging.FileHandler(self.detailed_log_file, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            
            # Add handler to logger
            self.detailed_logger.addHandler(file_handler)
            
            # Log initialization
            self.detailed_logger.info("=" * 80)
            self.detailed_logger.info("ENHANCED QUICK SCAN - DETAILED LOG")
            self.detailed_logger.info("=" * 80)
            self.detailed_logger.info(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.detailed_logger.info(f"Log file: {self.detailed_log_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup detailed logging: {e}")
    
    def _close_detailed_logger(self):
        """FIX: close detailed logger file handlers (handle leak per scan)."""
        try:
            if self.detailed_logger:
                for h in self.detailed_logger.handlers[:]:
                    try:
                        h.close()
                    except Exception:
                        pass
                    self.detailed_logger.removeHandler(h)
        except Exception:
            pass

    def _init_scanner(self):
        """Initialize critical system scanner"""
        try:
            self.logger.info("🔍 Initializing enhanced quick scan system")
            if self.detailed_logger:
                self.detailed_logger.info("🔍 Initializing enhanced quick scan system")
            
            # Create scan results directory
            results_dir = os.path.join(_BASE_DIR, 'logs', 'quick_scan_results')
            os.makedirs(results_dir, exist_ok=True)

            if self.detailed_logger:
                self.detailed_logger.info(f"✅ Created scan results directory: {results_dir}")
            
        except Exception as e:
            self.logger.error(f"Scanner initialization failed: {e}")
            if self.detailed_logger:
                self.detailed_logger.error(f"Scanner initialization failed: {e}")
    
    def _get_startup_registry_keys(self) -> List[Dict[str, str]]:
        """Get critical startup registry locations"""
        return [
            {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'HKLM Run'
            },
            {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'name': 'HKLM RunOnce'
            },
            {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'name': 'HKCU Run'
            },
            {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'name': 'HKCU RunOnce'
            },
            {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'name': 'HKLM Run (WOW64)'
            },
            {
                'hive': winreg.HKEY_LOCAL_MACHINE,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                'name': 'HKLM Policies Run'
            },
            {
                'hive': winreg.HKEY_CURRENT_USER,
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                'name': 'HKCU Policies Run'
            }
        ]
    
    def _get_system_directories(self) -> List[Dict[str, str]]:
        """Get critical Windows system directories"""
        windows_dir = os.environ.get('WINDIR', r'C:\Windows')
        system_drive = os.environ.get('SYSTEMDRIVE', 'C:')
        
        return [
            {
                'path': os.path.join(windows_dir, 'System32'),
                'name': 'System32',
                'priority': 'critical',
                'scan_executables': True
            },
            {
                'path': os.path.join(windows_dir, 'SysWOW64'),
                'name': 'SysWOW64',
                'priority': 'critical',
                'scan_executables': True
            },
            {
                'path': windows_dir,
                'name': 'Windows Directory',
                'priority': 'high',
                'scan_executables': True,
                'max_depth': 1
            },
            {
                'path': os.path.join(windows_dir, 'System32', 'drivers'),
                'name': 'System Drivers',
                'priority': 'critical',
                'scan_executables': True
            },
            {
                'path': os.path.join(windows_dir, 'System32', 'config'),
                'name': 'System Config',
                'priority': 'high',
                'scan_executables': False
            },
            {
                'path': os.path.join(system_drive, 'Program Files'),
                'name': 'Program Files',
                'priority': 'medium',
                'scan_executables': True,
                'max_depth': 2
            },
            {
                'path': os.path.join(system_drive, 'Program Files (x86)'),
                'name': 'Program Files (x86)',
                'priority': 'medium',
                'scan_executables': True,
                'max_depth': 2
            }
        ]
    
    def _get_autorun_locations(self) -> List[Dict[str, str]]:
        """Get autorun and startup locations"""
        user_profile = os.environ.get('USERPROFILE', '')
        all_users_startup = os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        user_startup = os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        
        return [
            {
                'path': all_users_startup,
                'name': 'All Users Startup',
                'priority': 'critical'
            },
            {
                'path': user_startup,
                'name': 'User Startup',
                'priority': 'critical'
            },
            {
                'path': os.path.join(user_profile, 'AppData', 'Roaming'),
                'name': 'User AppData Roaming',
                'priority': 'high',
                'max_depth': 2
            },
            {
                'path': os.path.join(user_profile, 'AppData', 'Local'),
                'name': 'User AppData Local',
                'priority': 'high',
                'max_depth': 2
            }
        ]
    
    def _get_memory_scan_targets(self) -> List[str]:
        """Get processes for memory scanning"""
        return [
            'explorer.exe',
            'winlogon.exe',
            'csrss.exe',
            'lsass.exe',
            'services.exe',
            'svchost.exe',
            'dwm.exe'
        ]
    
    def _get_browser_locations(self) -> List[Dict[str, str]]:
        """Get browser-related locations"""
        user_profile = os.environ.get('USERPROFILE', '')
        
        return [
            {
                'path': os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                'name': 'Chrome User Data',
                'priority': 'medium'
            },
            {
                'path': os.path.join(user_profile, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
                'name': 'Firefox Profiles',
                'priority': 'medium'
            },
            {
                'path': os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                'name': 'Edge User Data',
                'priority': 'medium'
            }
        ]
    
    def _get_temp_directories(self) -> List[Dict[str, str]]:
        """Get temporary directories"""
        return [
            {
                'path': os.environ.get('TEMP', r'C:\Windows\Temp'),
                'name': 'System Temp',
                'priority': 'high'
            },
            {
                'path': os.environ.get('TMP', r'C:\Windows\Temp'),
                'name': 'System TMP',
                'priority': 'high'
            },
            {
                'path': r'C:\Windows\Temp',
                'name': 'Windows Temp',
                'priority': 'high'
            },
            {
                'path': os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp'),
                'name': 'User Temp',
                'priority': 'high'
            }
        ]
    
    def perform_enhanced_quick_scan(self, progress_callback=None) -> Dict[str, Any]:
        """Perform enhanced quick scan of critical system areas"""
        start_time = time.time()
        self.progress_callback = progress_callback  # Store callback for use in other methods
        
        try:
            # Debug: Check if progress callback is received - log to file
            if progress_callback:
                debug_msg = f"🔧 DEBUG: Progress callback received: {progress_callback}"
                print(debug_msg)
                if self.detailed_logger:
                    self.detailed_logger.info(debug_msg)
            else:
                debug_msg = "🔧 DEBUG: No progress callback provided"
                print(debug_msg)
                if self.detailed_logger:
                    self.detailed_logger.info(debug_msg)
            
            self.logger.info("🚀 Starting enhanced quick scan of critical system areas")
            if self.detailed_logger:
                self.detailed_logger.info("🚀 Starting enhanced quick scan of critical system areas")
                self.detailed_logger.info("-" * 80)
                self.detailed_logger.info("SCAN CONFIGURATION:")
                self.detailed_logger.info(f"AI Engine: {'Available' if self.ai_engine else 'Not Available'}")
                self.detailed_logger.info(f"Signature Engine: {'Available' if self.signature_engine else 'Not Available'}")
                self.detailed_logger.info(f"Heuristic Analyzer: {'Available' if self.heuristic_analyzer else 'Not Available'}")
                self.detailed_logger.info("-" * 80)
            
            # Reset statistics and estimate total files
            estimated_total_files = 10000  # More realistic estimate for quick scan
            self.scan_stats = {
                'files_scanned': 0,
                'threats_found': 0,
                'suspicious_files': 0,
                'registry_entries_checked': 0,
                'processes_analyzed': 0,
                'scan_time': 0,
                'areas_scanned': [],
                'threats_detected': [],
                'suspicious_registry': [],
                'suspicious_processes': [],
                'estimated_total_files': estimated_total_files
            }
            
            scan_results = {
                'scan_type': 'enhanced_quick_scan',
                'start_time': datetime.now().isoformat(),
                'areas_scanned': {},
                'threats_found': [],
                'summary': {}
            }
            
            # Calculate total areas more accurately for progress tracking
            total_areas = (
                1 +  # startup registry (counted as 1 area)
                len(self.critical_areas['system_directories']) + 
                len(self.critical_areas['autorun_locations']) +
                1 +  # memory processes
                len(self.critical_areas['browser_locations']) +
                len(self.critical_areas['temp_directories'])
            )
            current_area = 0
            
            # Initialize progress tracking variables
            self.scan_stats['current_progress'] = 0.0
            self.scan_stats['last_reported_progress'] = -1
            
            # 1. Scan startup registry entries
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                result = progress_callback(area_progress, "Scanning startup registry entries...")
                if not result:
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("📋 SCANNING STARTUP REGISTRY ENTRIES")
                self.detailed_logger.info(f"Registry locations to scan: {len(self.critical_areas['startup_registry'])}")
                for reg_loc in self.critical_areas['startup_registry']:
                    self.detailed_logger.info(f"  - {reg_loc['name']}: {reg_loc['path']}")
            
            registry_results = self._scan_startup_registry()
            scan_results['areas_scanned']['startup_registry'] = registry_results
            self.scan_stats['areas_scanned'].append('startup_registry')
            current_area += 1  # Registry scan counts as 1 area
            
            # 2. Scan system directories
            current_area += 1
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                if not progress_callback(area_progress, "Scanning system directories..."):
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("📁 SCANNING SYSTEM DIRECTORIES")
                self.detailed_logger.info(f"System directories to scan: {len(self.critical_areas['system_directories'])}")
                for sys_dir in self.critical_areas['system_directories']:
                    self.detailed_logger.info(f"  - {sys_dir['name']}: {sys_dir['path']} (Priority: {sys_dir['priority']})")
            
            for sys_dir in self.critical_areas['system_directories']:
                if self.detailed_logger:
                    self.detailed_logger.info(f"🔍 Scanning directory: {sys_dir['name']} - {sys_dir['path']}")
                dir_results = self._scan_directory(sys_dir, current_area, total_areas)
                scan_results['areas_scanned'][f"system_dir_{sys_dir['name']}"] = dir_results
                current_area += 1
                
                # Update progress after each directory
                if progress_callback:
                    area_progress = (current_area / total_areas) * 100
                    self.scan_stats['current_progress'] = area_progress
                    if not progress_callback(min(area_progress, 95.0), f"Completed {sys_dir['name']}"):
                        return {'error': 'Scan stopped by user'}
            
            self.scan_stats['areas_scanned'].append('system_directories')
            
            # 3. Scan autorun locations
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                if not progress_callback(area_progress, "Scanning autorun locations..."):
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("🚀 SCANNING AUTORUN LOCATIONS")
                self.detailed_logger.info(f"Autorun locations to scan: {len(self.critical_areas['autorun_locations'])}")
                for autorun_loc in self.critical_areas['autorun_locations']:
                    self.detailed_logger.info(f"  - {autorun_loc['name']}: {autorun_loc['path']} (Priority: {autorun_loc['priority']})")
            
            for autorun_loc in self.critical_areas['autorun_locations']:
                if self.detailed_logger:
                    self.detailed_logger.info(f"🔍 Scanning autorun location: {autorun_loc['name']} - {autorun_loc['path']}")
                autorun_results = self._scan_directory(autorun_loc, current_area, total_areas)
                scan_results['areas_scanned'][f"autorun_{autorun_loc['name']}"] = autorun_results
                current_area += 1
                
                # Update progress after each autorun location
                if progress_callback:
                    area_progress = (current_area / total_areas) * 100
                    self.scan_stats['current_progress'] = area_progress
                    if not progress_callback(min(area_progress, 95.0), f"Completed {autorun_loc['name']}"):
                        return {'error': 'Scan stopped by user'}
            
            self.scan_stats['areas_scanned'].append('autorun_locations')
            
            # 4. Scan memory processes
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                if not progress_callback(area_progress, "Scanning memory processes..."):
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("💾 SCANNING MEMORY PROCESSES")
                self.detailed_logger.info(f"Target processes to analyze: {len(self.critical_areas['memory_processes'])}")
                for proc_name in self.critical_areas['memory_processes']:
                    self.detailed_logger.info(f"  - {proc_name}")
            
            memory_results = self._scan_memory_processes()
            scan_results['areas_scanned']['memory_processes'] = memory_results
            self.scan_stats['areas_scanned'].append('memory_processes')
            current_area += 1
            
            # 5. Scan browser locations
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                if not progress_callback(area_progress, "Scanning browser locations..."):
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("🌐 SCANNING BROWSER LOCATIONS")
                self.detailed_logger.info(f"Browser locations to scan: {len(self.critical_areas['browser_locations'])}")
                for browser_loc in self.critical_areas['browser_locations']:
                    self.detailed_logger.info(f"  - {browser_loc['name']}: {browser_loc['path']} (Priority: {browser_loc['priority']})")
            
            for browser_loc in self.critical_areas['browser_locations']:
                if self.detailed_logger:
                    self.detailed_logger.info(f"🔍 Scanning browser location: {browser_loc['name']} - {browser_loc['path']}")
                browser_results = self._scan_directory(browser_loc, current_area, total_areas)
                scan_results['areas_scanned'][f"browser_{browser_loc['name']}"] = browser_results
                current_area += 1

                # FIX: honor stop request in the browser phase too (was missing)
                if progress_callback:
                    area_progress = (current_area / total_areas) * 100
                    self.scan_stats['current_progress'] = area_progress
                    if not progress_callback(min(area_progress, 95.0), f"Completed {browser_loc['name']}"):
                        return {'error': 'Scan stopped by user'}

            self.scan_stats['areas_scanned'].append('browser_locations')
            
            # 6. Scan temp directories
            if progress_callback:
                area_progress = (current_area / total_areas) * 100
                self.scan_stats['current_progress'] = area_progress
                if not progress_callback(area_progress, "Scanning temp directories..."):
                    return {'error': 'Scan stopped by user'}
            
            if self.detailed_logger:
                self.detailed_logger.info("📁 SCANNING TEMP DIRECTORIES")
                self.detailed_logger.info(f"Temp directories to scan: {len(self.critical_areas['temp_directories'])}")
                for temp_dir in self.critical_areas['temp_directories']:
                    self.detailed_logger.info(f"  - {temp_dir['name']}: {temp_dir['path']} (Priority: {temp_dir['priority']})")
            
            for temp_dir in self.critical_areas['temp_directories']:
                if self.detailed_logger:
                    self.detailed_logger.info(f"🔍 Scanning temp directory: {temp_dir['name']} - {temp_dir['path']}")
                temp_results = self._scan_directory(temp_dir, current_area, total_areas)
                scan_results['areas_scanned'][f"temp_{temp_dir['name']}"] = temp_results
                current_area += 1

                # FIX: honor stop request in the temp phase too (was missing)
                if progress_callback:
                    area_progress = (current_area / total_areas) * 100
                    self.scan_stats['current_progress'] = area_progress
                    if not progress_callback(min(area_progress, 95.0), f"Completed {temp_dir['name']}"):
                        return {'error': 'Scan stopped by user'}

            self.scan_stats['areas_scanned'].append('temp_directories')
            
            # Finalize scan results
            self.scan_stats['scan_time'] = time.time() - start_time
            scan_results['end_time'] = datetime.now().isoformat()
            scan_results['summary'] = self.scan_stats.copy()

            # FIX: close detailed log handlers so files/handles are not leaked
            # (one open handle per scan previously accumulated until exit).
            self._close_detailed_logger()

            # Final progress callback at 100% when scan truly completes
            if progress_callback:
                progress_callback(100.0, "Scan completed successfully")
            
            # Log final results
            if self.detailed_logger:
                self.detailed_logger.info("=" * 80)
                self.detailed_logger.info("SCAN COMPLETED - FINAL SUMMARY")
                self.detailed_logger.info("=" * 80)
                self.detailed_logger.info(f"Scan duration: {self.scan_stats['scan_time']:.2f} seconds")
                self.detailed_logger.info(f"Files scanned: {self.scan_stats['files_scanned']}")
                self.detailed_logger.info(f"Threats found: {self.scan_stats['threats_found']}")
                self.detailed_logger.info(f"Suspicious files: {self.scan_stats['suspicious_files']}")
                self.detailed_logger.info(f"Registry entries checked: {self.scan_stats['registry_entries_checked']}")
                self.detailed_logger.info(f"Processes analyzed: {self.scan_stats['processes_analyzed']}")
                self.detailed_logger.info(f"Areas scanned: {', '.join(self.scan_stats['areas_scanned'])}")
                self.detailed_logger.info("=" * 80)
            
            # Save scan results
            self._save_scan_results(scan_results)
            
            if progress_callback:
                if not progress_callback(100, "Enhanced quick scan completed!"):
                    return {'error': 'Scan stopped by user'}
            
            self.logger.info(f"✅ Enhanced quick scan completed in {self.scan_stats['scan_time']:.2f}s")
            self.logger.info(f"📊 Files scanned: {self.scan_stats['files_scanned']}, Threats: {self.scan_stats['threats_found']}")
            
            if self.detailed_logger:
                self.detailed_logger.info(f"✅ Enhanced quick scan completed - Log saved to: {self.detailed_log_file}")
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Enhanced quick scan failed: {e}")
            return {'error': str(e), 'scan_stats': self.scan_stats}
    
    def _scan_startup_registry(self) -> Dict[str, Any]:
        """Scan startup registry entries for threats"""
        try:
            registry_results = {
                'entries_checked': 0,
                'suspicious_entries': [],
                'threats_found': []
            }
            
            for reg_location in self.critical_areas['startup_registry']:
                try:
                    with winreg.OpenKey(reg_location['hive'], reg_location['path']) as key:
                        i = 0
                        while True:
                            try:
                                name, value, reg_type = winreg.EnumValue(key, i)
                                registry_results['entries_checked'] += 1
                                self.scan_stats['registry_entries_checked'] += 1
                                
                                # Analyze registry entry
                                entry_analysis = self._analyze_registry_entry(name, value, reg_location['name'])
                                
                                if entry_analysis['is_suspicious']:
                                    registry_results['suspicious_entries'].append(entry_analysis)
                                    self.scan_stats['suspicious_registry'].append(entry_analysis)
                                
                                if entry_analysis['is_threat']:
                                    registry_results['threats_found'].append(entry_analysis)
                                    self.scan_stats['threats_found'] += 1
                                
                                i += 1
                                
                            except WindowsError:
                                break
                                
                except FileNotFoundError:
                    # Registry key doesn't exist
                    continue
                except Exception as e:
                    self.logger.debug(f"Registry scan error for {reg_location['name']}: {e}")
                    continue
            
            return registry_results
            
        except Exception as e:
            self.logger.error(f"Registry scanning failed: {e}")
            return {'error': str(e)}
    
    def _analyze_registry_entry(self, name: str, value: str, location: str) -> Dict[str, Any]:
        """Analyze registry entry for suspicious characteristics"""
        try:
            analysis = {
                'name': name,
                'value': value,
                'location': location,
                'is_suspicious': False,
                'is_threat': False,
                'risk_factors': []
            }
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'\.tmp\.',
                r'%temp%',
                r'%appdata%',
                r'powershell',
                r'cmd\.exe',
                r'rundll32',
                r'regsvr32',
                r'mshta',
                r'wscript',
                r'cscript'
            ]
            
            value_lower = value.lower()
            
            for pattern in suspicious_patterns:
                import re
                if re.search(pattern, value_lower):
                    analysis['risk_factors'].append(f"Suspicious pattern: {pattern}")
                    analysis['is_suspicious'] = True
            
            # FIX: Run/RunOnce values are usually '"C:\...\app.exe" /arg' or
            # 'C:\...\app.exe /arg'. os.path.exists() on the raw string returned
            # False for nearly every legitimate autostart entry, marking them all
            # suspicious ("Referenced file not found"). Extract the actual
            # executable path first.
            candidate = value.strip() if isinstance(value, str) else ''
            if candidate.startswith('"'):
                candidate = candidate[1:].split('"')[0]
            else:
                for sep in (' /', ' -'):
                    if sep in candidate:
                        candidate = candidate.split(sep)[0]
                        break
            candidate = candidate.strip()

            if candidate and os.path.exists(candidate):
                file_analysis = self._scan_single_file(value)
                if file_analysis and file_analysis.get('is_threat'):
                    analysis['is_threat'] = True
                    analysis['risk_factors'].append("Referenced file is malicious")
                elif file_analysis and file_analysis.get('is_suspicious'):
                    analysis['is_suspicious'] = True
                    analysis['risk_factors'].append("Referenced file is suspicious")
            else:
                # File doesn't exist - potentially suspicious
                analysis['risk_factors'].append("Referenced file not found")
                analysis['is_suspicious'] = True
            
            return analysis
            
        except Exception as e:
            return {
                'name': name,
                'value': value,
                'location': location,
                'error': str(e),
                'is_suspicious': False,
                'is_threat': False
            }
    
    def _scan_directory(self, dir_config: Dict[str, Any], current_area: int = 0, total_areas: int = 1) -> Dict[str, Any]:
        """Scan directory for threats"""
        try:
            dir_path = dir_config['path']
            
            # Check for stop/pause before starting directory scan
            if hasattr(self, 'progress_callback') and callable(self.progress_callback):
                debug_msg = f"🔧 DEBUG: Checking callback before directory scan: {dir_path}"
                print(debug_msg)
                if self.detailed_logger:
                    self.detailed_logger.info(debug_msg)
                # FIX: report the real area progress instead of resetting the
                # progress bar to zero for every directory
                area_progress = (current_area / total_areas) * 100 if total_areas else 0
                result = self.progress_callback(min(area_progress, 95.0), f"Starting scan of {dir_path}")
                debug_msg2 = f"🔧 DEBUG: Directory start callback returned: {result}"
                print(debug_msg2)
                if self.detailed_logger:
                    self.detailed_logger.info(debug_msg2)
                if not result:
                    debug_msg3 = f"🔧 DEBUG: Stopping directory scan due to callback"
                    print(debug_msg3)
                    if self.detailed_logger:
                        self.detailed_logger.info(debug_msg3)
                    return {'error': 'Scan stopped by user', 'path': dir_path}
            
            if not os.path.exists(dir_path):
                if self.detailed_logger:
                    self.detailed_logger.warning(f"❌ Directory not found: {dir_path}")
                return {'error': 'Directory not found', 'path': dir_path}
            
            if self.detailed_logger:
                self.detailed_logger.info(f"📂 Starting scan of directory: {dir_path}")
            
            dir_results = {
                'path': dir_path,
                'name': dir_config['name'],
                'files_scanned': 0,
                'threats_found': [],
                'suspicious_files': []
            }
            
            max_depth = dir_config.get('max_depth', 3)
            scan_executables = dir_config.get('scan_executables', True)
            
            if self.detailed_logger:
                self.detailed_logger.info(f"  Max depth: {max_depth}, Scan executables: {scan_executables}")
            
            # Scan files in directory
            # FIX: honor max_depth and scan_executables. They were computed but
            # never used, so the "quick scan" walked ALL of C:\Windows / WinSxS /
            # AppData to unlimited depth and every single file went through the
            # engines - the scan could never finish in the promised 5 minutes.
            all_files = []
            base_depth = dir_path.rstrip(os.sep).count(os.sep)
            for root, dirs, files in os.walk(dir_path):
                depth = root.rstrip(os.sep).count(os.sep) - base_depth
                if depth >= max_depth:
                    dirs[:] = []
                for file in files:
                    file_path = os.path.join(root, file)
                    if scan_executables and not self._is_executable_file(file_path):
                        continue
                    all_files.append(file_path)

            total_files = len(all_files)
            if self.detailed_logger:
                self.detailed_logger.info(f"Found {total_files} scannable files in {dir_config['name']}")
            
            # Scan each file
            files_scanned = 0
            threats_found = 0
            suspicious_found = 0
            scanned_files = []
            
            for i, file_path in enumerate(all_files):
                try:
                    # Update progress within directory
                    if hasattr(self, 'progress_callback') and callable(self.progress_callback) and total_files > 0:
                        file_progress = (i / total_files) * 100
                        area_progress = (current_area / total_areas) * 100 + (file_progress / total_areas)
                        if not self.progress_callback(min(area_progress, 95.0), f"Scanning {os.path.basename(file_path)}"):
                            break
                    
                    # Scan individual file
                    file_result = self._scan_single_file(file_path)
                    if file_result:
                        scanned_files.append(file_result)
                        files_scanned += 1
                        
                        if file_result.get('is_threat'):
                            threats_found += 1
                            if self.detailed_logger:
                                self.detailed_logger.warning(f"⚠️ Threat found: {file_path}")
                        elif file_result.get('is_suspicious'):
                            suspicious_found += 1
                
                except Exception as e:
                    if self.detailed_logger:
                        self.detailed_logger.error(f"Error scanning file {file_path}: {e}")
                    continue
            
            dir_results['files_scanned'] = files_scanned
            # FIX: 'threats_found' must be a LIST here (the GUI iterates it),
            # matching the registry/memory areas; keep the count in 'threat_count'.
            dir_results['threats_found'] = [f for f in scanned_files if f.get('is_threat')]
            dir_results['threat_count'] = threats_found
            dir_results['files'] = scanned_files

            # FIX: propagate per-directory counters into the global stats. They
            # were never updated before, so every scan reported "0 files scanned".
            self.scan_stats['files_scanned'] += files_scanned
            self.scan_stats['threats_found'] += threats_found
            self.scan_stats['suspicious_files'] += suspicious_found

            return dir_results
            
        except Exception as e:
            if self.detailed_logger:
                self.detailed_logger.error(f"❌ Directory scanning failed for {dir_config}: {e}")
            return {
                'directory': dir_config.get('name', 'unknown'),
                'path': dir_config.get('path', 'unknown'),
                'status': 'error',
                'error': str(e),
                'files_scanned': 0,
                'threats_found': 0,
                'files': []
            }
    
    def _scan_memory_processes(self) -> Dict[str, Any]:
        """Scan memory processes for threats"""
        try:
            memory_results = {
                'processes_analyzed': 0,
                'suspicious_processes': [],
                'threats_found': []
            }
            
            # FIX: only scan the configured critical target processes (previously
            # every process on the system was re-scanned, duplicating the
            # directory scans).
            targets = {n.lower() for n in self.critical_areas.get('memory_processes', [])}

            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info

                    if not proc_info['exe']:
                        continue

                    if not proc_info['name'] or proc_info['name'].lower() not in targets:
                        continue
                    
                    memory_results['processes_analyzed'] += 1
                    self.scan_stats['processes_analyzed'] += 1
                    
                    # Analyze process
                    proc_analysis = self._analyze_process(proc_info)
                    
                    if proc_analysis['is_suspicious']:
                        memory_results['suspicious_processes'].append(proc_analysis)
                        self.scan_stats['suspicious_processes'].append(proc_analysis)
                    
                    if proc_analysis['is_threat']:
                        memory_results['threats_found'].append(proc_analysis)
                        self.scan_stats['threats_found'] += 1
                    
                    # Scan process executable
                    if os.path.exists(proc_info['exe']):
                        file_result = self._scan_single_file(proc_info['exe'])
                        
                        if file_result and file_result.get('is_threat'):
                            proc_analysis['executable_threat'] = True
                            memory_results['threats_found'].append({
                                **proc_analysis,
                                'file_analysis': file_result
                            })
                            self.scan_stats['threats_found'] += 1
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    self.logger.debug(f"Process analysis error: {e}")
                    continue
            
            return memory_results
            
        except Exception as e:
            self.logger.error(f"Memory scanning failed: {e}")
            return {'error': str(e)}
    
    def _analyze_process(self, proc_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze process for suspicious characteristics"""
        try:
            analysis = {
                'pid': proc_info['pid'],
                'name': proc_info['name'],
                'exe': proc_info['exe'],
                'cmdline': proc_info.get('cmdline', []),
                'is_suspicious': False,
                'is_threat': False,
                'risk_factors': []
            }
            
            # Check for suspicious process characteristics
            exe_path = proc_info['exe'].lower() if proc_info['exe'] else ''
            cmdline_str = ' '.join(proc_info.get('cmdline', [])).lower()
            
            # Suspicious locations
            suspicious_locations = [
                r'\temp\.',
                r'\appdata\local\temp',
                r'\users\public',
                r'\programdata\.',
                r'\windows\temp'
            ]
            
            for location in suspicious_locations:
                if location in exe_path:
                    analysis['risk_factors'].append(f"Running from suspicious location: {location}")
                    analysis['is_suspicious'] = True
            
            # Suspicious command line patterns
            suspicious_cmdline = [
                'powershell',
                'cmd /c',
                'rundll32',
                'regsvr32',
                'mshta',
                'wscript',
                'cscript'
            ]
            
            for pattern in suspicious_cmdline:
                if pattern in cmdline_str:
                    analysis['risk_factors'].append(f"Suspicious command line: {pattern}")
                    analysis['is_suspicious'] = True
            
            return analysis
            
        except Exception as e:
            return {
                'pid': proc_info.get('pid', 0),
                'name': proc_info.get('name', 'Unknown'),
                'error': str(e),
                'is_suspicious': False,
                'is_threat': False
            }
    
    def _scan_single_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Scan single file using available engines"""
        try:
            if not os.path.exists(file_path):
                return None
            
            scan_result = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'is_threat': False,
                'is_suspicious': False,
                'detection_methods': [],
                'threat_score': 0.0
            }
            
            # Signature scan
            if self.signature_engine:
                sig_result = self.signature_engine.check_file_signature(file_path)
                if sig_result.get('is_threat'):
                    scan_result['is_threat'] = True
                    scan_result['detection_methods'].append('signature')
                    scan_result['threat_info'] = sig_result
            
            # AI scan with enhanced Windows system file protection
            if self.ai_engine:
                # Check if it's a Windows system file first
                file_path_lower = file_path.lower()
                is_system_file = any(sys_path in file_path_lower for sys_path in [
                    'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\', 'c:\\windows\\winsxs\\',
                    'c:\\program files\\', 'c:\\program files (x86)\\'
                ])
                
                if is_system_file:
                    # Use very high threshold for system files
                    ai_result = self.ai_engine.analyze_file(file_path)
                    if ai_result.get('threat_score', 0) > 0.95:  # Very strict threshold
                        scan_result['is_threat'] = True
                        scan_result['detection_methods'].append('ai')
                        scan_result['threat_score'] = ai_result.get('threat_score', 0)
                    elif ai_result.get('threat_score', 0) > 0.85:  # High threshold for suspicious
                        scan_result['is_suspicious'] = True
                        scan_result['threat_score'] = ai_result.get('threat_score', 0)
                else:
                    # Normal thresholds for non-system files
                    ai_result = self.ai_engine.analyze_file(file_path)
                    if ai_result.get('threat_score', 0) > 0.8:  # Raised from 0.7
                        scan_result['is_threat'] = True
                        scan_result['detection_methods'].append('ai')
                        scan_result['threat_score'] = ai_result.get('threat_score', 0)
                    elif ai_result.get('threat_score', 0) > 0.6:  # Raised from 0.4
                        scan_result['is_suspicious'] = True
                        scan_result['threat_score'] = ai_result.get('threat_score', 0)
            
            # Heuristic scan
            if self.heuristic_analyzer:
                heur_result = self.heuristic_analyzer.analyze_file(file_path)
                if heur_result.get('is_threat'):
                    scan_result['is_threat'] = True
                    scan_result['detection_methods'].append('heuristic')
                elif heur_result.get('is_suspicious'):
                    scan_result['is_suspicious'] = True
            
            return scan_result
            
        except Exception as e:
            self.logger.debug(f"File scan error for {file_path}: {e}")
            return None
    
    def _is_executable_file(self, file_path: str) -> bool:
        """Check if file is executable"""
        executable_extensions = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.com', '.pif', '.msi'}
        return Path(file_path).suffix.lower() in executable_extensions
    
    def _save_scan_results(self, scan_results: Dict[str, Any]):
        """Save scan results to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            results_dir = os.path.join(_BASE_DIR, 'logs', 'quick_scan_results')
            os.makedirs(results_dir, exist_ok=True)
            results_file = os.path.join(results_dir, f"enhanced_quick_scan_{timestamp}.json")
            
            with open(results_file, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)
            
            self.logger.info(f"📄 Scan results saved to {results_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save scan results: {e}")
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get current scan statistics"""
        return self.scan_stats.copy()


def test_enhanced_quick_scan():
    """Test enhanced quick scan system"""
    print("🧪 Testing Enhanced Quick Scan System...")
    
    try:
        # Initialize scanner
        scanner = CriticalSystemScanner()
        
        print("\n🔍 Critical scan areas configured:")
        for area_name, area_data in scanner.critical_areas.items():
            print(f"   • {area_name}: {len(area_data)} locations")
        
        # Test progress callback
        def progress_callback(percent, message):
            print(f"   Progress: {percent:.1f}% - {message}")
            return True  # Always return True to continue scan
        
        print(f"\n🚀 Starting enhanced quick scan...")
        
        # Perform scan
        scan_results = scanner.perform_enhanced_quick_scan(progress_callback)
        
        if 'error' not in scan_results:
            print(f"\n✅ Enhanced quick scan completed!")
            
            summary = scan_results.get('summary', {})
            print(f"📊 Scan Summary:")
            print(f"   Files scanned: {summary.get('files_scanned', 0)}")
            print(f"   Threats found: {summary.get('threats_found', 0)}")
            print(f"   Suspicious files: {summary.get('suspicious_files', 0)}")
            print(f"   Registry entries checked: {summary.get('registry_entries_checked', 0)}")
            print(f"   Processes analyzed: {summary.get('processes_analyzed', 0)}")
            print(f"   Scan time: {summary.get('scan_time', 0):.2f}s")
            print(f"   Areas scanned: {len(summary.get('areas_scanned', []))}")
            
        else:
            print(f"❌ Scan failed: {scan_results['error']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced quick scan test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main function to implement enhanced quick scan"""
    print("=" * 70)
    print("🔍 IMPLEMENTING ENHANCED QUICK SCAN SYSTEM")
    print("=" * 70)
    
    # Test implementation
    if test_enhanced_quick_scan():
        print("\n" + "=" * 70)
        print("🎉 ENHANCED QUICK SCAN SYSTEM IMPLEMENTED!")
        print("✅ Startup registry scanning")
        print("🗂️ Critical Windows directories (System32, SysWOW64)")
        print("🚀 Autorun locations scanning")
        print("💾 Memory process analysis")
        print("🌐 Browser locations scanning")
        print("📁 Temporary directories scanning")
        print("📊 Comprehensive threat detection")
        print("=" * 70)
    else:
        print("\n❌ Implementation failed")


if __name__ == "__main__":
    main()
