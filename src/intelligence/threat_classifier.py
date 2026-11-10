#!/usr/bin/env python3
"""
Threat Classification and Scoring System for AI Antivirus
Advanced threat analysis and risk assessment
"""

import os
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import json
import sqlite3
import hashlib
import re

from .threat_intelligence_engine import ThreatLevel, ThreatCategory

class RiskFactor(Enum):
    """Risk assessment factors"""
    FILE_ENTROPY = "file_entropy"
    SUSPICIOUS_STRINGS = "suspicious_strings"
    NETWORK_BEHAVIOR = "network_behavior"
    REGISTRY_MODIFICATIONS = "registry_modifications"
    FILE_OPERATIONS = "file_operations"
    PROCESS_INJECTION = "process_injection"
    ANTI_ANALYSIS = "anti_analysis"
    PERSISTENCE_MECHANISMS = "persistence_mechanisms"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"

@dataclass
class ThreatScore:
    """Comprehensive threat scoring"""
    overall_score: float
    confidence: float
    risk_factors: Dict[RiskFactor, float]
    behavioral_score: float
    static_score: float
    intelligence_score: float
    severity_level: ThreatLevel
    classification: ThreatCategory
    reasoning: List[str]
    recommendations: List[str]

class ThreatClassifier:
    """Advanced threat classification and scoring system"""
    
    def __init__(self, intelligence_engine=None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.intelligence.threat_classifier')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.intelligence_engine = intelligence_engine
        
        # Classification rules and weights
        self.classification_rules = self._load_classification_rules()
        self.risk_weights = self._load_risk_weights()
        
        # Behavioral patterns
        self.malware_patterns = self._load_malware_patterns()
        self.suspicious_strings = self._load_suspicious_strings()
        
        # Machine learning models (placeholders for future implementation)
        self.ml_models = {}
        
    def _load_classification_rules(self) -> Dict:
        """Load threat classification rules"""
        return {
            'file_size_thresholds': {
                'suspicious_small': 1024,  # Files smaller than 1KB
                'suspicious_large': 100 * 1024 * 1024  # Files larger than 100MB
            },
            'entropy_thresholds': {
                'low': 3.0,
                'medium': 5.0,
                'high': 7.0,
                'very_high': 7.5
            },
            'string_analysis': {
                'min_suspicious_strings': 3,
                'critical_string_threshold': 1
            },
            'behavioral_thresholds': {
                'low_risk': 0.3,
                'medium_risk': 0.5,
                'high_risk': 0.7,
                'critical_risk': 0.9
            }
        }
    
    def _load_risk_weights(self) -> Dict[RiskFactor, float]:
        """Load risk factor weights"""
        return {
            RiskFactor.FILE_ENTROPY: 0.15,
            RiskFactor.SUSPICIOUS_STRINGS: 0.20,
            RiskFactor.NETWORK_BEHAVIOR: 0.15,
            RiskFactor.REGISTRY_MODIFICATIONS: 0.10,
            RiskFactor.FILE_OPERATIONS: 0.10,
            RiskFactor.PROCESS_INJECTION: 0.15,
            RiskFactor.ANTI_ANALYSIS: 0.05,
            RiskFactor.PERSISTENCE_MECHANISMS: 0.05,
            RiskFactor.PRIVILEGE_ESCALATION: 0.03,
            RiskFactor.DATA_EXFILTRATION: 0.02
        }
    
    def _load_malware_patterns(self) -> Dict:
        """Load behavioral patterns for different malware types"""
        return {
            'ransomware': {
                'file_operations': ['encrypt', 'delete_shadow_copies', 'mass_file_changes'],
                'network_behavior': ['tor_communication', 'bitcoin_addresses'],
                'registry_modifications': ['disable_system_restore', 'modify_boot_settings'],
                'strings': ['ransom', 'bitcoin', 'decrypt', 'payment', 'locked']
            },
            'trojan': {
                'network_behavior': ['c2_communication', 'data_upload', 'remote_access'],
                'process_injection': ['dll_injection', 'process_hollowing'],
                'persistence': ['registry_autorun', 'scheduled_tasks'],
                'strings': ['backdoor', 'remote', 'control', 'keylog']
            },
            'spyware': {
                'data_exfiltration': ['keylogging', 'screenshot_capture', 'credential_theft'],
                'network_behavior': ['data_upload', 'stealth_communication'],
                'anti_analysis': ['vm_detection', 'debugger_detection'],
                'strings': ['keylog', 'password', 'steal', 'capture']
            },
            'adware': {
                'network_behavior': ['ad_requests', 'tracking_beacons'],
                'file_operations': ['browser_modification', 'shortcut_creation'],
                'registry_modifications': ['browser_settings', 'homepage_change'],
                'strings': ['advertisement', 'popup', 'banner', 'click']
            }
        }
    
    def _load_suspicious_strings(self) -> Dict:
        """Load suspicious string patterns"""
        return {
            'critical': [
                r'CreateRemoteThread',
                r'VirtualAllocEx',
                r'WriteProcessMemory',
                r'SetWindowsHookEx',
                r'GetProcAddress',
                r'LoadLibrary',
                r'NtCreateSection',
                r'ZwMapViewOfSection'
            ],
            'high': [
                r'RegCreateKey',
                r'RegSetValue',
                r'CreateProcess',
                r'ShellExecute',
                r'WinExec',
                r'CreateFile',
                r'DeleteFile',
                r'CopyFile'
            ],
            'medium': [
                r'InternetOpen',
                r'InternetConnect',
                r'HttpSendRequest',
                r'URLDownloadToFile',
                r'GetSystemDirectory',
                r'GetWindowsDirectory'
            ],
            'behavioral': [
                r'bitcoin',
                r'ransom',
                r'decrypt',
                r'keylog',
                r'password',
                r'backdoor',
                r'trojan',
                r'virus'
            ]
        }
    
    def classify_threat(self, file_path: str, file_data: bytes = None, 
                       behavioral_data: Dict = None, ai_score: float = None) -> ThreatScore:
        """Comprehensive threat classification and scoring"""
        try:
            # Initialize scoring components
            risk_factors = {}
            reasoning = []
            recommendations = []
            
            # Static analysis scoring
            static_score = self._analyze_static_features(file_path, file_data, risk_factors, reasoning)
            
            # Behavioral analysis scoring
            behavioral_score = self._analyze_behavioral_features(behavioral_data, risk_factors, reasoning)
            
            # Intelligence-based scoring
            intelligence_score = self._analyze_intelligence_features(file_path, file_data, risk_factors, reasoning)
            
            # AI model scoring (if available)
            ai_contribution = ai_score if ai_score is not None else 0.0
            
            # Calculate weighted overall score
            overall_score = self._calculate_overall_score(
                static_score, behavioral_score, intelligence_score, ai_contribution
            )
            
            # Determine severity level and classification
            severity_level = self._determine_severity_level(overall_score, risk_factors)
            classification = self._determine_classification(risk_factors, reasoning)
            
            # Calculate confidence based on available data
            confidence = self._calculate_confidence(
                static_score, behavioral_score, intelligence_score, ai_contribution
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(severity_level, classification, risk_factors)
            
            return ThreatScore(
                overall_score=overall_score,
                confidence=confidence,
                risk_factors=risk_factors,
                behavioral_score=behavioral_score,
                static_score=static_score,
                intelligence_score=intelligence_score,
                severity_level=severity_level,
                classification=classification,
                reasoning=reasoning,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Error classifying threat for {file_path}: {e}")
            return self._create_error_score(str(e))
    
    def _analyze_static_features(self, file_path: str, file_data: bytes, 
                                risk_factors: Dict, reasoning: List[str]) -> float:
        """Analyze static file features"""
        try:
            score = 0.0
            
            if not file_data:
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                except Exception as e:
                    reasoning.append(f"Could not read file: {e}")
                    return 0.0
            
            # File size analysis
            file_size = len(file_data)
            size_score = self._analyze_file_size(file_size, reasoning)
            risk_factors[RiskFactor.FILE_ENTROPY] = size_score
            score += size_score * 0.1
            
            # Entropy analysis
            entropy_score = self._calculate_entropy(file_data, reasoning)
            risk_factors[RiskFactor.FILE_ENTROPY] = entropy_score
            score += entropy_score * 0.3
            
            # String analysis
            string_score = self._analyze_suspicious_strings(file_data, reasoning)
            risk_factors[RiskFactor.SUSPICIOUS_STRINGS] = string_score
            score += string_score * 0.4
            
            # Anti-analysis techniques
            anti_analysis_score = self._detect_anti_analysis(file_data, reasoning)
            risk_factors[RiskFactor.ANTI_ANALYSIS] = anti_analysis_score
            score += anti_analysis_score * 0.2
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error in static analysis: {e}")
            reasoning.append(f"Static analysis error: {e}")
            return 0.0
    
    def _analyze_behavioral_features(self, behavioral_data: Dict, 
                                   risk_factors: Dict, reasoning: List[str]) -> float:
        """Analyze behavioral features"""
        try:
            if not behavioral_data:
                return 0.0
            
            score = 0.0
            
            # Network behavior analysis
            network_score = self._analyze_network_behavior(behavioral_data.get('network', {}), reasoning)
            risk_factors[RiskFactor.NETWORK_BEHAVIOR] = network_score
            score += network_score * 0.25
            
            # Registry modifications
            registry_score = self._analyze_registry_behavior(behavioral_data.get('registry', {}), reasoning)
            risk_factors[RiskFactor.REGISTRY_MODIFICATIONS] = registry_score
            score += registry_score * 0.20
            
            # File operations
            file_ops_score = self._analyze_file_operations(behavioral_data.get('file_ops', {}), reasoning)
            risk_factors[RiskFactor.FILE_OPERATIONS] = file_ops_score
            score += file_ops_score * 0.20
            
            # Process injection
            injection_score = self._analyze_process_injection(behavioral_data.get('processes', {}), reasoning)
            risk_factors[RiskFactor.PROCESS_INJECTION] = injection_score
            score += injection_score * 0.20
            
            # Persistence mechanisms
            persistence_score = self._analyze_persistence(behavioral_data.get('persistence', {}), reasoning)
            risk_factors[RiskFactor.PERSISTENCE_MECHANISMS] = persistence_score
            score += persistence_score * 0.15
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error in behavioral analysis: {e}")
            reasoning.append(f"Behavioral analysis error: {e}")
            return 0.0
    
    def _analyze_intelligence_features(self, file_path: str, file_data: bytes,
                                     risk_factors: Dict, reasoning: List[str]) -> float:
        """Analyze threat intelligence features"""
        try:
            if not self.intelligence_engine:
                return 0.0
            
            score = 0.0
            
            # Calculate file hashes
            if file_data:
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha1_hash = hashlib.sha1(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                
                # Query threat intelligence
                for hash_value, hash_type in [(md5_hash, 'md5'), (sha1_hash, 'sha1'), (sha256_hash, 'sha256')]:
                    threats = self.intelligence_engine.query_threat_intelligence(hash_value, hash_type)
                    
                    if threats:
                        max_threat_score = 0.0
                        for threat in threats:
                            threat_score = threat.confidence_score * (threat.threat_level.value / 4.0)
                            max_threat_score = max(max_threat_score, threat_score)
                            
                            reasoning.append(f"Known threat: {threat.threat_name} ({threat.source})")
                        
                        score = max(score, max_threat_score)
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error in intelligence analysis: {e}")
            reasoning.append(f"Intelligence analysis error: {e}")
            return 0.0
    
    def _calculate_entropy(self, data: bytes, reasoning: List[str]) -> float:
        """Calculate file entropy"""
        try:
            if len(data) == 0:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * np.log2(probability)
            
            # Normalize entropy (0-1 scale)
            normalized_entropy = entropy / 8.0
            
            # Determine risk level
            thresholds = self.classification_rules['entropy_thresholds']
            if entropy > thresholds['very_high']:
                reasoning.append(f"Very high entropy ({entropy:.2f}) - likely packed/encrypted")
                return 0.9
            elif entropy > thresholds['high']:
                reasoning.append(f"High entropy ({entropy:.2f}) - possibly packed")
                return 0.7
            elif entropy > thresholds['medium']:
                reasoning.append(f"Medium entropy ({entropy:.2f}) - some compression")
                return 0.4
            elif entropy < thresholds['low']:
                reasoning.append(f"Low entropy ({entropy:.2f}) - mostly text/padding")
                return 0.2
            else:
                return normalized_entropy
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    def _analyze_suspicious_strings(self, data: bytes, reasoning: List[str]) -> float:
        """Analyze suspicious strings in file"""
        try:
            # Convert to string for analysis
            try:
                text = data.decode('utf-8', errors='ignore')
            except:
                text = str(data)
            
            score = 0.0
            found_strings = []
            
            # Check for different categories of suspicious strings
            for category, patterns in self.suspicious_strings.items():
                category_score = 0.0
                category_matches = []
                
                for pattern in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        category_matches.extend(matches)
                
                if category_matches:
                    found_strings.extend(category_matches)
                    
                    if category == 'critical':
                        category_score = min(len(category_matches) * 0.3, 1.0)
                    elif category == 'high':
                        category_score = min(len(category_matches) * 0.2, 0.8)
                    elif category == 'medium':
                        category_score = min(len(category_matches) * 0.1, 0.6)
                    elif category == 'behavioral':
                        category_score = min(len(category_matches) * 0.15, 0.7)
                
                score = max(score, category_score)
            
            if found_strings:
                reasoning.append(f"Found {len(found_strings)} suspicious strings: {found_strings[:5]}")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing strings: {e}")
            return 0.0
    
    def _analyze_file_size(self, file_size: int, reasoning: List[str]) -> float:
        """Analyze file size for suspicious characteristics"""
        try:
            thresholds = self.classification_rules['file_size_thresholds']
            
            if file_size < thresholds['suspicious_small']:
                reasoning.append(f"Unusually small file size: {file_size} bytes")
                return 0.3
            elif file_size > thresholds['suspicious_large']:
                reasoning.append(f"Unusually large file size: {file_size} bytes")
                return 0.4
            else:
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error analyzing file size: {e}")
            return 0.0
    
    def _detect_anti_analysis(self, data: bytes, reasoning: List[str]) -> float:
        """Detect anti-analysis techniques"""
        try:
            text = data.decode('utf-8', errors='ignore')
            score = 0.0
            
            # Common anti-analysis strings
            anti_analysis_patterns = [
                r'IsDebuggerPresent',
                r'CheckRemoteDebuggerPresent',
                r'GetTickCount',
                r'QueryPerformanceCounter',
                r'VirtualBox',
                r'VMware',
                r'QEMU',
                r'Sandboxie'
            ]
            
            found_patterns = []
            for pattern in anti_analysis_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    found_patterns.append(pattern)
                    score += 0.2
            
            if found_patterns:
                reasoning.append(f"Anti-analysis techniques detected: {found_patterns}")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error detecting anti-analysis: {e}")
            return 0.0
    
    def _analyze_network_behavior(self, network_data: Dict, reasoning: List[str]) -> float:
        """Analyze network behavior patterns"""
        try:
            if not network_data:
                return 0.0
            
            score = 0.0
            
            # Suspicious domains/IPs
            suspicious_domains = network_data.get('suspicious_domains', [])
            if suspicious_domains:
                score += min(len(suspicious_domains) * 0.2, 0.8)
                reasoning.append(f"Suspicious domains contacted: {suspicious_domains[:3]}")
            
            # C2 communication patterns
            c2_indicators = network_data.get('c2_indicators', [])
            if c2_indicators:
                score += 0.6
                reasoning.append("Command and control communication detected")
            
            # Data exfiltration
            large_uploads = network_data.get('large_uploads', 0)
            if large_uploads > 0:
                score += min(large_uploads * 0.1, 0.4)
                reasoning.append(f"Large data uploads detected: {large_uploads}")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing network behavior: {e}")
            return 0.0
    
    def _analyze_registry_behavior(self, registry_data: Dict, reasoning: List[str]) -> float:
        """Analyze registry modification patterns"""
        try:
            if not registry_data:
                return 0.0
            
            score = 0.0
            
            # Autorun modifications
            autorun_changes = registry_data.get('autorun_changes', [])
            if autorun_changes:
                score += min(len(autorun_changes) * 0.3, 0.8)
                reasoning.append(f"Autorun registry changes: {len(autorun_changes)}")
            
            # Security settings modifications
            security_changes = registry_data.get('security_changes', [])
            if security_changes:
                score += min(len(security_changes) * 0.4, 0.9)
                reasoning.append("Security settings modified")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing registry behavior: {e}")
            return 0.0
    
    def _analyze_file_operations(self, file_ops_data: Dict, reasoning: List[str]) -> float:
        """Analyze file operation patterns"""
        try:
            if not file_ops_data:
                return 0.0
            
            score = 0.0
            
            # Mass file operations
            files_modified = file_ops_data.get('files_modified', 0)
            if files_modified > 100:
                score += 0.7
                reasoning.append(f"Mass file modification: {files_modified} files")
            elif files_modified > 50:
                score += 0.5
                reasoning.append(f"Many files modified: {files_modified}")
            
            # System file modifications
            system_files_modified = file_ops_data.get('system_files_modified', [])
            if system_files_modified:
                score += 0.8
                reasoning.append("System files modified")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing file operations: {e}")
            return 0.0
    
    def _analyze_process_injection(self, process_data: Dict, reasoning: List[str]) -> float:
        """Analyze process injection techniques"""
        try:
            if not process_data:
                return 0.0
            
            score = 0.0
            
            # Process hollowing
            if process_data.get('process_hollowing', False):
                score += 0.8
                reasoning.append("Process hollowing detected")
            
            # DLL injection
            dll_injections = process_data.get('dll_injections', [])
            if dll_injections:
                score += min(len(dll_injections) * 0.3, 0.7)
                reasoning.append(f"DLL injection detected: {len(dll_injections)}")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing process injection: {e}")
            return 0.0
    
    def _analyze_persistence(self, persistence_data: Dict, reasoning: List[str]) -> float:
        """Analyze persistence mechanisms"""
        try:
            if not persistence_data:
                return 0.0
            
            score = 0.0
            
            # Scheduled tasks
            scheduled_tasks = persistence_data.get('scheduled_tasks', [])
            if scheduled_tasks:
                score += min(len(scheduled_tasks) * 0.3, 0.6)
                reasoning.append(f"Scheduled tasks created: {len(scheduled_tasks)}")
            
            # Service installation
            services_installed = persistence_data.get('services_installed', [])
            if services_installed:
                score += min(len(services_installed) * 0.4, 0.7)
                reasoning.append(f"Services installed: {len(services_installed)}")
            
            return min(score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error analyzing persistence: {e}")
            return 0.0
    
    def _calculate_overall_score(self, static_score: float, behavioral_score: float,
                               intelligence_score: float, ai_score: float) -> float:
        """Calculate weighted overall threat score"""
        try:
            # Weights for different analysis types
            weights = {
                'static': 0.25,
                'behavioral': 0.35,
                'intelligence': 0.30,
                'ai': 0.10
            }
            
            overall_score = (
                static_score * weights['static'] +
                behavioral_score * weights['behavioral'] +
                intelligence_score * weights['intelligence'] +
                ai_score * weights['ai']
            )
            
            return min(overall_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating overall score: {e}")
            return 0.0
    
    def _determine_severity_level(self, overall_score: float, risk_factors: Dict) -> ThreatLevel:
        """Determine threat severity level"""
        try:
            thresholds = self.classification_rules['behavioral_thresholds']
            
            if overall_score >= thresholds['critical_risk']:
                return ThreatLevel.CRITICAL
            elif overall_score >= thresholds['high_risk']:
                return ThreatLevel.HIGH
            elif overall_score >= thresholds['medium_risk']:
                return ThreatLevel.MEDIUM
            elif overall_score >= thresholds['low_risk']:
                return ThreatLevel.LOW
            else:
                return ThreatLevel.UNKNOWN
                
        except Exception as e:
            self.logger.error(f"Error determining severity level: {e}")
            return ThreatLevel.UNKNOWN
    
    def _determine_classification(self, risk_factors: Dict, reasoning: List[str]) -> ThreatCategory:
        """Determine threat classification based on patterns"""
        try:
            # Analyze reasoning for classification hints
            reasoning_text = ' '.join(reasoning).lower()
            
            # Check for specific malware type indicators
            if any(word in reasoning_text for word in ['ransom', 'encrypt', 'bitcoin']):
                return ThreatCategory.RANSOMWARE
            elif any(word in reasoning_text for word in ['backdoor', 'remote', 'c2', 'command']):
                return ThreatCategory.BACKDOOR
            elif any(word in reasoning_text for word in ['trojan', 'injection', 'hollow']):
                return ThreatCategory.TROJAN
            elif any(word in reasoning_text for word in ['keylog', 'password', 'steal']):
                return ThreatCategory.SPYWARE
            elif any(word in reasoning_text for word in ['advertisement', 'popup', 'banner']):
                return ThreatCategory.ADWARE
            elif any(word in reasoning_text for word in ['rootkit', 'hide', 'stealth']):
                return ThreatCategory.ROOTKIT
            else:
                return ThreatCategory.MALWARE
                
        except Exception as e:
            self.logger.error(f"Error determining classification: {e}")
            return ThreatCategory.SUSPICIOUS
    
    def _calculate_confidence(self, static_score: float, behavioral_score: float,
                            intelligence_score: float, ai_score: float) -> float:
        """Calculate confidence in the threat assessment"""
        try:
            # Base confidence on availability of different analysis types
            confidence_factors = []
            
            if static_score > 0:
                confidence_factors.append(0.6)
            if behavioral_score > 0:
                confidence_factors.append(0.8)
            if intelligence_score > 0:
                confidence_factors.append(0.9)
            if ai_score > 0:
                confidence_factors.append(0.7)
            
            if not confidence_factors:
                return 0.1
            
            # Average confidence with bonus for multiple sources
            base_confidence = sum(confidence_factors) / len(confidence_factors)
            multi_source_bonus = min(len(confidence_factors) * 0.1, 0.3)
            
            return min(base_confidence + multi_source_bonus, 1.0)
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence: {e}")
            return 0.5
    
    def _generate_recommendations(self, severity_level: ThreatLevel, 
                                classification: ThreatCategory, 
                                risk_factors: Dict) -> List[str]:
        """Generate actionable recommendations"""
        try:
            recommendations = []
            
            # Severity-based recommendations
            if severity_level == ThreatLevel.CRITICAL:
                recommendations.extend([
                    "Immediately quarantine the file",
                    "Perform full system scan",
                    "Check for lateral movement",
                    "Review system logs for compromise indicators"
                ])
            elif severity_level == ThreatLevel.HIGH:
                recommendations.extend([
                    "Quarantine the file",
                    "Scan related files and directories",
                    "Monitor system for suspicious activity"
                ])
            elif severity_level == ThreatLevel.MEDIUM:
                recommendations.extend([
                    "Consider quarantining the file",
                    "Perform additional analysis",
                    "Monitor file behavior"
                ])
            
            # Classification-specific recommendations
            if classification == ThreatCategory.RANSOMWARE:
                recommendations.extend([
                    "Check backup integrity",
                    "Isolate from network",
                    "Preserve forensic evidence"
                ])
            elif classification == ThreatCategory.SPYWARE:
                recommendations.extend([
                    "Check for credential theft",
                    "Review network traffic",
                    "Change passwords"
                ])
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            return ["Perform manual analysis"]
    
    def _create_error_score(self, error_message: str) -> ThreatScore:
        """Create error threat score"""
        return ThreatScore(
            overall_score=0.0,
            confidence=0.0,
            risk_factors={},
            behavioral_score=0.0,
            static_score=0.0,
            intelligence_score=0.0,
            severity_level=ThreatLevel.UNKNOWN,
            classification=ThreatCategory.SUSPICIOUS,
            reasoning=[f"Analysis error: {error_message}"],
            recommendations=["Manual analysis required due to error"]
        )
