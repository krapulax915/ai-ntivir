#!/usr/bin/env python3
"""
URL Scanner Module
=================

Advanced URL scanning and analysis for detecting malicious websites,
phishing attempts, and suspicious web content.
"""

import re
import json
import time
import hashlib
import logging
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote
from datetime import datetime

class URLScanner:
    """Advanced URL scanner for malicious content detection"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.url_scanner')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Malicious URL patterns
        self.malicious_patterns = [
            # Common malware hosting patterns
            r'\.exe\?',
            r'download\.php\?',
            r'get\.php\?file=',
            r'dl\.php\?',
            
            # Suspicious parameters
            r'[?&]cmd=',
            r'[?&]exec=',
            r'[?&]shell=',
            r'[?&]system=',
            
            # Base64 encoded content
            r'data:.*base64',
            
            # Suspicious file extensions in URLs
            r'\.(scr|pif|com|bat|cmd|exe|vbs|js)(\?|$)',
        ]
        
        # Known malicious domains (simplified list)
        self.malicious_domains = {
            'malware-site.com',
            'virus-download.net', 
            'trojan-host.org',
            'phishing-bank.com',
            'fake-security.net'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'
        }
        
        # Safe domains (major legitimate sites)
        self.safe_domains = {
            'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'mozilla.org', 'python.org', 'openai.com',
            'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'amazon.com', 'apple.com', 'adobe.com', 'nvidia.com'
        }
    
    def scan_url(self, url: str) -> Dict[str, any]:
        """Comprehensive URL scan"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            result = {
                'url': url,
                'domain': domain,
                'safe': True,
                'threat_score': 0.0,
                'threat_types': [],
                'warnings': [],
                'details': {}
            }
            
            # Check if domain is known safe
            if any(safe_domain in domain for safe_domain in self.safe_domains):
                result.update({
                    'safe': True,
                    'threat_score': 0.1,
                    'details': {'classification': 'known_safe_domain'}
                })
                return result
            
            # Check malicious domains
            if domain in self.malicious_domains:
                result.update({
                    'safe': False,
                    'threat_score': 0.95,
                    'threat_types': ['malicious_domain'],
                    'details': {'reason': 'Domain in malicious database'}
                })
                return result
            
            # Analyze URL structure
            structure_score = self._analyze_url_structure(url, parsed)
            if structure_score > 0.0:
                result['threat_score'] += structure_score
                result['warnings'].append('Suspicious URL structure')
            
            # Check for malicious patterns
            pattern_score = self._check_malicious_patterns(url)
            if pattern_score > 0.0:
                result['threat_score'] += pattern_score
                result['threat_types'].append('malicious_pattern')
            
            # Check domain reputation
            domain_score = self._check_domain_reputation(domain)
            if domain_score > 0.0:
                result['threat_score'] += domain_score
                result['warnings'].append('Suspicious domain characteristics')
            
            # Final threat assessment
            if result['threat_score'] > 0.7:
                result['safe'] = False
                result['threat_types'].append('high_risk')
            elif result['threat_score'] > 0.4:
                result['warnings'].append('Medium risk URL')
            
            result['threat_score'] = min(result['threat_score'], 1.0)
            
            return result
            
        except Exception as e:
            self.logger.error(f"URL scan error: {e}")
            return {
                'url': url,
                'safe': True,  # Default to safe on error
                'threat_score': 0.0,
                'threat_types': ['scan_error'],
                'warnings': [f'Scan failed: {e}'],
                'details': {}
            }
    
    def _analyze_url_structure(self, url: str, parsed) -> float:
        """Analyze URL structure for suspicious characteristics"""
        score = 0.0
        
        try:
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Very long domains are suspicious
            if len(domain) > 60:
                score += 0.2
            
            # IP addresses instead of domain names
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                score += 0.3
            
            # Excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 4:
                score += 0.2
            
            # Suspicious TLDs
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 0.3
                    break
            
            # URL shorteners (can hide malicious content)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
            if any(shortener in domain for shortener in shorteners):
                score += 0.1
            
            # Excessive URL encoding
            if '%' in url and url.count('%') > 8:
                score += 0.2
            
            # Very long paths (often used to hide malicious content)
            if len(path) > 100:
                score += 0.1
            
            return min(score, 0.8)
            
        except Exception as e:
            self.logger.error(f"URL structure analysis error: {e}")
            return 0.0
    
    def _check_malicious_patterns(self, url: str) -> float:
        """Check URL against known malicious patterns"""
        score = 0.0
        
        try:
            url_lower = url.lower()
            
            for pattern in self.malicious_patterns:
                if re.search(pattern, url_lower):
                    score += 0.3
                    self.logger.warning(f"Malicious pattern detected: {pattern}")
            
            return min(score, 0.8)
            
        except Exception as e:
            self.logger.error(f"Pattern check error: {e}")
            return 0.0
    
    def _check_domain_reputation(self, domain: str) -> float:
        """Check domain reputation and characteristics"""
        score = 0.0
        
        try:
            # Check for suspicious domain patterns
            suspicious_keywords = [
                'secure', 'verify', 'update', 'login', 'bank', 'paypal',
                'microsoft', 'google', 'apple', 'security', 'alert'
            ]
            
            # Domains trying to impersonate legitimate services
            for keyword in suspicious_keywords:
                if keyword in domain and not any(safe in domain for safe in self.safe_domains):
                    score += 0.2
                    break
            
            # Domains with numbers (often suspicious)
            if re.search(r'\d+', domain):
                score += 0.1
            
            # Domains with hyphens (can be suspicious)
            if domain.count('-') > 2:
                score += 0.1
            
            # Very new or temporary domains (simplified check)
            if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf']):
                score += 0.2
            
            return min(score, 0.6)
            
        except Exception as e:
            self.logger.error(f"Domain reputation check error: {e}")
            return 0.0
    
    def check_download_url(self, url: str, filename: str = "") -> Dict[str, any]:
        """Special check for download URLs"""
        try:
            # Basic URL scan first
            result = self.scan_url(url)
            
            # Additional checks for downloads
            download_score = 0.0
            
            # Check file extension in URL
            suspicious_extensions = ['.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.js']
            for ext in suspicious_extensions:
                if ext in url.lower():
                    download_score += 0.4
                    result['warnings'].append(f'Suspicious file extension: {ext}')
            
            # Check filename if provided
            if filename:
                for ext in suspicious_extensions:
                    if filename.lower().endswith(ext):
                        download_score += 0.3
                        result['warnings'].append(f'Suspicious download file: {filename}')
            
            # Check for direct download patterns
            download_patterns = [
                r'download\.php',
                r'get\.php',
                r'file\.php',
                r'dl\.php'
            ]
            
            for pattern in download_patterns:
                if re.search(pattern, url.lower()):
                    download_score += 0.2
                    result['warnings'].append('Suspicious download pattern')
            
            # Update threat score
            result['threat_score'] += download_score
            result['threat_score'] = min(result['threat_score'], 1.0)
            
            # Update safety assessment
            if result['threat_score'] > 0.7:
                result['safe'] = False
                result['threat_types'].append('malicious_download')
            
            return result
            
        except Exception as e:
            self.logger.error(f"Download URL check error: {e}")
            return {
                'url': url,
                'safe': True,
                'threat_score': 0.0,
                'threat_types': ['check_error'],
                'warnings': [f'Check failed: {e}'],
                'details': {}
            }
    
    def get_url_info(self, url: str) -> Dict[str, any]:
        """Get detailed information about a URL"""
        try:
            parsed = urlparse(url)
            
            return {
                'url': url,
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'is_secure': parsed.scheme == 'https',
                'domain_parts': parsed.netloc.split('.'),
                'path_segments': [seg for seg in parsed.path.split('/') if seg],
                'query_params': dict(param.split('=') for param in parsed.query.split('&') if '=' in param) if parsed.query else {}
            }
            
        except Exception as e:
            self.logger.error(f"URL info extraction error: {e}")
            return {'error': str(e)}
