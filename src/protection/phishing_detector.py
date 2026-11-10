#!/usr/bin/env python3
"""
Phishing Detector Module
=======================

Advanced phishing detection system that analyzes websites for
phishing attempts, fake login pages, and social engineering attacks.
"""

import re
import json
import time
import logging
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, unquote
import difflib

class PhishingDetector:
    """Advanced phishing detection engine"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.phishing_detector')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Phishing keywords and patterns
        self.phishing_keywords = {
            'urgent': ['urgent', 'immediate', 'expires', 'limited time', 'act now'],
            'verification': ['verify', 'confirm', 'validate', 'authenticate', 'update'],
            'security': ['security', 'suspended', 'locked', 'breach', 'compromised'],
            'financial': ['payment', 'billing', 'refund', 'tax', 'invoice', 'account'],
            'prizes': ['winner', 'congratulations', 'prize', 'lottery', 'reward'],
            'threats': ['suspended', 'terminated', 'blocked', 'restricted', 'penalty']
        }
        
        # Legitimate brand patterns (for impersonation detection)
        self.legitimate_brands = {
            'paypal': ['paypal.com', 'paypal-community.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com'],
            'apple': ['apple.com', 'icloud.com', 'itunes.com'],
            'amazon': ['amazon.com', 'aws.amazon.com'],
            'facebook': ['facebook.com', 'instagram.com', 'whatsapp.com'],
            'banks': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com']
        }
        
        # Common phishing domain patterns
        self.phishing_patterns = [
            r'secure.*login',
            r'verify.*account', 
            r'update.*payment',
            r'suspended.*account',
            r'security.*alert',
            r'confirm.*identity',
            r'billing.*information',
            r'account.*verification'
        ]
        
        # Suspicious URL characteristics
        self.suspicious_chars = ['-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    
    def detect_phishing(self, url: str, page_content: str = "") -> Dict[str, any]:
        """Comprehensive phishing detection"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            result = {
                'url': url,
                'domain': domain,
                'is_phishing': False,
                'confidence': 0.0,
                'phishing_types': [],
                'warnings': [],
                'indicators': [],
                'legitimate_target': None
            }
            
            # Check domain for brand impersonation
            impersonation_score, target_brand = self._check_brand_impersonation(domain)
            if impersonation_score > 0:
                result['confidence'] += impersonation_score
                result['phishing_types'].append('brand_impersonation')
                result['legitimate_target'] = target_brand
                result['indicators'].append(f'Impersonating {target_brand}')
            
            # Check for phishing patterns in URL
            pattern_score = self._check_phishing_patterns(url)
            if pattern_score > 0:
                result['confidence'] += pattern_score
                result['phishing_types'].append('suspicious_patterns')
                result['indicators'].append('Suspicious URL patterns detected')
            
            # Check domain characteristics
            domain_score = self._analyze_domain_characteristics(domain)
            if domain_score > 0:
                result['confidence'] += domain_score
                result['warnings'].append('Suspicious domain characteristics')
            
            # Analyze page content if provided
            if page_content:
                content_score = self._analyze_page_content(page_content)
                if content_score > 0:
                    result['confidence'] += content_score
                    result['phishing_types'].append('suspicious_content')
                    result['indicators'].append('Phishing content detected')
            
            # Final assessment
            result['confidence'] = min(result['confidence'], 1.0)
            
            if result['confidence'] > 0.7:
                result['is_phishing'] = True
                result['warnings'].append('High probability phishing site')
            elif result['confidence'] > 0.4:
                result['warnings'].append('Potentially suspicious site')
            
            return result
            
        except Exception as e:
            self.logger.error(f"Phishing detection error: {e}")
            return {
                'url': url,
                'is_phishing': False,
                'confidence': 0.0,
                'phishing_types': ['detection_error'],
                'warnings': [f'Detection failed: {e}'],
                'indicators': [],
                'legitimate_target': None
            }
    
    def _check_brand_impersonation(self, domain: str) -> Tuple[float, Optional[str]]:
        """Check if domain is impersonating a legitimate brand"""
        try:
            max_score = 0.0
            target_brand = None
            
            for brand, legitimate_domains in self.legitimate_brands.items():
                # Check if domain contains brand name but isn't legitimate
                if brand in domain:
                    is_legitimate = any(legit_domain in domain for legit_domain in legitimate_domains)
                    
                    if not is_legitimate:
                        # Calculate similarity to legitimate domains
                        for legit_domain in legitimate_domains:
                            similarity = difflib.SequenceMatcher(None, domain, legit_domain).ratio()
                            
                            # High similarity but not exact match = likely impersonation
                            if 0.6 < similarity < 1.0:
                                score = 0.8 * similarity
                                if score > max_score:
                                    max_score = score
                                    target_brand = brand
                            
                            # Brand name with suspicious characters
                            if brand in domain and any(char in domain for char in self.suspicious_chars):
                                score = 0.6
                                if score > max_score:
                                    max_score = score
                                    target_brand = brand
            
            return max_score, target_brand
            
        except Exception as e:
            self.logger.error(f"Brand impersonation check error: {e}")
            return 0.0, None
    
    def _check_phishing_patterns(self, url: str) -> float:
        """Check URL against known phishing patterns"""
        try:
            score = 0.0
            url_lower = url.lower()
            
            for pattern in self.phishing_patterns:
                if re.search(pattern, url_lower):
                    score += 0.2
                    self.logger.info(f"Phishing pattern detected: {pattern}")
            
            # Check for keyword combinations
            for category, keywords in self.phishing_keywords.items():
                keyword_count = sum(1 for keyword in keywords if keyword in url_lower)
                if keyword_count > 0:
                    score += 0.1 * keyword_count
            
            return min(score, 0.8)
            
        except Exception as e:
            self.logger.error(f"Phishing pattern check error: {e}")
            return 0.0
    
    def _analyze_domain_characteristics(self, domain: str) -> float:
        """Analyze domain for suspicious characteristics"""
        try:
            score = 0.0
            
            # Very long domains
            if len(domain) > 50:
                score += 0.2
            
            # Excessive hyphens or numbers
            if domain.count('-') > 3:
                score += 0.2
            
            if sum(1 for char in domain if char.isdigit()) > 5:
                score += 0.2
            
            # Suspicious TLDs commonly used for phishing
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score += 0.3
            
            # Subdomain abuse (many subdomains)
            if domain.count('.') > 4:
                score += 0.2
            
            # Mixed case in domain (unusual)
            if domain != domain.lower() and domain != domain.upper():
                score += 0.1
            
            return min(score, 0.6)
            
        except Exception as e:
            self.logger.error(f"Domain analysis error: {e}")
            return 0.0
    
    def _analyze_page_content(self, content: str) -> float:
        """Analyze page content for phishing indicators"""
        try:
            score = 0.0
            content_lower = content.lower()
            
            # Check for phishing keywords in content
            total_keywords = 0
            for category, keywords in self.phishing_keywords.items():
                category_count = sum(1 for keyword in keywords if keyword in content_lower)
                total_keywords += category_count
                
                # High concentration of certain keyword types
                if category in ['urgent', 'threats'] and category_count > 2:
                    score += 0.3
                elif category_count > 1:
                    score += 0.1
            
            # Too many phishing keywords overall
            if total_keywords > 5:
                score += 0.2
            
            # Check for fake login forms
            if 'password' in content_lower and 'login' in content_lower:
                # Look for suspicious form characteristics
                if any(indicator in content_lower for indicator in ['verify account', 'update payment', 'confirm identity']):
                    score += 0.4
            
            # Check for urgency indicators
            urgency_phrases = [
                'act now', 'limited time', 'expires soon', 'immediate action',
                'within 24 hours', 'account will be closed', 'suspended'
            ]
            
            urgency_count = sum(1 for phrase in urgency_phrases if phrase in content_lower)
            if urgency_count > 0:
                score += 0.2 * urgency_count
            
            # Check for prize/reward scams
            prize_indicators = [
                'congratulations', 'winner', 'selected', 'prize', 'reward',
                'lottery', 'sweepstakes', 'free money'
            ]
            
            prize_count = sum(1 for indicator in prize_indicators if indicator in content_lower)
            if prize_count > 1:
                score += 0.3
            
            return min(score, 0.8)
            
        except Exception as e:
            self.logger.error(f"Content analysis error: {e}")
            return 0.0
    
    def check_login_page(self, url: str, page_content: str) -> Dict[str, any]:
        """Special check for login pages"""
        try:
            result = self.detect_phishing(url, page_content)
            
            # Additional login page specific checks
            content_lower = page_content.lower()
            
            # Check for legitimate login page indicators
            legitimate_indicators = [
                'https://' in url,  # Secure connection
                'csrf' in content_lower,  # CSRF protection
                'captcha' in content_lower,  # CAPTCHA protection
            ]
            
            legitimate_count = sum(1 for indicator in legitimate_indicators if indicator)
            
            # Check for suspicious login page characteristics
            suspicious_indicators = [
                'verify your account' in content_lower,
                'update your payment' in content_lower,
                'confirm your identity' in content_lower,
                'account suspended' in content_lower,
                'security alert' in content_lower
            ]
            
            suspicious_count = sum(1 for indicator in suspicious_indicators if indicator)
            
            # Adjust confidence based on login page analysis
            if suspicious_count > legitimate_count:
                result['confidence'] += 0.3
                result['phishing_types'].append('fake_login_page')
                result['indicators'].append('Suspicious login page characteristics')
            
            return result
            
        except Exception as e:
            self.logger.error(f"Login page check error: {e}")
            return {
                'url': url,
                'is_phishing': False,
                'confidence': 0.0,
                'phishing_types': ['check_error'],
                'warnings': [f'Check failed: {e}'],
                'indicators': [],
                'legitimate_target': None
            }
    
    def get_phishing_report(self, url: str, page_content: str = "") -> Dict[str, any]:
        """Generate detailed phishing analysis report"""
        try:
            detection_result = self.detect_phishing(url, page_content)
            
            # Additional analysis
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            report = {
                'timestamp': time.time(),
                'url_analysis': detection_result,
                'domain_info': {
                    'domain': domain,
                    'subdomain_count': domain.count('.'),
                    'length': len(domain),
                    'has_numbers': any(char.isdigit() for char in domain),
                    'has_hyphens': '-' in domain,
                    'tld': domain.split('.')[-1] if '.' in domain else ''
                },
                'recommendations': []
            }
            
            # Generate recommendations based on findings
            if detection_result['is_phishing']:
                report['recommendations'].extend([
                    'DO NOT enter any personal information on this site',
                    'DO NOT download any files from this site',
                    'Report this site to your security team',
                    'Clear your browser cache and cookies'
                ])
            elif detection_result['confidence'] > 0.3:
                report['recommendations'].extend([
                    'Exercise caution when using this site',
                    'Verify the site URL carefully',
                    'Do not enter sensitive information unless certain of legitimacy'
                ])
            else:
                report['recommendations'].append('Site appears to be legitimate')
            
            return report
            
        except Exception as e:
            self.logger.error(f"Phishing report generation error: {e}")
            return {'error': str(e)}
