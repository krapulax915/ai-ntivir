#!/usr/bin/env python3
"""
Browser Protection Module
========================

Comprehensive browser protection system that monitors web traffic,
blocks malicious URLs, and protects against phishing attacks.
"""

import os
import re
import json
import time
import sqlite3
import hashlib
import logging
import threading
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urlparse, unquote
import requests
from datetime import datetime, timedelta

class BrowserProtection:
    """Main browser protection engine"""
    
    def __init__(self, config_path: str = "config.json"):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.protection.browser_protection')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self.db_path = "browser_protection.db"
        self.config_path = config_path
        self._initialize_database()
        
        # Initialize Firefox test detector
        self.firefox_detector = None
        self._init_firefox_detector()
        
        # Protection lists
        self.blocked_domains = set()
        self.phishing_patterns = []
        self.safe_domains = set()
        # Monitoring state
        self._is_monitoring = False
        self.monitor_thread = None
        
        # Statistics
        self.stats = {
            'blocked_urls': 0,
            'phishing_attempts': 0,
            'safe_visits': 0,
            'total_requests': 0
        }
        
        self._initialize_database()
        self._load_protection_lists()
        self._load_config()
        
        # Auto-start browser protection by default
        self.start_monitoring()
        
    def _initialize_database(self):
        """Initialize browser protection database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # URL history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS url_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    user_agent TEXT,
                    blocked BOOLEAN DEFAULT 0
                )
            ''')
            
            # Blocked URLs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    domain TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    added_timestamp REAL NOT NULL,
                    source TEXT DEFAULT 'manual'
                )
            ''')
            
            # Safe domains whitelist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS safe_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    added_timestamp REAL NOT NULL,
                    verified BOOLEAN DEFAULT 0
                )
            ''')
            
            # Protection statistics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protection_stats (
                    date TEXT PRIMARY KEY,
                    blocked_urls INTEGER DEFAULT 0,
                    phishing_attempts INTEGER DEFAULT 0,
                    safe_visits INTEGER DEFAULT 0,
                    total_requests INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info("Browser protection database initialized")
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
    
    def _init_firefox_detector(self):
        """Initialize Firefox test detector"""
        try:
            import sys
            import os
            sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            
            from create_firefox_test_detector import create_firefox_test_detector
            self.firefox_detector = create_firefox_test_detector()
            self.logger.info("Firefox test detector initialized for browser protection")
            
        except Exception as e:
            self.logger.warning(f"Firefox detector not available for browser protection: {e}")
            self.firefox_detector = None
    
    def _load_protection_lists(self):
        """Load malicious URLs and protection patterns"""
        try:
            # Load built-in malicious domains
            self.blocked_domains.update([
                # Known malware domains
                'malware.com', 'virus.net', 'trojan.org',
                # Phishing domains
                'secure-bank-login.com', 'paypal-verification.net',
                'microsoft-security.org', 'google-security.com',
                # Suspicious TLDs
                '.tk', '.ml', '.ga', '.cf'
            ])
            
            # Load phishing patterns
            self.phishing_patterns.extend([
                r'secure.*login', r'verify.*account', r'update.*payment',
                r'suspended.*account', r'urgent.*action', r'click.*here.*now',
                r'limited.*time.*offer', r'congratulations.*winner',
                r'free.*money', r'inheritance.*claim'
            ])
            
            # Load safe domains
            self.safe_domains.update([
                'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
                'wikipedia.org', 'mozilla.org', 'python.org', 'openai.com',
                'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com'
            ])
            
            self.logger.info(f"Loaded {len(self.blocked_domains)} blocked domains")
            self.logger.info(f"Loaded {len(self.phishing_patterns)} phishing patterns")
            self.logger.info(f"Loaded {len(self.safe_domains)} safe domains")
            
        except Exception as e:
            self.logger.error(f"Error loading protection lists: {e}")
    
    def _load_config(self):
        """Load browser protection configuration"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    
                browser_config = config.get('browser_protection', {})
                self.block_malicious = browser_config.get('block_malicious', True)
                self.block_phishing = browser_config.get('block_phishing', True)
                self.scan_downloads = browser_config.get('scan_downloads', True)
                self.log_all_requests = browser_config.get('log_all_requests', False)
                
            else:
                # Default configuration
                self.block_malicious = True
                self.block_phishing = True
                self.scan_downloads = True
                self.log_all_requests = False
                
        except Exception as e:
            self.logger.error(f"Config loading error: {e}")
            # Use defaults
            self.block_malicious = True
            self.block_phishing = True
            self.scan_downloads = True
            self.log_all_requests = False
    
    def check_url(self, url: str, user_agent: str = "") -> Dict[str, any]:
        """Check if URL is safe or malicious"""
        try:
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            result = {
                'url': url,
                'domain': domain,
                'safe': True,
                'blocked': False,
                'threat_score': 0.0,
                'threat_type': 'none',
                'reason': 'Safe URL'
            }
            
            # Try Firefox test detector first (highest priority)
            if self.firefox_detector:
                try:
                    firefox_result = self.firefox_detector.analyze_url(url)
                    if firefox_result.get('is_threat', False):
                        result.update({
                            'safe': False,
                            'blocked': True,
                            'threat_score': firefox_result.get('threat_score', 0.8),
                            'threat_type': 'test_threat',
                            'reason': f"Firefox test detector: {', '.join(firefox_result.get('threat_indicators', []))}"
                        })
                        self._log_url_check(url, domain, 'test_threat', result['threat_score'], user_agent, True)
                        self.stats['blocked_urls'] += 1
                        return result
                except Exception as e:
                    self.logger.warning(f"Firefox detector failed for URL {url}: {e}")
            
            # Check if domain is in safe list
            if any(safe_domain in domain for safe_domain in self.safe_domains):
                result.update({
                    'safe': True,
                    'threat_score': 0.1,
                    'reason': 'Known safe domain'
                })
                self._log_url_check(url, domain, 'safe', 0.1, user_agent, False)
                return result
            
            # Check blocked domains
            if any(blocked in domain for blocked in self.blocked_domains):
                result.update({
                    'safe': False,
                    'blocked': True,
                    'threat_score': 0.9,
                    'threat_type': 'malicious_domain',
                    'reason': 'Domain in blocklist'
                })
                self._log_url_check(url, domain, 'malicious', 0.9, user_agent, True)
                self.stats['blocked_urls'] += 1
                return result
            
            # Check for phishing patterns
            if self.block_phishing:
                full_url = f"{domain}{path}"
                for pattern in self.phishing_patterns:
                    if re.search(pattern, full_url, re.IGNORECASE):
                        result.update({
                            'safe': False,
                            'blocked': True,
                            'threat_score': 0.8,
                            'threat_type': 'phishing',
                            'reason': f'Phishing pattern detected: {pattern}'
                        })
                        self._log_url_check(url, domain, 'phishing', 0.8, user_agent, True)
                        self.stats['phishing_attempts'] += 1
                        return result
            
            # Check URL structure for suspicious patterns
            suspicious_score = self._analyze_url_structure(url)
            if suspicious_score > 0.6:
                result.update({
                    'safe': False,
                    'blocked': True,
                    'threat_score': suspicious_score,
                    'threat_type': 'suspicious_structure',
                    'reason': 'Suspicious URL structure'
                })
                self._log_url_check(url, domain, 'suspicious', suspicious_score, user_agent, True)
                self.stats['blocked_urls'] += 1
                return result
            
            # URL appears safe
            self._log_url_check(url, domain, 'safe', 0.2, user_agent, False)
            self.stats['safe_visits'] += 1
            self.stats['total_requests'] += 1
            
            return result
            
        except Exception as e:
            self.logger.error(f"URL check error: {e}")
            return {
                'url': url,
                'safe': True,  # Default to safe on error
                'blocked': False,
                'threat_score': 0.0,
                'threat_type': 'error',
                'reason': f'Check failed: {e}'
            }
    
    def _analyze_url_structure(self, url: str) -> float:
        """Analyze URL structure for suspicious patterns"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            suspicious_score = 0.0
            
            # Check domain length (very long domains are suspicious)
            if len(domain) > 50:
                suspicious_score += 0.2
            
            # Check for IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_score += 0.3
            
            # Check for suspicious subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                suspicious_score += 0.2
            
            # Check for URL shorteners (can hide malicious URLs)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                suspicious_score += 0.1
            
            # Check for suspicious path patterns
            suspicious_paths = ['download', 'install', 'update', 'security', 'verify']
            if any(susp_path in path for susp_path in suspicious_paths):
                suspicious_score += 0.1
            
            # Check for excessive URL encoding
            if '%' in url and url.count('%') > 5:
                suspicious_score += 0.2
            
            return min(suspicious_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"URL structure analysis error: {e}")
            return 0.0
    
    def _log_url_check(self, url: str, domain: str, classification: str, 
                      threat_score: float, user_agent: str, blocked: bool):
        """Log URL check to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO url_history 
                (url, domain, classification, threat_score, timestamp, user_agent, blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (url, domain, classification, threat_score, time.time(), user_agent, blocked))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"URL logging error: {e}")
    
    def add_blocked_url(self, url: str, reason: str, threat_type: str = "manual"):
        """Add URL to blocklist"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_urls 
                (url, domain, reason, threat_type, added_timestamp, source)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (url, domain, reason, threat_type, time.time(), 'manual'))
            
            conn.commit()
            conn.close()
            
            # Add to runtime blocklist
            self.blocked_domains.add(domain)
            
            self.logger.info(f"Added {url} to blocklist: {reason}")
            
        except Exception as e:
            self.logger.error(f"Error adding blocked URL: {e}")
    
    def add_safe_domain(self, domain: str):
        """Add domain to safe list"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO safe_domains 
                (domain, added_timestamp, verified)
                VALUES (?, ?, ?)
            ''', (domain.lower(), time.time(), True))
            
            conn.commit()
            conn.close()
            
            # Add to runtime safe list
            self.safe_domains.add(domain.lower())
            
            self.logger.info(f"Added {domain} to safe domains")
            
        except Exception as e:
            self.logger.error(f"Error adding safe domain: {e}")
    
    def get_protection_stats(self) -> Dict[str, any]:
        """Get browser protection statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get today's stats
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute('''
                SELECT blocked_urls, phishing_attempts, safe_visits, total_requests
                FROM protection_stats WHERE date = ?
            ''', (today,))
            
            result = cursor.fetchone()
            if result:
                daily_stats = {
                    'blocked_urls': result[0],
                    'phishing_attempts': result[1], 
                    'safe_visits': result[2],
                    'total_requests': result[3]
                }
            else:
                daily_stats = {
                    'blocked_urls': 0,
                    'phishing_attempts': 0,
                    'safe_visits': 0,
                    'total_requests': 0
                }
            
            # Get total counts
            cursor.execute('SELECT COUNT(*) FROM url_history WHERE blocked = 1')
            total_blocked = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM url_history')
            total_requests = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'daily': daily_stats,
                'total_blocked': total_blocked,
                'total_requests': total_requests,
                'runtime_stats': self.stats.copy(),
                'protection_enabled': {
                    'malicious_blocking': self.block_malicious,
                    'phishing_protection': self.block_phishing,
                    'download_scanning': self.scan_downloads
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {'error': str(e)}
    
    def get_statistics(self):
        """Get browser protection statistics for GUI display"""
        try:
            return {
                'blocked_urls': self.stats.get('blocked_urls', 0),
                'phishing_attempts': self.stats.get('phishing_attempts', 0),
                'safe_visits': self.stats.get('safe_visits', 0),
                'total_requests': self.stats.get('total_requests', 0),
                'monitoring_status': self._is_monitoring,
                'blocked_domains_count': len(self.blocked_domains),
                'safe_domains_count': len(self.safe_domains),
                'phishing_patterns_count': len(self.phishing_patterns)
            }
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {
                'blocked_urls': 0,
                'phishing_attempts': 0,
                'safe_visits': 0,
                'total_requests': 0,
                'monitoring_status': False,
                'blocked_domains_count': 0,
                'safe_domains_count': 0,
                'phishing_patterns_count': 0,
                'error': str(e)
            }
    
    def get_blocked_domains(self):
        """Get list of blocked domains for GUI display"""
        try:
            return list(self.blocked_domains)
        except Exception as e:
            self.logger.error(f"Error getting blocked domains: {e}")
            return []
    
    def get_safe_domains(self):
        """Get list of safe domains for GUI display"""
        try:
            return list(self.safe_domains)
        except Exception as e:
            self.logger.error(f"Error getting safe domains: {e}")
            return []
    
    def get_phishing_patterns(self):
        """Get list of phishing patterns for GUI display"""
        try:
            return self.phishing_patterns.copy()
        except Exception as e:
            self.logger.error(f"Error getting phishing patterns: {e}")
            return []
    
    def is_monitoring(self):
        """Check if browser protection is currently monitoring"""
        return self._is_monitoring
    
    def start_monitoring(self):
        """Start browser protection monitoring"""
        if not self._is_monitoring:
            self._is_monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_browser_activity)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
        self.logger.info("Browser protection monitoring started")
    
    def stop_monitoring(self):
        """Stop browser protection monitoring"""
        self._is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Browser protection monitoring stopped")
    
    def _monitor_browser_activity(self):
        """Monitor browser activity (placeholder for real implementation)"""
        # This would integrate with browser APIs or network monitoring
        # For now, it's a placeholder that could be extended with:
        # - Windows API hooks for browser processes
        # - Proxy server integration
        # - Browser extension communication
        while self._is_monitoring:
            try:
                # Placeholder monitoring logic
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Browser monitoring error: {e}")
                break
