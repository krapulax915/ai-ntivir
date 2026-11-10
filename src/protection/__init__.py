"""
Browser Protection Module
========================

This module provides comprehensive browser protection including:
- Malicious URL detection and blocking
- Phishing protection
- Download scanning
- Real-time web threat monitoring
"""

from .browser_protection import BrowserProtection
from .url_scanner import URLScanner
from .phishing_detector import PhishingDetector

__all__ = ['BrowserProtection', 'URLScanner', 'PhishingDetector']
