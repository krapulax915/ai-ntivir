#!/usr/bin/env python3
"""
Initialize basic threat signatures for testing
"""

import os
import sys
import sqlite3
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.detection.signature_engine import SignatureEngine

def init_basic_signatures():
    """Initialize basic threat signatures for testing"""
    print("Initializing basic threat signatures...")
    
    # Create signature engine
    sig_engine = SignatureEngine()
    
    # Basic malware signatures (test hashes)
    test_signatures = [
        {
            'hash_value': '5d41402abc4b2a76b9719d911017c592',
            'hash_type': 'md5',
            'threat_name': 'Test.Trojan.Generic',
            'threat_level': 'HIGH',
            'family': 'TestTrojan',
            'description': 'Generic test trojan signature'
        },
        {
            'hash_value': 'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
            'hash_type': 'sha1', 
            'threat_name': 'Test.Ransomware.Crypto',
            'threat_level': 'CRITICAL',
            'family': 'TestRansomware',
            'description': 'Test ransomware signature'
        },
        {
            'hash_value': '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
            'hash_type': 'sha256',
            'threat_name': 'Test.Malware.Generic',
            'threat_level': 'MEDIUM',
            'family': 'TestMalware',
            'description': 'Generic test malware signature'
        },
        {
            'hash_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'hash_type': 'sha256',
            'threat_name': 'Test.Spyware.KeyLogger',
            'threat_level': 'HIGH',
            'family': 'TestSpyware',
            'description': 'Test keylogger signature'
        },
        {
            'hash_value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'hash_type': 'sha1',
            'threat_name': 'Test.Adware.Generic',
            'threat_level': 'LOW',
            'family': 'TestAdware', 
            'description': 'Test adware signature'
        }
    ]
    
    # Add signatures
    for sig in test_signatures:
        try:
            sig_engine.add_signature(
                hash_value=sig['hash_value'],
                hash_type=sig['hash_type'],
                threat_name=sig['threat_name'],
                threat_level=sig['threat_level'],
                family=sig['family'],
                description=sig['description']
            )
            print(f"✅ Added signature: {sig['threat_name']}")
        except Exception as e:
            print(f"❌ Failed to add signature {sig['threat_name']}: {e}")
    
    # Get statistics
    stats = sig_engine.get_signature_statistics()
    print(f"\n📊 Signature Statistics:")
    print(f"Total signatures: {stats.get('total_signatures', 0)}")
    print(f"By threat level: {stats.get('by_threat_level', {})}")
    
    print("✅ Basic threat signatures initialized successfully!")

if __name__ == "__main__":
    init_basic_signatures()
