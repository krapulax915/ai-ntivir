"""Smoke test for CriticalSystemScanner.perform_enhanced_quick_scan
This test instantiates the scanner with lightweight mock engines and runs the
enhanced quick scan to ensure it completes without crashing and returns the
expected structure.

FIX (2026-11-10): the previous version called scanner.quick_scan(), a method
that does not exist (the real API is perform_enhanced_quick_scan), used mock
method names that never matched the real engines (scan_file vs
check_file_signature) and asserted result keys ('status') that the scanner
never produced. Rewritten against the real contract.
"""

import sys
import os
# Ensure AI_Antivirus package root is on sys.path for standalone tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from enhanced_quick_scan_system import CriticalSystemScanner

class DummyAI:
    def analyze_registry_key(self, key):
        return {'threat_score': 0.0}
    def analyze_file(self, path):
        # The scanner reads 'threat_score' from analyze_file results
        return {'threat_score': 0.0}

class DummySig:
    def check_file_signature(self, path):
        # Real engine contract: SignatureEngine.check_file_signature(file_path)
        return {'is_threat': False}

class DummyHeur:
    def analyze_file(self, path):
        # The scanner reads 'is_threat' / 'is_suspicious' from heuristic results
        return {'is_threat': False, 'is_suspicious': False}


def progress_cb(progress, message):
    # Simple callback that prints and returns True to continue
    print(f"PROGRESS: {progress} - {message}")
    return True


def run_smoke_test():
    scanner = CriticalSystemScanner(ai_engine=DummyAI(), signature_engine=DummySig(), heuristic_analyzer=DummyHeur())
    result = scanner.perform_enhanced_quick_scan(progress_callback=progress_cb)
    print('Result keys:', list(result.keys()))
    assert 'error' not in result or result.get('error') != 'Scan stopped by user'
    assert 'summary' in result, f"missing 'summary' in result: {list(result.keys())}"
    summary = result['summary']
    assert isinstance(summary.get('files_scanned'), int), "files_scanned must be an int"
    assert 'areas_scanned' in result
    print('Smoke test passed')


if __name__ == '__main__':
    run_smoke_test()
