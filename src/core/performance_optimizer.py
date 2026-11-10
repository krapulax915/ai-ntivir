import os
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed

class ScanPerformanceOptimizer:
    """Optimize scanning performance with parallel processing"""
    
    def __init__(self, ai_engine, signature_engine):
        self.ai_engine = ai_engine
        self.signature_engine = signature_engine
        self.max_workers = min(4, multiprocessing.cpu_count())
        
    def optimized_scan(self, file_paths, progress_callback=None):
        """Perform optimized parallel scanning"""
        results = {
            'scanned': 0,
            'threats': 0,
            'clean': 0,
            'errors': 0,
            'threat_files': []
        }
        
        total_files = len(file_paths)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path): file_path 
                for file_path in file_paths
            }
            
            # Process completed scans
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                
                try:
                    scan_result = future.result()
                    results['scanned'] += 1
                    
                    if scan_result['is_threat']:
                        results['threats'] += 1
                        results['threat_files'].append({
                            'file': file_path,
                            'threat_info': scan_result
                        })
                    else:
                        results['clean'] += 1
                        
                except Exception as e:
                    results['errors'] += 1
                
                # Progress callback
                if progress_callback:
                    progress = (results['scanned'] / total_files) * 100
                    progress_callback(progress, results['scanned'], total_files)
        
        return results
    
    def _scan_single_file(self, file_path):
        """Scan single file with multiple engines"""
        try:
            # Quick pre-checks
            if not os.path.exists(file_path):
                return {'is_threat': False, 'error': 'File not found'}
            
            # Size check (skip very large files for performance)
            try:
                size = os.path.getsize(file_path)
                if size > 500 * 1024 * 1024:  # >500MB
                    return {'is_threat': False, 'skipped': 'File too large'}
            except (OSError, PermissionError):
                return {'is_threat': False, 'error': 'Permission denied'}
            
            # Signature scan (fastest)
            sig_result = self.signature_engine.check_file_signature(file_path)
            if sig_result.get('is_threat', False):
                return {
                    'is_threat': True,
                    'detection_method': 'signature',
                    'threat_name': sig_result.get('threat_name', 'Unknown')
                }
            
            # AI scan
            ai_score = self.ai_engine.analyze_file(file_path)
            if isinstance(ai_score, dict):
                ai_score = ai_score.get('threat_score', 0.0)
            
            if ai_score > 0.7:
                return {
                    'is_threat': True,
                    'detection_method': 'ai',
                    'threat_score': ai_score
                }
            
            return {'is_threat': False, 'ai_score': ai_score}
            
        except Exception as e:
            return {'is_threat': False, 'error': str(e)}
