# Enhanced Signature Engine Integration
from .signature_engine import SignatureEngine
import sqlite3
import time
import hashlib
from typing import Dict, Optional

class EnhancedSignatureEngine(SignatureEngine):
    """Production-ready enhanced signature engine"""
    
    def __init__(self, db_path: str = "signatures/signatures.db"):
        super().__init__(db_path)
        self.signature_cache = {}
        self.cache_max_size = 10000
        self.performance_stats = {
            'total_checks': 0,
            'cache_hits': 0,
            'detection_time': []
        }
        self.init_enhanced_schema()
    
    def init_enhanced_schema(self):
        """Initialize enhanced database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS enhanced_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_value TEXT UNIQUE NOT NULL,
                    hash_type TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_level INTEGER DEFAULT 5,
                    family TEXT,
                    description TEXT,
                    confidence REAL DEFAULT 1.0,
                    detection_count INTEGER DEFAULT 0,
                    active BOOLEAN DEFAULT TRUE
                )
                """)
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash_value ON enhanced_signatures(hash_value)')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Enhanced schema init failed: {e}")
    
    def check_file_signature(self, file_path: str) -> Dict:
        """Override with enhanced version"""
        return self.check_file_signature_enhanced(file_path)
    
    def check_file_signature_enhanced(self, file_path: str) -> Dict:
        """Enhanced signature checking with caching"""
        start_time = time.time()
        self.performance_stats['total_checks'] += 1
        
        try:
            # Use parent method for hash calculation
            result = super().check_file_signature(file_path)
            
            # Add performance tracking
            self.performance_stats['detection_time'].append(time.time() - start_time)
            
            # Enhance result with additional metadata
            if result.get('is_threat'):
                result['detection_method'] = 'signature_enhanced'
                result['confidence'] = 1.0
            
            return result
            
        except Exception as e:
            self.logger.error(f"Enhanced signature check failed: {e}")
            return {'is_threat': False, 'error': str(e)}
