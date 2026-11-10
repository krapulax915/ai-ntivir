import os
import hashlib
import json
import logging
import threading
import time
from typing import Dict, List, Set, Optional
from pathlib import Path
import requests
import sqlite3

# Official mirror of the full signature database (~180 MB, ~559k entries).
# The Inno Setup installer downloads it during installation; this fallback
# covers plain-ZIP deployments where the database file is missing.
SIGNATURE_DB_DOWNLOAD_URL = "https://files.catbox.moe/lkjqct.db"
SIGNATURE_DB_SHA256 = "9e890c7177d5ccf307c3d3e4f410bc20b51cd10ad8651f33c951b3ca6b54de4b"

class SignatureEngine:
    """Signature-based threat detection engine"""

    def __init__(self, signature_db_path: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.detection.signature_engine')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.db_path = signature_db_path or "signatures/signatures.db"
        self.signatures = {}
        self.hash_cache = {}
        self.lock = threading.Lock()

        # Download the signature database if it is missing entirely
        self._ensure_database_downloaded()

        # Initialize signature database
        self._initialize_database()
        self._load_signatures()

    def _ensure_database_downloaded(self):
        """
        If the signature database is missing (fresh install without the
        installer download step, or a plain-ZIP deployment), download it once
        from the official mirror. Any failure is non-fatal: the engine
        continues with an empty database and rule-based detection still works.
        """
        try:
            if os.path.exists(self.db_path) and os.path.getsize(self.db_path) > (1024 * 1024):
                return  # database present and non-trivial

            url = SIGNATURE_DB_DOWNLOAD_URL
            self.logger.info(f"Signature database missing - downloading from official mirror: {url}")

            db_dir = os.path.dirname(self.db_path) or '.'
            os.makedirs(db_dir, exist_ok=True)
            temp_path = self.db_path + '.downloading'

            # Download to a temporary file first, then swap atomically
            with requests.get(url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                with open(temp_path, 'wb') as fh:
                    for chunk in resp.iter_content(chunk_size=1024 * 512):
                        if chunk:
                            fh.write(chunk)

            # Verify integrity before replacing anything
            sha = hashlib.sha256()
            with open(temp_path, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b''):
                    sha.update(chunk)
            if sha.hexdigest() != SIGNATURE_DB_SHA256:
                os.remove(temp_path)
                self.logger.error("Downloaded signature database hash mismatch - discarded")
                return

            os.replace(temp_path, self.db_path)
            self.logger.info("Signature database downloaded and verified successfully")
        except Exception as e:
            self.logger.warning(f"Signature database download skipped/failed (continuing without it): {e}")
            try:
                if os.path.exists(self.db_path + '.downloading'):
                    os.remove(self.db_path + '.downloading')
            except Exception:
                pass
    
    def _initialize_database(self):
        """Initialize signature database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_type TEXT NOT NULL,
                    hash_value TEXT NOT NULL UNIQUE,
                    threat_name TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    family TEXT,
                    description TEXT,
                    first_seen REAL NOT NULL,
                    last_updated REAL NOT NULL,
                    source TEXT DEFAULT 'local'
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_hash_value ON signatures(hash_value)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_level ON signatures(threat_level)
            ''')
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Signature database initialized: {self.db_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize signature database: {e}")
            raise
    
    def _load_signatures(self):
        """Load signature count and prepare for database queries (optimized for large databases)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Only load signature count, not all signatures into memory
            cursor.execute('SELECT COUNT(*) FROM signatures')
            signature_count = cursor.fetchone()[0]
            
            # Load only high-priority signatures into memory for fast access
            cursor.execute('''
                SELECT hash_value, threat_name, threat_level, family, description
                FROM signatures 
                WHERE threat_level IN ('CRITICAL', 'HIGH')
                LIMIT 10000
            ''')
            
            priority_signatures = cursor.fetchall()
            conn.close()
            
            with self.lock:
                self.signatures.clear()
                for row in priority_signatures:
                    hash_value, threat_name, threat_level, family, description = row
                    self.signatures[hash_value] = {
                        'threat_name': threat_name,
                        'threat_level': threat_level,
                        'family': family,
                        'description': description
                    }
            
            self.logger.info(f"Database contains {signature_count:,} signatures")
            self.logger.info(f"Loaded {len(self.signatures)} high-priority signatures into memory")
            
        except Exception as e:
            self.logger.error(f"Failed to load signatures: {e}")
    
    def _check_hash_in_database(self, hash_value: str) -> Dict:
        """Check specific hash in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT threat_name, threat_level, family, description
                FROM signatures 
                WHERE hash_value = ?
            ''', (hash_value,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                threat_name, threat_level, family, description = result
                return {
                    'threat_name': threat_name,
                    'threat_level': threat_level,
                    'family': family,
                    'description': description
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Database hash check failed: {e}")
            return None
    
    def check_file(self, file_path: str) -> Dict:
        """Scan file using signature detection - alias for check_file_signature"""
        return self.check_file_signature(file_path)
    
    def check_file_signature(self, file_path: str) -> Dict:
        """Check file against signature database"""
        try:
            # Calculate file hashes
            file_hashes = self._calculate_file_hashes(file_path)
            
            # Check against signatures (memory first, then database)
            for hash_type, hash_value in file_hashes.items():
                # First check in-memory signatures (high priority)
                with self.lock:
                    if hash_value in self.signatures:
                        signature_info = self.signatures[hash_value]
                        
                        return {
                            'is_threat': True,
                            'hash_type': hash_type,
                            'hash_value': hash_value,
                            'threat_name': signature_info['threat_name'],
                            'threat_level': signature_info['threat_level'],
                            'family': signature_info['family'],
                            'description': signature_info['description'],
                            'detection_method': 'signature_memory'
                        }
                
                # If not found in memory, check database
                db_result = self._check_hash_in_database(hash_value)
                if db_result:
                    return {
                        'is_threat': True,
                        'hash_type': hash_type,
                        'hash_value': hash_value,
                        'threat_name': db_result['threat_name'],
                        'threat_level': db_result['threat_level'],
                        'family': db_result['family'],
                        'description': db_result['description'],
                        'detection_method': 'signature_database'
                    }
            
            # No signature match found
            return {
                'is_threat': False,
                'hashes': file_hashes,
                'detection_method': 'signature'
            }
            
        except Exception as e:
            self.logger.error(f"Signature check failed for {file_path}: {e}")
            return {
                'is_threat': False,
                'error': str(e),
                'detection_method': 'signature'
            }
    
    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hashes for file"""
        hashes = {}
        
        try:
            # Check cache first
            file_stat = os.stat(file_path)
            cache_key = f"{file_path}_{file_stat.st_mtime}_{file_stat.st_size}"
            
            if cache_key in self.hash_cache:
                return self.hash_cache[cache_key]
            
            # Calculate hashes
            hash_md5 = hashlib.md5()
            hash_sha1 = hashlib.sha1()
            hash_sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_md5.update(chunk)
                    hash_sha1.update(chunk)
                    hash_sha256.update(chunk)
            
            hashes = {
                'md5': hash_md5.hexdigest(),
                'sha1': hash_sha1.hexdigest(),
                'sha256': hash_sha256.hexdigest()
            }
            
            # Cache result
            self.hash_cache[cache_key] = hashes
            
            # Limit cache size
            if len(self.hash_cache) > 1000:
                # Remove oldest entries (simplified)
                old_keys = list(self.hash_cache.keys())[:500]
                for key in old_keys:
                    del self.hash_cache[key]
            
            return hashes
            
        except Exception as e:
            self.logger.error(f"Hash calculation failed for {file_path}: {e}")
            return {}
    
    def add_signature(self, hash_value: str, hash_type: str, threat_name: str, 
                     threat_level: str, family: str = None, description: str = None):
        """Add new signature to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            current_time = time.time()
            
            cursor.execute('''
                INSERT OR REPLACE INTO signatures 
                (hash_type, hash_value, threat_name, threat_level, family, 
                 description, first_seen, last_updated, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'local')
            ''', (hash_type, hash_value, threat_name, threat_level, family, 
                  description, current_time, current_time))
            
            conn.commit()
            conn.close()
            
            # Update in-memory signatures
            with self.lock:
                self.signatures[hash_value] = {
                    'threat_name': threat_name,
                    'threat_level': threat_level,
                    'family': family,
                    'description': description
                }
            
            self.logger.info(f"Signature added: {threat_name} ({hash_value})")
            
        except Exception as e:
            self.logger.error(f"Failed to add signature: {e}")
    
    def remove_signature(self, hash_value: str):
        """Remove signature from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM signatures WHERE hash_value = ?', (hash_value,))
            conn.commit()
            conn.close()
            
            # Remove from memory
            with self.lock:
                self.signatures.pop(hash_value, None)
            
            self.logger.info(f"Signature removed: {hash_value}")
            
        except Exception as e:
            self.logger.error(f"Failed to remove signature: {e}")
    
    def update_signatures_from_server(self, server_url: str) -> bool:
        """Update signatures from remote server"""
        try:
            response = requests.get(f"{server_url}/signatures/latest", timeout=30)
            response.raise_for_status()
            
            signature_data = response.json()
            signatures = signature_data.get('signatures', [])
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            updated_count = 0
            current_time = time.time()
            
            for sig in signatures:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO signatures 
                        (hash_type, hash_value, threat_name, threat_level, family, 
                         description, first_seen, last_updated, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'server')
                    ''', (
                        sig['hash_type'],
                        sig['hash_value'],
                        sig['threat_name'],
                        sig['threat_level'],
                        sig.get('family'),
                        sig.get('description'),
                        sig.get('first_seen', current_time),
                        current_time
                    ))
                    updated_count += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to update signature {sig.get('hash_value')}: {e}")
            
            conn.commit()
            conn.close()
            
            # Reload signatures into memory
            self._load_signatures()
            
            self.logger.info(f"Updated {updated_count} signatures from server")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update signatures from server: {e}")
            return False
    
    def get_signature_stats(self) -> Dict:
        """Get signature database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total signatures
            cursor.execute('SELECT COUNT(*) FROM signatures')
            total_signatures = cursor.fetchone()[0]
            
            # By threat level
            cursor.execute('''
                SELECT threat_level, COUNT(*) 
                FROM signatures 
                GROUP BY threat_level
            ''')
            by_threat_level = dict(cursor.fetchall())
            
            # By source
            cursor.execute('''
                SELECT source, COUNT(*) 
                FROM signatures 
                GROUP BY source
            ''')
            by_source = dict(cursor.fetchall())
            
            # Recent additions (last 24 hours)
            cutoff_time = time.time() - 86400
            cursor.execute('''
                SELECT COUNT(*) 
                FROM signatures 
                WHERE last_updated > ?
            ''', (cutoff_time,))
            recent_additions = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_signatures': total_signatures,
                'by_threat_level': by_threat_level,
                'by_source': by_source,
                'recent_additions': recent_additions,
                'cache_size': len(self.hash_cache)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get signature stats: {e}")
            return {}
    
    def export_signatures(self, output_path: str, threat_level: str = None) -> bool:
        """Export signatures to JSON file"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if threat_level:
                cursor.execute('''
                    SELECT * FROM signatures WHERE threat_level = ?
                ''', (threat_level,))
            else:
                cursor.execute('SELECT * FROM signatures')
            
            signatures = []
            for row in cursor.fetchall():
                signatures.append({
                    'id': row[0],
                    'hash_type': row[1],
                    'hash_value': row[2],
                    'threat_name': row[3],
                    'threat_level': row[4],
                    'family': row[5],
                    'description': row[6],
                    'first_seen': row[7],
                    'last_updated': row[8],
                    'source': row[9]
                })
            
            conn.close()
            
            export_data = {
                'export_time': time.time(),
                'total_signatures': len(signatures),
                'filter': threat_level,
                'signatures': signatures
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Exported {len(signatures)} signatures to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export signatures: {e}")
            return False
    
    def import_signatures(self, import_path: str) -> bool:
        """Import signatures from JSON file"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            signatures = import_data.get('signatures', [])
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            imported_count = 0
            current_time = time.time()
            
            for sig in signatures:
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO signatures 
                        (hash_type, hash_value, threat_name, threat_level, family, 
                         description, first_seen, last_updated, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'imported')
                    ''', (
                        sig['hash_type'],
                        sig['hash_value'],
                        sig['threat_name'],
                        sig['threat_level'],
                        sig.get('family'),
                        sig.get('description'),
                        sig.get('first_seen', current_time),
                        current_time
                    ))
                    imported_count += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to import signature {sig.get('hash_value')}: {e}")
            
            conn.commit()
            conn.close()
            
            # Reload signatures
            self._load_signatures()
            
            self.logger.info(f"Imported {imported_count} signatures from {import_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import signatures: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get signature database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total signatures
            cursor.execute("SELECT COUNT(*) FROM signatures")
            total_signatures = cursor.fetchone()[0]
            
            # By source
            cursor.execute("SELECT source, COUNT(*) FROM signatures GROUP BY source")
            by_source = dict(cursor.fetchall())
            
            # By threat level
            cursor.execute("SELECT threat_level, COUNT(*) FROM signatures GROUP BY threat_level")
            by_threat_level = dict(cursor.fetchall())
            
            # Recent additions (last 24 hours)
            current_time = time.time()
            day_ago = current_time - 86400
            cursor.execute("SELECT COUNT(*) FROM signatures WHERE first_seen > ?", (day_ago,))
            recent_additions = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_signatures': total_signatures,
                'by_source': by_source,
                'by_threat_level': by_threat_level,
                'recent_additions_24h': recent_additions,
                'cache_size': len(self.hash_cache)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {
                'total_signatures': 0,
                'by_source': {},
                'by_threat_level': {},
                'recent_additions_24h': 0,
                'cache_size': 0
            }
