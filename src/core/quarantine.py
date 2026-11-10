import os
import shutil
import json
import time
import logging
import hashlib
from typing import Dict, List, Optional
from pathlib import Path
import sqlite3
import threading

class QuarantineManager:
    """Enhanced thread-safe quarantine manager with duplicate prevention"""
    
    def __init__(self, quarantine_dir: str = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.core.quarantine')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        
        # CRITICAL FIX V15: Quarantine INSIDE application directory
        if quarantine_dir is None:
            # Get the directory where this file (quarantine.py) is located
            # This file is in: AI_Antivirus/src/core/quarantine.py
            # We want: AI_Antivirus/quarantine (INSIDE the application!)
            this_file_path = os.path.abspath(__file__)
            src_core_dir = os.path.dirname(this_file_path)  # src/core
            src_dir = os.path.dirname(src_core_dir)  # src
            ai_antivirus_dir = os.path.dirname(src_dir)  # AI_Antivirus (or installation dir)
            
            # CRITICAL: Quarantine goes INSIDE AI_Antivirus directory
            quarantine_dir = os.path.join(ai_antivirus_dir, "quarantine")
            
            self.logger.info(f"🔍 Quarantine path auto-detected: {quarantine_dir}")
            self.logger.info(f"   Installation directory: {ai_antivirus_dir}")
        
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.db_path = os.path.join(self.quarantine_dir, "quarantine.db")
        self.lock = threading.Lock()
        
        # Thread-safe quarantine tracking
        self._quarantine_in_progress = set()
        self._quarantine_lock = threading.Lock()
        
        # Create quarantine directory and database
        self._initialize_quarantine()
    
    def _initialize_quarantine(self):
        """Initialize quarantine directory and database with enhanced error logging"""
        try:
            # CRITICAL FIX V14: Create directory with detailed logging
            self.logger.info(f"📁 Creating quarantine directory: {self.quarantine_dir}")
            os.makedirs(self.quarantine_dir, exist_ok=True)
            
            # Verify directory was created
            if os.path.exists(self.quarantine_dir):
                self.logger.info(f"✅ Quarantine directory created successfully")
            else:
                raise Exception(f"Directory creation failed: {self.quarantine_dir}")
            
            # Create quarantine database
            self.logger.info(f"📊 Creating quarantine database: {self.db_path}")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quarantined_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    threat_level TEXT NOT NULL,
                    quarantine_time REAL NOT NULL,
                    file_size INTEGER NOT NULL,
                    detection_info TEXT,
                    status TEXT DEFAULT 'quarantined',
                    restoration_time REAL,
                    deletion_time REAL,
                    UNIQUE(original_path, file_hash)
                )
            ''')

            # FIX: databases created by older versions lack the restoration_time
            # and deletion_time columns that restore_file()/delete_quarantined_file()
            # write. Every restore/delete then failed with "no such column" AFTER
            # the file was already moved/deleted on disk, leaving ghost records and
            # restored malware while the DB still said 'quarantined'. Migrate
            # idempotently with fixed DDL strings.
            try:
                cursor.execute('ALTER TABLE quarantined_files ADD COLUMN restoration_time REAL')
            except sqlite3.OperationalError:
                pass  # column already exists
            try:
                cursor.execute('ALTER TABLE quarantined_files ADD COLUMN deletion_time REAL')
            except sqlite3.OperationalError:
                pass  # column already exists

            conn.commit()
            conn.close()
            
            self.logger.info(f"✅ Quarantine system initialized successfully")
            self.logger.info(f"   Directory: {self.quarantine_dir}")
            self.logger.info(f"   Database: {self.db_path}")
            
        except PermissionError as e:
            self.logger.error(f"❌ CRITICAL: Permission denied creating quarantine directory!")
            self.logger.error(f"   Path: {self.quarantine_dir}")
            self.logger.error(f"   Error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"❌ CRITICAL: Failed to initialize quarantine system!")
            self.logger.error(f"   Path: {self.quarantine_dir}")
            self.logger.error(f"   Error type: {type(e).__name__}")
            self.logger.error(f"   Error: {e}")
            raise
    
    def quarantine_file(self, file_path: str, threat_info: Dict) -> bool:
        """Thread-safe file quarantine with duplicate prevention"""
        
        # Normalize file path
        file_path = os.path.abspath(file_path)
        
        # Check if quarantine already in progress for this file
        with self._quarantine_lock:
            if file_path in self._quarantine_in_progress:
                self.logger.info(f"Quarantine already in progress for: {file_path}")
                return False
            
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.warning(f"File not found for quarantine: {file_path}")
                return False
            
            # Check if already quarantined
            if self._is_already_quarantined(file_path):
                self.logger.info(f"File already quarantined: {file_path}")
                return True
            
            # Mark as in progress
            self._quarantine_in_progress.add(file_path)
        
        try:
            return self._perform_quarantine(file_path, threat_info)
        finally:
            # Always remove from in-progress set
            with self._quarantine_lock:
                self._quarantine_in_progress.discard(file_path)
    
    def _is_already_quarantined(self, file_path: str) -> bool:
        """Check if file is already quarantined"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM quarantined_files 
                WHERE original_path = ? AND status = 'quarantined'
            ''', (file_path,))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception as e:
            self.logger.error(f"Error checking quarantine status: {e}")
            return False
    
    def _perform_quarantine(self, file_path: str, threat_info: Dict) -> bool:
        """Perform actual quarantine operation"""
        try:
            # Skip system files and protected directories
            protected_paths = [
                'windows\\system32', 'windows\\syswow64', 'program files',
                'program files (x86)', 'windows\\winsxs'
            ]
            
            file_path_lower = file_path.lower()
            if any(path in file_path_lower for path in protected_paths):
                self.logger.info(f"Skipping quarantine of protected system file: {file_path}")
                return False
            
            # Get original file size before quarantine
            try:
                original_size = os.path.getsize(file_path)
            except:
                original_size = 0
            
            if original_size == 0:
                self.logger.warning(f"Skipping quarantine of empty file: {file_path}")
                return False
            
            # Generate unique quarantine filename
            # FIX: hash the file CONTENT instead of its path, so the same
            # malware re-downloaded under a new name is still recognized by the
            # UNIQUE(original_path, file_hash) dedup logic.
            try:
                content_hasher = hashlib.sha256()
                with open(file_path, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(65536), b''):
                        content_hasher.update(chunk)
                file_hash = content_hasher.hexdigest()
            except Exception as hash_err:
                self.logger.warning(f"Could not hash file content, falling back to path hash: {hash_err}")
                file_hash = hashlib.sha256(file_path.encode()).hexdigest()
            timestamp = str(int(time.time()))
            quarantine_filename = f"{file_hash}_{timestamp}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Ensure quarantine path is unique
            counter = 0
            while os.path.exists(quarantine_path):
                counter += 1
                quarantine_filename = f"{file_hash}_{timestamp}_{counter}"
                quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Perform quarantine with enhanced error handling
            success = self._safe_file_move(file_path, quarantine_path, original_size)
            
            if success:
                # Record in database
                # FIX: if the DB insert fails AFTER the file was moved, roll the
                # file back instead of leaving an untracked orphan in quarantine
                # while RTP reports "QUARANTINE FAILED".
                try:
                    self._record_quarantine(
                        original_path=file_path,
                        quarantine_path=quarantine_path,
                        file_hash=file_hash,
                        analysis_result=threat_info,
                        original_size=original_size
                    )
                except Exception as record_err:
                    self.logger.error(f"DB record failed, rolling back quarantine: {record_err}")
                    try:
                        shutil.move(quarantine_path, file_path)
                        self.logger.info(f"Rollback successful: file returned to {file_path}")
                    except Exception as rollback_err:
                        self.logger.error(f"Rollback failed, orphan remains at {quarantine_path}: {rollback_err}")
                    return False

                self.logger.info(f"✅ File successfully quarantined: {file_path} -> {quarantine_path} ({original_size} bytes)")
                return True
            else:
                self.logger.error(f"❌ Failed to quarantine file: {file_path}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Quarantine operation failed for {file_path}: {e}")
            return False
    
    def _safe_file_move(self, source_path: str, dest_path: str, expected_size: int) -> bool:
        """Safely move file to quarantine with verification - V14 Enhanced"""
        try:
            # Method 1: Copy + Verify + Delete
            try:
                shutil.copy2(source_path, dest_path)
                
                # Verify copy was successful
                if os.path.exists(dest_path):
                    actual_size = os.path.getsize(dest_path)
                    if actual_size == expected_size and actual_size > 0:
                        # Copy successful, remove original
                        os.remove(source_path)
                        self.logger.debug(f"✅ Copy+Delete successful: {source_path} ({actual_size} bytes)")
                        return True
                    else:
                        self.logger.warning(f"⚠️ Copy size mismatch: expected {expected_size}, got {actual_size}")
                        # CRITICAL FIX: Remove failed/partial copy
                        if os.path.exists(dest_path):
                            try:
                                os.remove(dest_path)
                                self.logger.info(f"🧹 Cleaned up partial file: {dest_path}")
                            except Exception as cleanup_err:
                                self.logger.error(f"❌ Failed to cleanup partial file: {cleanup_err}")
                
            except FileNotFoundError as e:
                # CRITICAL FIX V14: Specific handling for race condition
                self.logger.error(f"❌ FILE NOT FOUND: {source_path}")
                self.logger.error(f"   Possible race condition - browser may have moved/renamed the file")
                self.logger.error(f"   This typically happens when browser completes download during scan")
                return False
            except PermissionError as e:
                # CRITICAL FIX V14: Specific handling for permission issues
                self.logger.error(f"❌ PERMISSION DENIED: {source_path}")
                self.logger.error(f"   File may be locked by another process")
                self.logger.error(f"   Error: {e}")
                return False
            except Exception as e:
                # CRITICAL FIX: Catch ALL other exceptions
                self.logger.error(f"❌ Copy method failed: {type(e).__name__}: {e}")
                
                # CRITICAL: Cleanup partial file
                if os.path.exists(dest_path):
                    try:
                        os.remove(dest_path)
                        self.logger.info(f"🧹 Cleaned up partial file after exception: {dest_path}")
                    except Exception as cleanup_err:
                        self.logger.error(f"❌ Failed to cleanup after exception: {cleanup_err}")
            
            # Method 2: Direct move
            try:
                shutil.move(source_path, dest_path)
                
                # Verify move was successful
                if os.path.exists(dest_path):
                    actual_size = os.path.getsize(dest_path)
                    if actual_size == expected_size and actual_size > 0:
                        self.logger.debug(f"Move successful: {source_path} ({actual_size} bytes)")
                        return True
                    else:
                        self.logger.warning(f"Move size mismatch: expected {expected_size}, got {actual_size}")
                        # CRITICAL FIX: Remove failed move
                        if os.path.exists(dest_path):
                            try:
                                os.remove(dest_path)
                                self.logger.info(f"Cleaned up failed move: {dest_path}")
                            except Exception as cleanup_err:
                                self.logger.error(f"Failed to cleanup after move: {cleanup_err}")
                
            except Exception as e:
                # CRITICAL FIX: Catch ALL exceptions
                self.logger.error(f"Move method failed: {type(e).__name__}: {e}")
                
                # CRITICAL: Cleanup partial file
                if os.path.exists(dest_path):
                    try:
                        os.remove(dest_path)
                        self.logger.info(f"Cleaned up partial file after move exception: {dest_path}")
                    except Exception as cleanup_err:
                        self.logger.error(f"Failed to cleanup after move exception: {cleanup_err}")
            
            # Method 3: Rename (last resort)
            try:
                quarantine_path_alt = dest_path + ".quarantined"
                os.rename(source_path, quarantine_path_alt)
                
                # Update dest_path for verification
                if os.path.exists(quarantine_path_alt):
                    actual_size = os.path.getsize(quarantine_path_alt)
                    if actual_size == expected_size and actual_size > 0:
                        # Rename back to expected name
                        os.rename(quarantine_path_alt, dest_path)
                        self.logger.debug(f"Rename successful: {source_path} ({actual_size} bytes)")
                        return True
                    else:
                        # CRITICAL FIX: Remove failed rename
                        self.logger.warning(f"Rename size mismatch: expected {expected_size}, got {actual_size}")
                        try:
                            os.remove(quarantine_path_alt)
                            self.logger.info(f"Cleaned up failed rename: {quarantine_path_alt}")
                        except Exception as cleanup_err:
                            self.logger.error(f"Failed to cleanup after rename: {cleanup_err}")
                
            except Exception as re_err:
                # CRITICAL FIX: Enhanced exception handling
                self.logger.error(f"Rename method failed: {type(re_err).__name__}: {re_err}")
                
                # CRITICAL: Cleanup partial file
                quarantine_path_alt = dest_path + ".quarantined"
                if os.path.exists(quarantine_path_alt):
                    try:
                        os.remove(quarantine_path_alt)
                        self.logger.info(f"Cleaned up partial file after rename exception: {quarantine_path_alt}")
                    except Exception as cleanup_err:
                        self.logger.error(f"Failed to cleanup after rename exception: {cleanup_err}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"All quarantine methods failed for {source_path}: {e}")
            return False
    
    def restore_file(self, quarantine_id: int, restore_path: str = None) -> bool:
        """Restore a quarantined file"""
        with self.lock:
            conn_closed = False
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get quarantine record
                cursor.execute('''
                    SELECT original_path, quarantine_path, status 
                    FROM quarantined_files 
                    WHERE id = ?
                ''', (quarantine_id,))
                
                result = cursor.fetchone()
                if not result:
                    self.logger.warning(f"Quarantine record not found: {quarantine_id}")
                    conn.close()
                    return False

                original_path, quarantine_path, status = result

                if status != 'quarantined':
                    self.logger.warning(f"File not in quarantine: {quarantine_id}")
                    conn.close()
                    return False

                # Determine restore location
                target_path = restore_path or original_path
                
                # Ensure target directory exists
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                
                # Restore file
                shutil.move(quarantine_path, target_path)

                # Update database
                cursor.execute('''
                    UPDATE quarantined_files
                    SET status = 'restored', restoration_time = ?
                    WHERE id = ?
                ''', (time.time(), quarantine_id))

                conn.commit()
                conn.close()
                conn_closed = True
                
                self.logger.info(f"File restored: {quarantine_id} -> {target_path}")
                return True

            except Exception as e:
                self.logger.error(f"Failed to restore file {quarantine_id}: {e}")
                return False
            finally:
                # FIX: close the connection on every path (previously leaked on
                # every error).
                try:
                    if conn is not None and not conn_closed:
                        conn.close()
                except Exception:
                    pass
    
    def delete_quarantined_file(self, quarantine_id: int) -> bool:
        """Permanently delete a quarantined file"""
        with self.lock:
            conn_closed = False
            conn = None
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get quarantine record
                cursor.execute('''
                    SELECT quarantine_path, original_path, status 
                    FROM quarantined_files 
                    WHERE id = ?
                ''', (quarantine_id,))
                
                result = cursor.fetchone()
                if not result:
                    self.logger.warning(f"Quarantine record not found: {quarantine_id}")
                    conn.close()
                    conn_closed = True
                    return False

                quarantine_path, original_path, status = result

                if status != 'quarantined':
                    self.logger.warning(f"File not in quarantined status: {status}")
                    conn.close()
                    conn_closed = True
                    return False
                
                # Delete physical file
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                    self.logger.info(f"Quarantined file deleted: {quarantine_path}")

                # Update database record
                cursor.execute('''
                    UPDATE quarantined_files 
                    SET status = 'deleted', deletion_time = ?
                    WHERE id = ?
                ''', (time.time(), quarantine_id))
                
                conn.commit()
                conn.close()
                
                self.logger.info(f"Quarantine record {quarantine_id} marked as deleted")
                return True

            except Exception as e:
                self.logger.error(f"Failed to delete quarantined file {quarantine_id}: {e}")
                return False
            finally:
                # FIX: close the connection on every path (previously leaked).
                try:
                    if conn is not None and not conn_closed:
                        conn.close()
                except Exception:
                    pass
    
    def list_quarantined_files(self, status: str = 'quarantined') -> List[Dict]:
        """List quarantined files"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, original_path, threat_score, threat_level, 
                       quarantine_time, file_size, status
                FROM quarantined_files 
                WHERE status = ?
                ORDER BY quarantine_time DESC
            ''', (status,))
            
            results = cursor.fetchall()
            conn.close()
            
            quarantined_files = []
            for row in results:
                quarantined_files.append({
                    'id': row[0],
                    'original_path': row[1],
                    'threat_score': row[2],
                    'threat_level': row[3],
                    'quarantine_time': row[4],
                    'file_size': row[5],
                    'status': row[6]
                })
            
            return quarantined_files
            
        except Exception as e:
            self.logger.error(f"Failed to list quarantined files: {e}")
            return []
    
    def get_quarantine_stats(self) -> Dict:
        """Get comprehensive quarantine statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count by status
            cursor.execute('SELECT status, COUNT(*) FROM quarantined_files GROUP BY status')
            status_counts = dict(cursor.fetchall())
            
            # Total files quarantined
            cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE status = "quarantined"')
            active_quarantined = cursor.fetchone()[0]
            
            # Recent quarantine activity (last 24 hours)
            yesterday = time.time() - (24 * 60 * 60)
            cursor.execute('SELECT COUNT(*) FROM quarantined_files WHERE quarantine_time > ?', (yesterday,))
            recent_quarantined = cursor.fetchone()[0]
            
            # File size statistics
            cursor.execute('SELECT SUM(file_size), AVG(file_size), MAX(file_size) FROM quarantined_files WHERE status = "quarantined"')
            size_stats = cursor.fetchone()
            
            # Threat level distribution
            cursor.execute('SELECT threat_level, COUNT(*) FROM quarantined_files WHERE status = "quarantined" GROUP BY threat_level')
            threat_levels = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'active_quarantined': active_quarantined,
                'recent_quarantined': recent_quarantined,
                'status_counts': status_counts,
                'total_records': sum(status_counts.values()),
                'total_size_bytes': size_stats[0] or 0,
                'average_size_bytes': size_stats[1] or 0,
                'largest_file_bytes': size_stats[2] or 0,
                'threat_levels': threat_levels,
                'in_progress_count': len(self._quarantine_in_progress)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get quarantine stats: {e}")
            return {
                'active_quarantined': 0,
                'recent_quarantined': 0,
                'status_counts': {},
                'total_records': 0,
                'total_size_bytes': 0,
                'average_size_bytes': 0,
                'largest_file_bytes': 0,
                'threat_levels': {},
                'in_progress_count': 0
            }
    
    def _record_quarantine(self, original_path: str, quarantine_path: str, 
                          file_hash: str, analysis_result: Dict, original_size: int):
        """Record quarantine action in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO quarantined_files 
                (original_path, quarantine_path, file_hash, threat_score, threat_level, 
                 quarantine_time, file_size, detection_info, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                original_path,
                quarantine_path,
                file_hash,
                analysis_result.get('threat_score', 0.0),
                analysis_result.get('threat_level', 'unknown'),
                time.time(),
                original_size,
                json.dumps(analysis_result),
                'quarantined'
            ))
            
            conn.commit()
            conn.close()
            
            self.logger.debug(f"Quarantine record saved for {original_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to record quarantine: {e}")
            raise
