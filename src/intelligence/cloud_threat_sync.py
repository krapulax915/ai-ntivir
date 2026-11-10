#!/usr/bin/env python3
"""
Cloud-Based Threat Intelligence Synchronization
Synchronizes threat data with cloud services and threat feeds
"""

import os
import sys
import json
import logging
import requests
import sqlite3
import threading
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import asyncio
import aiohttp
from urllib.parse import urljoin

@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    indicator_id: str
    indicator_type: str  # hash, ip, domain, url
    value: str
    threat_type: str
    confidence: float
    source: str
    first_seen: str
    last_seen: str
    tags: List[str]
    metadata: Dict[str, Any]

@dataclass
class CloudProvider:
    """Cloud threat intelligence provider configuration"""
    provider_id: str
    name: str
    api_url: str
    api_key: str
    enabled: bool
    sync_interval: int  # minutes
    last_sync: Optional[str] = None
    indicators_count: int = 0

class CloudThreatIntelligenceSync:
    """Cloud-based threat intelligence synchronization system"""
    
    def __init__(self, config_path: str = None, callback: callable = None):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.intelligence.cloud_threat_sync')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.config_path = config_path or os.path.join(os.getcwd(), "config", "cloud_threat_config.json")
        self.callback = callback
        
        # Database for threat indicators
        self.db_path = os.path.join(os.getcwd(), "logs", "cloud_threat_intelligence.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Cloud providers
        self.providers: Dict[str, CloudProvider] = {}
        
        # Sync state
        self.sync_active = False
        self.sync_threads = {}
        
        # Statistics
        self.stats = {
            'total_indicators': 0,
            'indicators_today': 0,
            'successful_syncs': 0,
            'failed_syncs': 0,
            'last_sync_time': None,
            'active_providers': 0
        }
        
        # Thread safety
        self.lock = threading.Lock()
        
        self.init_database()
        self.load_configuration()
        self.logger.info("Cloud threat intelligence sync initialized")
    
    def init_database(self):
        """Initialize threat intelligence database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Threat indicators table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_indicators (
                        indicator_id TEXT PRIMARY KEY,
                        indicator_type TEXT NOT NULL,
                        value TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        source TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        tags TEXT,
                        metadata TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Cloud providers table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cloud_providers (
                        provider_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        api_url TEXT NOT NULL,
                        api_key TEXT NOT NULL,
                        enabled BOOLEAN NOT NULL,
                        sync_interval INTEGER NOT NULL,
                        last_sync TEXT,
                        indicators_count INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Sync history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sync_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        provider_id TEXT NOT NULL,
                        sync_time TEXT NOT NULL,
                        status TEXT NOT NULL,
                        indicators_added INTEGER DEFAULT 0,
                        indicators_updated INTEGER DEFAULT 0,
                        error_message TEXT,
                        duration_seconds REAL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicators_source ON threat_indicators(source)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sync_history_provider ON sync_history(provider_id)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def load_configuration(self):
        """Load cloud provider configuration"""
        try:
            # Create default config if not exists
            if not os.path.exists(self.config_path):
                self.create_default_config()
            
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Load providers
            for provider_data in config.get('providers', []):
                provider = CloudProvider(**provider_data)
                self.providers[provider.provider_id] = provider
            
            # Update stats
            self.stats['active_providers'] = len([p for p in self.providers.values() if p.enabled])
            
            self.logger.info(f"Loaded {len(self.providers)} cloud providers")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            default_config = {
                "providers": [
                    {
                        "provider_id": "malwarebazaar",
                        "name": "MalwareBazaar",
                        "api_url": "https://mb-api.abuse.ch/api/v1/",
                        "api_key": "",
                        "enabled": True,
                        "sync_interval": 60
                    },
                    {
                        "provider_id": "urlhaus",
                        "name": "URLhaus",
                        "api_url": "https://urlhaus-api.abuse.ch/v1/",
                        "api_key": "",
                        "enabled": True,
                        "sync_interval": 30
                    },
                    {
                        "provider_id": "threatfox",
                        "name": "ThreatFox",
                        "api_url": "https://threatfox-api.abuse.ch/api/v1/",
                        "api_key": "",
                        "enabled": True,
                        "sync_interval": 45
                    },
                    {
                        "provider_id": "virustotal",
                        "name": "VirusTotal",
                        "api_url": "https://www.virustotal.com/vtapi/v2/",
                        "api_key": "YOUR_VT_API_KEY",
                        "enabled": False,
                        "sync_interval": 120
                    }
                ],
                "sync_settings": {
                    "max_concurrent_syncs": 3,
                    "request_timeout": 30,
                    "retry_attempts": 3,
                    "batch_size": 1000
                }
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            self.logger.info(f"Created default configuration: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create default configuration: {e}")
    
    def start_sync(self):
        """Start cloud synchronization"""
        if self.sync_active:
            return
        
        self.sync_active = True
        
        # Start sync threads for each enabled provider
        for provider_id, provider in self.providers.items():
            if provider.enabled:
                thread = threading.Thread(
                    target=self._sync_worker,
                    args=(provider,),
                    daemon=True,
                    name=f"CloudSync-{provider_id}"
                )
                thread.start()
                self.sync_threads[provider_id] = thread
        
        self.logger.info("Cloud threat intelligence sync started")
    
    def stop_sync(self):
        """Stop cloud synchronization"""
        self.sync_active = False
        
        # Wait for threads to complete
        for thread in self.sync_threads.values():
            thread.join(timeout=5)
        
        self.sync_threads.clear()
        self.logger.info("Cloud threat intelligence sync stopped")
    
    def _sync_worker(self, provider: CloudProvider):
        """Sync worker for a specific provider"""
        while self.sync_active:
            try:
                # Check if sync is needed
                if self._should_sync_provider(provider):
                    self._sync_provider(provider)
                
                # Sleep for 1 minute before next check
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Sync worker error for {provider.name}: {e}")
                time.sleep(60)
    
    def _should_sync_provider(self, provider: CloudProvider) -> bool:
        """Check if provider should be synced"""
        if not provider.enabled:
            return False
        
        if not provider.last_sync:
            return True
        
        last_sync = datetime.fromisoformat(provider.last_sync)
        next_sync = last_sync + timedelta(minutes=provider.sync_interval)
        
        return datetime.now() >= next_sync
    
    def _sync_provider(self, provider: CloudProvider):
        """Sync threat intelligence from a provider"""
        start_time = datetime.now()
        
        try:
            self.logger.info(f"Starting sync with {provider.name}")
            
            # Get threat indicators from provider
            indicators = self._fetch_indicators(provider)
            
            if indicators:
                # Process and store indicators
                added, updated = self._process_indicators(indicators, provider.provider_id)
                
                # Update provider stats
                provider.last_sync = start_time.isoformat()
                provider.indicators_count += added
                
                # Log success
                duration = (datetime.now() - start_time).total_seconds()
                self._log_sync_result(provider.provider_id, start_time, "success", 
                                    added, updated, None, duration)
                
                # Update global stats
                with self.lock:
                    self.stats['successful_syncs'] += 1
                    self.stats['total_indicators'] += added
                    self.stats['last_sync_time'] = start_time.isoformat()
                
                # Callback notification
                if self.callback:
                    self.callback('sync_completed', {
                        'provider': provider.name,
                        'indicators_added': added,
                        'indicators_updated': updated
                    })
                
                self.logger.info(f"Sync completed: {provider.name} - Added: {added}, Updated: {updated}")
            
        except Exception as e:
            # Log failure
            duration = (datetime.now() - start_time).total_seconds()
            self._log_sync_result(provider.provider_id, start_time, "failed", 
                                0, 0, str(e), duration)
            
            with self.lock:
                self.stats['failed_syncs'] += 1
            
            self.logger.error(f"Sync failed: {provider.name} - {e}")
    
    def _fetch_indicators(self, provider: CloudProvider) -> List[ThreatIndicator]:
        """Fetch threat indicators from provider"""
        try:
            indicators = []
            
            if provider.provider_id == "malwarebazaar":
                indicators = self._fetch_malwarebazaar_indicators(provider)
            elif provider.provider_id == "urlhaus":
                indicators = self._fetch_urlhaus_indicators(provider)
            elif provider.provider_id == "threatfox":
                indicators = self._fetch_threatfox_indicators(provider)
            elif provider.provider_id == "virustotal":
                indicators = self._fetch_virustotal_indicators(provider)
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"Failed to fetch indicators from {provider.name}: {e}")
            return []
    
    def _fetch_malwarebazaar_indicators(self, provider: CloudProvider) -> List[ThreatIndicator]:
        """Fetch indicators from MalwareBazaar"""
        try:
            # Get recent samples
            response = requests.post(
                urljoin(provider.api_url, "samples/recent/"),
                data={"selector": "time"},
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"API request failed: {response.status_code}")
            
            data = response.json()
            indicators = []
            
            if data.get("query_status") == "ok":
                for sample in data.get("data", []):
                    # Create hash indicators
                    for hash_type in ["sha256_hash", "md5_hash", "sha1_hash"]:
                        if hash_type in sample and sample[hash_type]:
                            indicator = ThreatIndicator(
                                indicator_id=f"mb_{sample[hash_type]}",
                                indicator_type="hash",
                                value=sample[hash_type],
                                threat_type=sample.get("signature", "malware"),
                                confidence=0.9,
                                source="MalwareBazaar",
                                first_seen=sample.get("first_seen", ""),
                                last_seen=sample.get("last_seen", ""),
                                tags=sample.get("tags", []),
                                metadata={
                                    "file_type": sample.get("file_type", ""),
                                    "file_size": sample.get("file_size", 0),
                                    "delivery_method": sample.get("delivery_method", "")
                                }
                            )
                            indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"MalwareBazaar fetch error: {e}")
            return []
    
    def _fetch_urlhaus_indicators(self, provider: CloudProvider) -> List[ThreatIndicator]:
        """Fetch indicators from URLhaus"""
        try:
            # Get recent URLs
            response = requests.post(
                urljoin(provider.api_url, "urls/recent/"),
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"API request failed: {response.status_code}")
            
            data = response.json()
            indicators = []
            
            if data.get("query_status") == "ok":
                for url_data in data.get("urls", []):
                    indicator = ThreatIndicator(
                        indicator_id=f"uh_{hashlib.md5(url_data['url'].encode()).hexdigest()}",
                        indicator_type="url",
                        value=url_data["url"],
                        threat_type=url_data.get("threat", "malicious_url"),
                        confidence=0.85,
                        source="URLhaus",
                        first_seen=url_data.get("date_added", ""),
                        last_seen=url_data.get("last_online", ""),
                        tags=url_data.get("tags", []),
                        metadata={
                            "url_status": url_data.get("url_status", ""),
                            "host": url_data.get("host", ""),
                            "reporter": url_data.get("reporter", "")
                        }
                    )
                    indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"URLhaus fetch error: {e}")
            return []
    
    def _fetch_threatfox_indicators(self, provider: CloudProvider) -> List[ThreatIndicator]:
        """Fetch indicators from ThreatFox"""
        try:
            # Get recent IOCs
            response = requests.post(
                urljoin(provider.api_url, "get_iocs/"),
                data={"days": 1},
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"API request failed: {response.status_code}")
            
            data = response.json()
            indicators = []
            
            if data.get("query_status") == "ok":
                for ioc in data.get("data", []):
                    indicator = ThreatIndicator(
                        indicator_id=f"tf_{ioc['id']}",
                        indicator_type=ioc.get("ioc_type", "unknown").lower(),
                        value=ioc["ioc"],
                        threat_type=ioc.get("threat_type", "unknown"),
                        confidence=float(ioc.get("confidence_level", 50)) / 100,
                        source="ThreatFox",
                        first_seen=ioc.get("first_seen", ""),
                        last_seen=ioc.get("last_seen", ""),
                        tags=ioc.get("tags", []),
                        metadata={
                            "malware": ioc.get("malware", ""),
                            "reference": ioc.get("reference", ""),
                            "reporter": ioc.get("reporter", "")
                        }
                    )
                    indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            self.logger.error(f"ThreatFox fetch error: {e}")
            return []
    
    def _fetch_virustotal_indicators(self, provider: CloudProvider) -> List[ThreatIndicator]:
        """Fetch indicators from VirusTotal (placeholder)"""
        # VirusTotal requires paid API for bulk access
        # This is a placeholder implementation
        return []
    
    def _process_indicators(self, indicators: List[ThreatIndicator], source: str) -> Tuple[int, int]:
        """Process and store threat indicators"""
        try:
            added = 0
            updated = 0
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for indicator in indicators:
                    # Check if indicator exists
                    cursor.execute(
                        'SELECT indicator_id FROM threat_indicators WHERE indicator_id = ?',
                        (indicator.indicator_id,)
                    )
                    
                    if cursor.fetchone():
                        # Update existing indicator
                        cursor.execute('''
                            UPDATE threat_indicators 
                            SET last_seen = ?, confidence = ?, tags = ?, metadata = ?, updated_at = ?
                            WHERE indicator_id = ?
                        ''', (
                            indicator.last_seen,
                            indicator.confidence,
                            json.dumps(indicator.tags),
                            json.dumps(indicator.metadata),
                            datetime.now().isoformat(),
                            indicator.indicator_id
                        ))
                        updated += 1
                    else:
                        # Insert new indicator
                        cursor.execute('''
                            INSERT INTO threat_indicators 
                            (indicator_id, indicator_type, value, threat_type, confidence, 
                             source, first_seen, last_seen, tags, metadata)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            indicator.indicator_id,
                            indicator.indicator_type,
                            indicator.value,
                            indicator.threat_type,
                            indicator.confidence,
                            indicator.source,
                            indicator.first_seen,
                            indicator.last_seen,
                            json.dumps(indicator.tags),
                            json.dumps(indicator.metadata)
                        ))
                        added += 1
                
                conn.commit()
            
            return added, updated
            
        except Exception as e:
            self.logger.error(f"Failed to process indicators: {e}")
            return 0, 0
    
    def _log_sync_result(self, provider_id: str, sync_time: datetime, status: str,
                        added: int, updated: int, error_message: str, duration: float):
        """Log sync result to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO sync_history 
                    (provider_id, sync_time, status, indicators_added, indicators_updated, 
                     error_message, duration_seconds)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    provider_id, sync_time.isoformat(), status, added, updated,
                    error_message, duration
                ))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log sync result: {e}")
    
    def query_indicators(self, indicator_type: str = None, value: str = None, 
                        source: str = None, limit: int = 100) -> List[Dict]:
        """Query threat indicators"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = "SELECT * FROM threat_indicators WHERE 1=1"
                params = []
                
                if indicator_type:
                    query += " AND indicator_type = ?"
                    params.append(indicator_type)
                
                if value:
                    query += " AND value = ?"
                    params.append(value)
                
                if source:
                    query += " AND source = ?"
                    params.append(source)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                
                columns = [desc[0] for desc in cursor.description]
                indicators = []
                
                for row in cursor.fetchall():
                    indicator = dict(zip(columns, row))
                    # Parse JSON fields
                    if indicator['tags']:
                        indicator['tags'] = json.loads(indicator['tags'])
                    if indicator['metadata']:
                        indicator['metadata'] = json.loads(indicator['metadata'])
                    indicators.append(indicator)
                
                return indicators
                
        except Exception as e:
            self.logger.error(f"Failed to query indicators: {e}")
            return []
    
    def get_sync_statistics(self) -> Dict[str, Any]:
        """Get synchronization statistics"""
        try:
            # Update today's indicators count
            today = datetime.now().date().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM threat_indicators 
                    WHERE DATE(created_at) = ?
                ''', (today,))
                
                self.stats['indicators_today'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM threat_indicators')
                self.stats['total_indicators'] = cursor.fetchone()[0]
            
            return {
                **self.stats,
                'sync_active': self.sync_active,
                'providers_count': len(self.providers)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get sync statistics: {e}")
            return self.stats
    
    def get_sync_history(self, days: int = 7) -> List[Dict]:
        """Get synchronization history"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM sync_history 
                    WHERE sync_time >= ?
                    ORDER BY sync_time DESC
                ''', (cutoff_date,))
                
                columns = [desc[0] for desc in cursor.description]
                history = []
                
                for row in cursor.fetchall():
                    history.append(dict(zip(columns, row)))
                
                return history
                
        except Exception as e:
            self.logger.error(f"Failed to get sync history: {e}")
            return []
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_sync()
        self.logger.info("Cloud threat intelligence sync cleaned up")
