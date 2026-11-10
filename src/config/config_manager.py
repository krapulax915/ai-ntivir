import os
import json
import logging
import threading
from typing import Dict, Any, Optional
from pathlib import Path
import configparser

class ConfigManager:
    """Configuration management for AI Antivirus"""
    
    def __init__(self, config_file: str = "config.json"):
        try:
            from .comprehensive_logger import setup_module_logging
            self.logger = setup_module_logging('ai_antivirus.config.config_manager')
        except ImportError:
            self.logger = logging.getLogger(__name__)
        self.config_file = config_file
        self.config_lock = threading.Lock()
        self.config_data = {}
        self.default_config = self._get_default_config()
        
        # Load configuration
        self.load_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "version": "1.0.0",
            "core": {
                "ai_engine": {
                    "enabled": True,
                    "model_path": "models/threat_detection.onnx",
                    "threat_threshold": 0.0,
                    "max_file_size_mb": 100,
                    "scan_timeout_seconds": 30
                },
                "file_monitor": {
                    "enabled": True,
                    "monitor_paths": [
                        "C:\\",
                        "D:\\",
                        "E:\\"
                    ],
                    "excluded_paths": [
                        "C:\\Windows\\System32",
                        "C:\\Program Files\\Windows Defender"
                    ],
                    "max_workers": 3
                },
                "quarantine": {
                    "enabled": True,
                    "quarantine_dir": "quarantine",
                    "auto_cleanup_days": 30,
                    "max_quarantine_size_gb": 5
                }
            },
            "detection": {
                "signature_engine": {
                    "enabled": True,
                    "signature_db_path": "signatures/signatures.db",
                    "auto_update": True,
                    "update_interval_hours": 6
                },
                "heuristic_analyzer": {
                    "enabled": True,
                    "process_monitoring": True,
                    "behavioral_analysis": True,
                    "obfuscation_detection": True
                }
            },
            "network": {
                "p2p_communication": {
                    "enabled": True,
                    "port": 8888,
                    "max_peers": 50,
                    "discovery_enabled": True,
                    "encryption_enabled": True,
                    "network_key": "aintivirus_network_2024"
                }
            },
            "dlp": {
                "enabled": True,
                "monitor_usb": True,
                "monitor_network": True,
                "monitor_email": True,
                "max_file_size_mb": 10,
                "alert_on_violation": True,
                "block_transfers": False
            },
            "gui": {
                "enabled": True,
                "minimize_to_tray": True,
                "show_notifications": True,
                "auto_start": True,
                "theme": "dark"
            },
            "updater": {
                "auto_update_enabled": True,
                "backup_before_update": True,
                "restart_after_update": True,
                "update_check_interval_hours": 1,
                "update_servers": [
                    "https://updates.aintivirus.com",
                    "https://backup.aintivirus.com"
                ]
            },
            "logging": {
                "level": "INFO",
                "file_path": "logs/aintivirus.log",
                "max_file_size_mb": 10,
                "backup_count": 5,
                "console_output": True
            }
        }
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            with self.config_lock:
                if os.path.exists(self.config_file):
                    with open(self.config_file, 'r', encoding='utf-8') as f:
                        loaded_config = json.load(f)
                    
                    # Merge with defaults
                    self.config_data = self._merge_configs(self.default_config, loaded_config)
                    self.logger.info(f"Configuration loaded from {self.config_file}")
                else:
                    # Use default configuration
                    self.config_data = self.default_config.copy()
                    self.save_config()
                    self.logger.info("Default configuration created")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            self.config_data = self.default_config.copy()
            return False
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            with self.config_lock:
                # Ensure directory exists
                config_dir = os.path.dirname(self.config_file)
                if config_dir:
                    os.makedirs(config_dir, exist_ok=True)
                
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.config_data, f, indent=2, ensure_ascii=False)
                
                self.logger.info(f"Configuration saved to {self.config_file}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        try:
            with self.config_lock:
                keys = key.split('.')
                value = self.config_data
                
                for k in keys:
                    if isinstance(value, dict) and k in value:
                        value = value[k]
                    else:
                        return default
                
                return value
                
        except Exception as e:
            self.logger.error(f"Failed to get config value for key '{key}': {e}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value by key"""
        try:
            with self.config_lock:
                keys = key.split('.')
                config = self.config_data
                
                # Navigate to parent
                for k in keys[:-1]:
                    if k not in config:
                        config[k] = {}
                    config = config[k]
                
                # Set value
                config[keys[-1]] = value
                
                self.logger.debug(f"Configuration updated: {key} = {value}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to set config value for key '{key}': {e}")
            return False
    
    def get_section(self, section: str) -> Dict:
        """Get entire configuration section"""
        return self.get(section, {})
    
    def update_section(self, section: str, values: Dict) -> bool:
        """Update entire configuration section"""
        try:
            with self.config_lock:
                if section not in self.config_data:
                    self.config_data[section] = {}
                
                self.config_data[section].update(values)
                self.logger.debug(f"Configuration section updated: {section}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update config section '{section}': {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        try:
            with self.config_lock:
                self.config_data = self.default_config.copy()
                self.save_config()
                self.logger.info("Configuration reset to defaults")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to reset configuration: {e}")
            return False
    
    def validate_config(self) -> Dict:
        """Validate current configuration"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Check required sections
            required_sections = ['core', 'detection', 'network', 'gui', 'logging']
            for section in required_sections:
                if section not in self.config_data:
                    validation_result['errors'].append(f"Missing required section: {section}")
                    validation_result['valid'] = False
            
            # Validate specific settings
            self._validate_paths(validation_result)
            self._validate_network_settings(validation_result)
            self._validate_numeric_ranges(validation_result)
            
        except Exception as e:
            validation_result['errors'].append(f"Validation error: {e}")
            validation_result['valid'] = False
        
        return validation_result
    
    def _validate_paths(self, result: Dict):
        """Validate file and directory paths"""
        path_configs = [
            ('core.ai_engine.model_path', False),
            ('core.quarantine.quarantine_dir', False),
            ('detection.signature_engine.signature_db_path', False),
            ('logging.file_path', False)
        ]
        
        for path_key, must_exist in path_configs:
            path_value = self.get(path_key)
            if path_value:
                if must_exist and not os.path.exists(path_value):
                    result['errors'].append(f"Path does not exist: {path_key} = {path_value}")
                elif not must_exist:
                    # Check if parent directory exists or can be created
                    parent_dir = os.path.dirname(path_value)
                    if parent_dir and not os.path.exists(parent_dir):
                        try:
                            os.makedirs(parent_dir, exist_ok=True)
                        except:
                            result['warnings'].append(f"Cannot create directory for: {path_key}")
    
    def _validate_network_settings(self, result: Dict):
        """Validate network-related settings"""
        port = self.get('network.p2p_communication.port', 8888)
        if not (1024 <= port <= 65535):
            result['errors'].append(f"Invalid P2P port: {port} (must be 1024-65535)")
        
        max_peers = self.get('network.p2p_communication.max_peers', 50)
        if not (1 <= max_peers <= 1000):
            result['warnings'].append(f"Max peers value seems unusual: {max_peers}")
    
    def _validate_numeric_ranges(self, result: Dict):
        """Validate numeric configuration values"""
        numeric_configs = [
            ('core.ai_engine.max_file_size_mb', 1, 1000),
            ('core.ai_engine.scan_timeout_seconds', 5, 300),
            ('core.quarantine.auto_cleanup_days', 1, 365),
            ('core.quarantine.max_quarantine_size_gb', 1, 100),
            ('logging.max_file_size_mb', 1, 100),
            ('logging.backup_count', 1, 20)
        ]
        
        for config_key, min_val, max_val in numeric_configs:
            value = self.get(config_key)
            if value is not None and not (min_val <= value <= max_val):
                result['warnings'].append(
                    f"Value out of recommended range: {config_key} = {value} "
                    f"(recommended: {min_val}-{max_val})"
                )
    
    def _merge_configs(self, default: Dict, loaded: Dict) -> Dict:
        """Merge loaded configuration with defaults"""
        merged = default.copy()
        
        for key, value in loaded.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def export_config(self, export_path: str) -> bool:
        """Export configuration to file"""
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Configuration exported to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            return False
    
    def import_config(self, import_path: str) -> bool:
        """Import configuration from file"""
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Validate imported configuration
            temp_config = self.config_data
            self.config_data = self._merge_configs(self.default_config, imported_config)
            
            validation_result = self.validate_config()
            if not validation_result['valid']:
                # Restore previous configuration if validation fails
                self.config_data = temp_config
                self.logger.error(f"Configuration import failed validation: {validation_result['errors']}")
                return False
            
            self.save_config()
            self.logger.info(f"Configuration imported from {import_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import configuration: {e}")
            return False
    
    def get_config_summary(self) -> Dict:
        """Get configuration summary"""
        return {
            'version': self.get('version'),
            'ai_engine_enabled': self.get('core.ai_engine.enabled'),
            'file_monitor_enabled': self.get('core.file_monitor.enabled'),
            'p2p_enabled': self.get('network.p2p_communication.enabled'),
            'dlp_enabled': self.get('dlp.enabled'),
            'auto_update_enabled': self.get('updater.auto_update_enabled'),
            'log_level': self.get('logging.level'),
            'config_file': self.config_file,
            'last_modified': os.path.getmtime(self.config_file) if os.path.exists(self.config_file) else None
        }
