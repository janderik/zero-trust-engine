"""Configuration management for Zero Trust Engine."""

import os
import yaml
from typing import Dict, Any, Optional


DEFAULT_CONFIG = {
    "engine": {
        "mode": "enforce",
        "log_level": "info"
    },
    "identity": {
        "providers": [{"type": "local"}],
        "session_timeout": 3600
    },
    "device": {
        "trust_score_threshold": 70,
        "require_compliance": True
    },
    "network": {
        "trusted_ranges": ["192.168.0.0/16", "10.0.0.0/8"],
        "segments": []
    }
}


class ConfigManager:
    """Manage Zero Trust Engine configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = DEFAULT_CONFIG.copy()
        
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
    
    def load_config(self, path: str):
        """Load configuration from YAML file."""
        try:
            with open(path, 'r') as f:
                loaded_config = yaml.safe_load(f)
                if loaded_config:
                    self._merge_config(self.config, loaded_config)
        except Exception as e:
            print(f"Warning: Could not load config from {path}: {e}")
    
    def _merge_config(self, base: Dict, override: Dict):
        """Deep merge configuration dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated path."""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any):
        """Set configuration value by dot-separated path."""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def save_config(self, path: Optional[str] = None):
        """Save configuration to YAML file."""
        save_path = path or self.config_path
        if not save_path:
            raise ValueError("No config path specified")
        
        with open(save_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def get_config(self) -> Dict[str, Any]:
        """Get the full configuration."""
        return self.config.copy()
