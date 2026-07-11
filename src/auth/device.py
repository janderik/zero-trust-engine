"""Device trust validation and compliance checking."""

import platform
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class ComplianceStatus(Enum):
    """Device compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    PENDING = "pending"


@dataclass
class DeviceInfo:
    """Device information and trust status."""
    device_id: str
    hostname: str
    os_type: str
    os_version: str
    compliance_status: ComplianceStatus = ComplianceStatus.UNKNOWN
    trust_score: float = 0.0
    last_check: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)


class DeviceTrustManager:
    """Manage device trust and compliance."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.devices = {}
        self.trust_threshold = config.get("trust_score_threshold", 70)
    
    def register_device(self, device_id: str, hostname: str = None, os_type: str = None):
        """Register a new device."""
        if hostname is None:
            hostname = platform.node()
        if os_type is None:
            os_type = f"{platform.system()} {platform.release()}"
        
        device = DeviceInfo(
            device_id=device_id,
            hostname=hostname,
            os_type=os_type,
            os_version=platform.version()
        )
        self.devices[device_id] = device
        return device
    
    def check_compliance(self, device_id: str) -> ComplianceStatus:
        """Check device compliance status."""
        if device_id not in self.devices:
            return ComplianceStatus.UNKNOWN
        
        device = self.devices[device_id]
        
        checks = [
            self._check_encryption(device),
            self._check_antivirus(device),
            self._check_firewall(device),
            self._check_updates(device)
        ]
        
        passed = sum(checks)
        total = len(checks)
        
        device.trust_score = (passed / total) * 100 if total > 0 else 0
        
        if device.trust_score >= self.trust_threshold:
            device.compliance_status = ComplianceStatus.COMPLIANT
        else:
            device.compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return device.compliance_status
    
    def get_trust_score(self, device_id: str) -> float:
        """Get device trust score."""
        if device_id not in self.devices:
            return 0.0
        
        return self.devices[device_id].trust_score
    
    def is_device_compliant(self, device_id: str) -> bool:
        """Check if device meets compliance requirements."""
        status = self.check_compliance(device_id)
        return status == ComplianceStatus.COMPLIANT
    
    def get_device_info(self, device_id: str) -> Optional[DeviceInfo]:
        """Get device information."""
        return self.devices.get(device_id)
    
    def _check_encryption(self, device: DeviceInfo) -> bool:
        """Check if device has encryption enabled."""
        return device.attributes.get("encrypted", True)
    
    def _check_antivirus(self, device: DeviceInfo) -> bool:
        """Check if antivirus is running."""
        return device.attributes.get("antivirus_active", True)
    
    def _check_firewall(self, device: DeviceInfo) -> bool:
        """Check if firewall is enabled."""
        return device.attributes.get("firewall_enabled", True)
    
    def _check_updates(self, device: DeviceInfo) -> bool:
        """Check if system is up to date."""
        return device.attributes.get("updates_current", True)
    
    def update_device_attributes(self, device_id: str, attributes: Dict[str, Any]):
        """Update device attributes."""
        if device_id in self.devices:
            self.devices[device_id].attributes.update(attributes)
    
    def get_all_devices(self) -> List[DeviceInfo]:
        """Get all registered devices."""
        return list(self.devices.values())
