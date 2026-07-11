"""Network microsegmentation implementation."""

import ipaddress
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class NetworkSegment:
    """A network segment definition."""
    name: str
    cidr: str
    description: str = ""
    allowed_services: List[str] = field(default_factory=list)
    allowed_protocols: List[str] = field(default_factory=list)
    max_bandwidth_mbps: Optional[int] = None
    tags: Dict[str, str] = field(default_factory=dict)
    
    def contains_ip(self, ip_address: str) -> bool:
        """Check if an IP address is in this segment."""
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
            ip = ipaddress.ip_address(ip_address)
            return ip in network
        except ValueError:
            return False


@dataclass
class FirewallRule:
    """A firewall rule between segments."""
    source_segment: str
    destination_segment: str
    action: str  # "allow" or "deny"
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    description: str = ""


class MicrosegmentationManager:
    """Manage network microsegments and policies."""
    
    def __init__(self):
        self.segments: Dict[str, NetworkSegment] = {}
        self.firewall_rules: List[FirewallRule] = []
        self.active_rules: Dict[str, List[str]] = {}
    
    def create_segment(self, name: str, cidr: str, **kwargs) -> NetworkSegment:
        """Create a new network segment."""
        segment = NetworkSegment(
            name=name,
            cidr=cidr,
            description=kwargs.get("description", ""),
            allowed_services=kwargs.get("allowed_services", []),
            allowed_protocols=kwargs.get("allowed_protocols", []),
            max_bandwidth_mbps=kwargs.get("max_bandwidth_mbps"),
            tags=kwargs.get("tags", {})
        )
        self.segments[name] = segment
        return segment
    
    def remove_segment(self, name: str) -> bool:
        """Remove a network segment."""
        if name in self.segments:
            del self.segments[name]
            self.active_rules.pop(name, None)
            return True
        return False
    
    def add_firewall_rule(self, rule: FirewallRule):
        """Add a firewall rule."""
        self.firewall_rules.append(rule)
    
    def check_connection(self, source_ip: str, dest_ip: str, port: int, protocol: str = "tcp") -> bool:
        """Check if a connection is allowed between two IPs."""
        source_segment = self._find_segment(source_ip)
        dest_segment = self._find_segment(dest_ip)
        
        if not source_segment or not dest_segment:
            return False
        
        if source_segment.name == dest_segment.name:
            return True
        
        for rule in self.firewall_rules:
            if (rule.source_segment == source_segment.name and 
                rule.destination_segment == dest_segment.name):
                
                if rule.action == "deny":
                    return False
                
                if rule.ports and port not in rule.ports:
                    continue
                
                if rule.protocols and protocol not in rule.protocols:
                    continue
                
                return True
        
        return False
    
    def _find_segment(self, ip_address: str) -> Optional[NetworkSegment]:
        """Find which segment an IP belongs to."""
        for segment in self.segments.values():
            if segment.contains_ip(ip_address):
                return segment
        return None
    
    def get_segment_for_ip(self, ip_address: str) -> Optional[str]:
        """Get segment name for an IP address."""
        segment = self._find_segment(ip_address)
        return segment.name if segment else None
    
    def get_segment_info(self, name: str) -> Optional[NetworkSegment]:
        """Get segment information."""
        return self.segments.get(name)
    
    def get_all_segments(self) -> List[NetworkSegment]:
        """Get all network segments."""
        return list(self.segments.values())
    
    def get_rules_for_segment(self, segment_name: str) -> List[FirewallRule]:
        """Get all rules involving a segment."""
        return [
            rule for rule in self.firewall_rules
            if rule.source_segment == segment_name or rule.destination_segment == segment_name
        ]
    
    def create_default_segments(self):
        """Create default network segments."""
        self.create_segment("dmz", "172.16.0.0/24", description="DMZ network")
        self.create_segment("internal", "192.168.1.0/24", description="Internal network")
        self.create_segment("production", "10.0.1.0/24", description="Production network")
        self.create_segment("development", "10.0.2.0/24", description="Development network")
        
        self.add_firewall_rule(FirewallRule(
            source_segment="dmz",
            destination_segment="internal",
            action="deny",
            description="Block DMZ to internal"
        ))
        
        self.add_firewall_rule(FirewallRule(
            source_segment="internal",
            destination_segment="production",
            action="allow",
            ports=[443, 8080],
            description="Allow HTTPS and API access"
        ))
