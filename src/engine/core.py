"""Core Zero Trust Engine implementation."""

import time
import uuid
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Verdict(Enum):
    """Access decision verdicts."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


@dataclass
class AccessRequest:
    """Represents an access request to be evaluated."""
    user_id: str
    device_id: str
    resource: str
    action: str
    source_ip: str
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AccessDecision:
    """Decision made by the Zero Trust Engine."""
    request_id: str
    allowed: bool
    verdict: Verdict
    reason: str
    risk_score: float
    timestamp: float = field(default_factory=time.time)
    conditions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustContext:
    """Trust context for evaluation."""
    identity_verified: bool = False
    device_compliant: bool = False
    network_trusted: bool = False
    mfa_verified: bool = False
    risk_score: float = 0.0


class ZeroTrustEngine:
    """Main Zero Trust Engine for evaluating access requests."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.policies = []
        self.audit_log = []
        self.initialized = False
    
    def initialize(self):
        """Initialize the engine with default policies."""
        self.initialized = True
        self._load_default_policies()
    
    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate an access request against all policies."""
        if not self.initialized:
            raise RuntimeError("Engine not initialized. Call initialize() first.")
        
        context = self._build_trust_context(request)
        
        decision = self._apply_policies(request, context)
        
        self._log_decision(request, decision)
        
        return decision
    
    def _build_trust_context(self, request: AccessRequest) -> TrustContext:
        """Build trust context from request information."""
        context = TrustContext()
        
        context.identity_verified = self._verify_identity(request.user_id)
        context.device_compliant = self._check_device_compliance(request.device_id)
        context.network_trusted = self._check_network_trust(request.source_ip)
        context.mfa_verified = request.context.get("mfa_verified", False)
        
        risk_score = 0.0
        if not context.identity_verified:
            risk_score += 30
        if not context.device_compliant:
            risk_score += 25
        if not context.network_trusted:
            risk_score += 20
        if not context.mfa_verified:
            risk_score += 15
        
        context.risk_score = min(risk_score, 100.0)
        
        return context
    
    def _verify_identity(self, user_id: str) -> bool:
        """Verify user identity."""
        return bool(user_id and len(user_id) > 0)
    
    def _check_device_compliance(self, device_id: str) -> bool:
        """Check if device is compliant."""
        return bool(device_id and len(device_id) > 0)
    
    def _check_network_trust(self, source_ip: str) -> bool:
        """Check if source network is trusted."""
        trusted_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18."]
        return any(source_ip.startswith(prefix) for prefix in trusted_prefixes)
    
    def _apply_policies(self, request: AccessRequest, context: TrustContext) -> AccessDecision:
        """Apply policies to make access decision."""
        verdict = Verdict.DENY
        reason = "Default deny"
        conditions = []
        
        if context.risk_score < 30:
            verdict = Verdict.ALLOW
            reason = "All trust checks passed"
            conditions = ["identity_verified", "device_compliant", "network_trusted"]
        elif context.risk_score < 60:
            verdict = Verdict.CHALLENGE
            reason = "Additional verification required"
            conditions = ["mfa_required"]
        else:
            verdict = Verdict.DENY
            reason = f"High risk score: {context.risk_score}"
        
        return AccessDecision(
            request_id=request.request_id,
            allowed=(verdict == Verdict.ALLOW),
            verdict=verdict,
            reason=reason,
            risk_score=context.risk_score,
            conditions=conditions,
            metadata={
                "user_id": request.user_id,
                "device_id": request.device_id,
                "resource": request.resource
            }
        )
    
    def _log_decision(self, request: AccessRequest, decision: AccessDecision):
        """Log access decision for audit."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": request.request_id,
            "user_id": request.user_id,
            "device_id": request.device_id,
            "resource": request.resource,
            "action": request.action,
            "verdict": decision.verdict.value,
            "risk_score": decision.risk_score,
            "reason": decision.reason
        }
        self.audit_log.append(log_entry)
    
    def _load_default_policies(self):
        """Load default zero trust policies."""
        self.policies = [
            {
                "name": "default_deny",
                "description": "Default deny all requests",
                "effect": "deny",
                "conditions": []
            },
            {
                "name": "trusted_network_allow",
                "description": "Allow trusted networks with verified identity",
                "effect": "allow",
                "conditions": [
                    {"type": "identity", "verified": True},
                    {"type": "network", "trusted": True}
                ]
            }
        ]
    
    def get_audit_log(self) -> List[Dict]:
        """Get the audit log."""
        return self.audit_log
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        if not self.audit_log:
            return {"total_requests": 0}
        
        total = len(self.audit_log)
        allowed = sum(1 for log in self.audit_log if log["verdict"] == "allow")
        denied = sum(1 for log in self.audit_log if log["verdict"] == "deny")
        challenged = sum(1 for log in self.audit_log if log["verdict"] == "challenge")
        
        return {
            "total_requests": total,
            "allowed": allowed,
            "denied": denied,
            "challenged": challenged,
            "allow_rate": (allowed / total * 100) if total > 0 else 0
        }
