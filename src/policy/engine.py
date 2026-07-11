"""Policy engine for access control decisions."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .rules import PolicyRule


@dataclass
class PolicyContext:
    """Context for policy evaluation."""
    user_id: str
    device_id: str
    resource: str
    action: str
    source_ip: str
    attributes: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.attributes is None:
            self.attributes = {}


@dataclass
class PolicyDecision:
    """Decision made by policy engine."""
    allowed: bool
    reason: str
    matched_rules: List[str]
    risk_score: float = 0.0


class PolicyEngine:
    """Evaluate policies against access requests."""
    
    def __init__(self):
        self.policies = []
        self.rules = {}
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule."""
        self.rules[rule.name] = rule
    
    def remove_rule(self, rule_name: str):
        """Remove a policy rule."""
        if rule_name in self.rules:
            del self.rules[rule_name]
    
    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        """Evaluate all rules against the context."""
        matched_rules = []
        allow_rules = []
        deny_rules = []
        
        for name, rule in self.rules.items():
            if rule.matches(context):
                matched_rules.append(name)
                if rule.effect == "allow":
                    allow_rules.append(name)
                elif rule.effect == "deny":
                    deny_rules.append(name)
        
        if deny_rules:
            return PolicyDecision(
                allowed=False,
                reason=f"Denied by rules: {', '.join(deny_rules)}",
                matched_rules=matched_rules,
                risk_score=100.0
            )
        
        if allow_rules:
            return PolicyDecision(
                allowed=True,
                reason=f"Allowed by rules: {', '.join(allow_rules)}",
                matched_rules=matched_rules,
                risk_score=0.0
            )
        
        return PolicyDecision(
            allowed=False,
            reason="No matching allow rules",
            matched_rules=matched_rules,
            risk_score=50.0
        )
    
    def get_all_rules(self) -> List[PolicyRule]:
        """Get all policy rules."""
        return list(self.rules.values())
    
    def load_policies(self, policies: List[Dict[str, Any]]):
        """Load policies from dictionary."""
        for policy_data in policies:
            rule = PolicyRule(
                name=policy_data.get("name", "unnamed"),
                description=policy_data.get("description", ""),
                effect=policy_data.get("effect", "deny"),
                conditions=policy_data.get("conditions", [])
            )
            self.add_rule(rule)
