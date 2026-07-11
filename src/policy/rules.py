"""Policy rule definitions and matching."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from .engine import PolicyContext


@dataclass
class Condition:
    """A single condition for policy matching."""
    type: str
    field: str
    operator: str
    value: Any
    
    def evaluate(self, context: PolicyContext) -> bool:
        """Evaluate condition against context."""
        actual_value = self._get_value(context)
        
        if actual_value is None:
            return False
        
        if self.operator == "equals":
            return actual_value == self.value
        elif self.operator == "not_equals":
            return actual_value != self.value
        elif self.operator == "contains":
            return self.value in str(actual_value)
        elif self.operator == "starts_with":
            return str(actual_value).startswith(self.value)
        elif self.operator == "in":
            return actual_value in self.value
        elif self.operator == "greater_than":
            return float(actual_value) > float(self.value)
        elif self.operator == "less_than":
            return float(actual_value) < float(self.value)
        
        return False
    
    def _get_value(self, context: PolicyContext) -> Any:
        """Get value from context based on condition type."""
        if self.type == "identity":
            if self.field == "user_id":
                return context.user_id
            elif self.field == "verified":
                return context.attributes.get("identity_verified", False)
        elif self.type == "device":
            if self.field == "device_id":
                return context.device_id
            elif self.field == "compliant":
                return context.attributes.get("device_compliant", False)
        elif self.type == "resource":
            if self.field == "resource":
                return context.resource
        elif self.type == "network":
            if self.field == "source_ip":
                return context.source_ip
            elif self.field == "trusted":
                return context.attributes.get("network_trusted", False)
        elif self.type == "action":
            if self.field == "action":
                return context.action
        
        return None


@dataclass
class PolicyRule:
    """A policy rule with conditions and effects."""
    name: str
    description: str
    effect: str  # "allow" or "deny"
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    priority: int = 0
    
    def matches(self, context: PolicyContext) -> bool:
        """Check if all conditions match the context."""
        if not self.conditions:
            return True
        
        for condition_data in self.conditions:
            condition = Condition(
                type=condition_data.get("type", ""),
                field=condition_data.get("field", ""),
                operator=condition_data.get("operator", "equals"),
                value=condition_data.get("value")
            )
            
            if not condition.evaluate(context):
                return False
        
        return True
    
    def add_condition(self, condition_type: str, field: str, operator: str, value: Any):
        """Add a condition to the rule."""
        self.conditions.append({
            "type": condition_type,
            "field": field,
            "operator": operator,
            "value": value
        })
