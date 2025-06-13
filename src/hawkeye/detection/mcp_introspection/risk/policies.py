"""
Risk Policies Module

This module provides configurable risk thresholds, policies, and enforcement
mechanisms for MCP server introspection and security assessment.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Union, Any
from datetime import datetime, timedelta

from ..models import SecurityRisk, RiskLevel, RiskCategory


logger = logging.getLogger(__name__)


class PolicyAction(Enum):
    """Actions that can be taken when a policy is violated."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    AUDIT = "audit"


class PolicyScope(Enum):
    """Scope of policy application."""
    GLOBAL = "global"
    SERVER = "server"
    TOOL = "tool"
    RESOURCE = "resource"
    CAPABILITY = "capability"


@dataclass
class RiskThreshold:
    """Defines risk thresholds for different risk levels."""
    critical: float = 9.0
    high: float = 7.0
    medium: float = 5.0
    low: float = 3.0
    info: float = 1.0
    
    def get_level(self, score: float) -> RiskLevel:
        """Get risk level based on score."""
        if score >= self.critical:
            return RiskLevel.CRITICAL
        elif score >= self.high:
            return RiskLevel.HIGH
        elif score >= self.medium:
            return RiskLevel.MEDIUM
        elif score >= self.low:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def validate(self) -> bool:
        """Validate threshold configuration."""
        thresholds = [self.info, self.low, self.medium, self.high, self.critical]
        return all(thresholds[i] <= thresholds[i+1] for i in range(len(thresholds)-1))


@dataclass
class PolicyRule:
    """Defines a single policy rule."""
    id: str
    name: str
    description: str
    scope: PolicyScope
    risk_categories: Set[RiskCategory]
    risk_levels: Set[RiskLevel]
    action: PolicyAction
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, risk: SecurityRisk, context: Dict[str, Any] = None) -> bool:
        """Check if this rule matches the given risk."""
        if not self.enabled:
            return False
        
        # Check risk category
        if self.risk_categories and risk.category not in self.risk_categories:
            return False
        
        # Check risk level
        if self.risk_levels and risk.level not in self.risk_levels:
            return False
        
        # Check custom conditions
        if self.conditions and context:
            for condition_key, condition_value in self.conditions.items():
                if condition_key not in context:
                    continue
                
                context_value = context[condition_key]
                if not self._evaluate_condition(context_value, condition_value):
                    return False
        
        return True
    
    def _evaluate_condition(self, context_value: Any, condition_value: Any) -> bool:
        """Evaluate a single condition."""
        if isinstance(condition_value, dict):
            operator = condition_value.get('operator', 'eq')
            value = condition_value.get('value')
            
            if operator == 'eq':
                return context_value == value
            elif operator == 'ne':
                return context_value != value
            elif operator == 'gt':
                return context_value > value
            elif operator == 'gte':
                return context_value >= value
            elif operator == 'lt':
                return context_value < value
            elif operator == 'lte':
                return context_value <= value
            elif operator == 'in':
                return context_value in value
            elif operator == 'not_in':
                return context_value not in value
            elif operator == 'contains':
                return value in str(context_value)
            elif operator == 'regex':
                import re
                return bool(re.search(value, str(context_value)))
        
        return context_value == condition_value


@dataclass
class PolicyViolation:
    """Represents a policy violation."""
    rule_id: str
    rule_name: str
    risk: SecurityRisk
    action: PolicyAction
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_notes: Optional[str] = None


class RiskPolicyEngine:
    """Engine for managing and enforcing risk policies."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the policy engine."""
        self.thresholds = RiskThreshold()
        self.rules: Dict[str, PolicyRule] = {}
        self.violations: List[PolicyViolation] = []
        self.config_path = config_path
        
        # Default policies
        self._load_default_policies()
        
        # Load custom policies if config path provided
        if config_path and config_path.exists():
            self.load_policies(config_path)
    
    def _load_default_policies(self):
        """Load default risk policies."""
        default_rules = [
            PolicyRule(
                id="critical_risk_block",
                name="Block Critical Risks",
                description="Block any operation with critical risk level",
                scope=PolicyScope.GLOBAL,
                risk_categories=set(),
                risk_levels={RiskLevel.CRITICAL},
                action=PolicyAction.BLOCK
            ),
            PolicyRule(
                id="high_risk_warn",
                name="Warn on High Risks",
                description="Generate warning for high risk operations",
                scope=PolicyScope.GLOBAL,
                risk_categories=set(),
                risk_levels={RiskLevel.HIGH},
                action=PolicyAction.WARN
            ),
            PolicyRule(
                id="file_system_audit",
                name="Audit File System Access",
                description="Audit all file system related operations",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.FILE_SYSTEM},
                risk_levels=set(),
                action=PolicyAction.AUDIT
            ),
            PolicyRule(
                id="network_high_risk_quarantine",
                name="Quarantine High-Risk Network Operations",
                description="Quarantine network operations with high risk",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.NETWORK_ACCESS},
                risk_levels={RiskLevel.HIGH, RiskLevel.CRITICAL},
                action=PolicyAction.QUARANTINE
            ),
            PolicyRule(
                id="code_execution_block",
                name="Block Code Execution",
                description="Block tools that can execute arbitrary code",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.CODE_EXECUTION},
                risk_levels={RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL},
                action=PolicyAction.BLOCK
            ),
            PolicyRule(
                id="data_access_audit",
                name="Audit Data Access",
                description="Audit all data access operations",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.DATA_ACCESS},
                risk_levels=set(),
                action=PolicyAction.AUDIT
            ),
            PolicyRule(
                id="authentication_block",
                name="Block Authentication Bypass",
                description="Block operations that could bypass authentication",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.AUTHENTICATION},
                risk_levels={RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL},
                action=PolicyAction.BLOCK
            ),
            PolicyRule(
                id="system_modification_warn",
                name="Warn on System Modifications",
                description="Warn when tools can modify system settings",
                scope=PolicyScope.TOOL,
                risk_categories={RiskCategory.SYSTEM_MODIFICATION},
                risk_levels={RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL},
                action=PolicyAction.WARN
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.id] = rule
    
    def add_rule(self, rule: PolicyRule) -> bool:
        """Add a new policy rule."""
        try:
            if rule.id in self.rules:
                logger.warning(f"Rule {rule.id} already exists, overwriting")
            
            self.rules[rule.id] = rule
            logger.info(f"Added policy rule: {rule.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rule {rule.id}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a policy rule."""
        try:
            if rule_id not in self.rules:
                logger.warning(f"Rule {rule_id} not found")
                return False
            
            del self.rules[rule_id]
            logger.info(f"Removed policy rule: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove rule {rule_id}: {e}")
            return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a policy rule."""
        if rule_id not in self.rules:
            logger.warning(f"Rule {rule_id} not found")
            return False
        
        self.rules[rule_id].enabled = True
        logger.info(f"Enabled policy rule: {rule_id}")
        return True
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a policy rule."""
        if rule_id not in self.rules:
            logger.warning(f"Rule {rule_id} not found")
            return False
        
        self.rules[rule_id].enabled = False
        logger.info(f"Disabled policy rule: {rule_id}")
        return True
    
    def evaluate_risk(self, risk: SecurityRisk, context: Dict[str, Any] = None) -> List[PolicyViolation]:
        """Evaluate a risk against all policies."""
        violations = []
        context = context or {}
        
        for rule in self.rules.values():
            if rule.matches(risk, context):
                violation = PolicyViolation(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    risk=risk,
                    action=rule.action,
                    timestamp=datetime.now(),
                    context=context.copy()
                )
                violations.append(violation)
                self.violations.append(violation)
                
                logger.info(f"Policy violation: {rule.name} -> {rule.action.value}")
        
        return violations
    
    def evaluate_risks(self, risks: List[SecurityRisk], context: Dict[str, Any] = None) -> List[PolicyViolation]:
        """Evaluate multiple risks against all policies."""
        all_violations = []
        
        for risk in risks:
            violations = self.evaluate_risk(risk, context)
            all_violations.extend(violations)
        
        return all_violations
    
    def get_action_for_risk(self, risk: SecurityRisk, context: Dict[str, Any] = None) -> PolicyAction:
        """Get the most restrictive action for a risk."""
        violations = self.evaluate_risk(risk, context)
        
        if not violations:
            return PolicyAction.ALLOW
        
        # Order actions by restrictiveness
        action_priority = {
            PolicyAction.BLOCK: 5,
            PolicyAction.QUARANTINE: 4,
            PolicyAction.WARN: 3,
            PolicyAction.AUDIT: 2,
            PolicyAction.ALLOW: 1
        }
        
        most_restrictive = max(violations, key=lambda v: action_priority[v.action])
        return most_restrictive.action
    
    def is_allowed(self, risk: SecurityRisk, context: Dict[str, Any] = None) -> bool:
        """Check if a risk is allowed by policies."""
        action = self.get_action_for_risk(risk, context)
        return action not in {PolicyAction.BLOCK, PolicyAction.QUARANTINE}
    
    def get_violations(self, resolved: Optional[bool] = None) -> List[PolicyViolation]:
        """Get policy violations, optionally filtered by resolution status."""
        if resolved is None:
            return self.violations.copy()
        
        return [v for v in self.violations if v.resolved == resolved]
    
    def resolve_violation(self, violation_index: int, notes: str = None) -> bool:
        """Mark a violation as resolved."""
        try:
            if 0 <= violation_index < len(self.violations):
                self.violations[violation_index].resolved = True
                self.violations[violation_index].resolution_notes = notes
                logger.info(f"Resolved violation {violation_index}")
                return True
            else:
                logger.warning(f"Invalid violation index: {violation_index}")
                return False
        except Exception as e:
            logger.error(f"Failed to resolve violation {violation_index}: {e}")
            return False
    
    def clear_violations(self, older_than: Optional[timedelta] = None):
        """Clear violations, optionally only those older than specified time."""
        if older_than is None:
            self.violations.clear()
            logger.info("Cleared all violations")
        else:
            cutoff_time = datetime.now() - older_than
            original_count = len(self.violations)
            self.violations = [v for v in self.violations if v.timestamp > cutoff_time]
            cleared_count = original_count - len(self.violations)
            logger.info(f"Cleared {cleared_count} violations older than {older_than}")
    
    def update_thresholds(self, thresholds: RiskThreshold) -> bool:
        """Update risk thresholds."""
        try:
            if not thresholds.validate():
                logger.error("Invalid threshold configuration")
                return False
            
            self.thresholds = thresholds
            logger.info("Updated risk thresholds")
            return True
        except Exception as e:
            logger.error(f"Failed to update thresholds: {e}")
            return False
    
    def load_policies(self, config_path: Path) -> bool:
        """Load policies from configuration file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Load thresholds
            if 'thresholds' in config:
                threshold_data = config['thresholds']
                thresholds = RiskThreshold(**threshold_data)
                self.update_thresholds(thresholds)
            
            # Load rules
            if 'rules' in config:
                for rule_data in config['rules']:
                    # Convert string enums back to enum objects
                    rule_data['scope'] = PolicyScope(rule_data['scope'])
                    rule_data['action'] = PolicyAction(rule_data['action'])
                    rule_data['risk_categories'] = {RiskCategory(cat) for cat in rule_data.get('risk_categories', [])}
                    rule_data['risk_levels'] = {RiskLevel(level) for level in rule_data.get('risk_levels', [])}
                    
                    rule = PolicyRule(**rule_data)
                    self.add_rule(rule)
            
            logger.info(f"Loaded policies from {config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load policies from {config_path}: {e}")
            return False
    
    def save_policies(self, config_path: Path) -> bool:
        """Save policies to configuration file."""
        try:
            config = {
                'thresholds': {
                    'critical': self.thresholds.critical,
                    'high': self.thresholds.high,
                    'medium': self.thresholds.medium,
                    'low': self.thresholds.low,
                    'info': self.thresholds.info
                },
                'rules': []
            }
            
            for rule in self.rules.values():
                rule_data = {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'scope': rule.scope.value,
                    'risk_categories': [cat.value for cat in rule.risk_categories],
                    'risk_levels': [level.value for level in rule.risk_levels],
                    'action': rule.action.value,
                    'enabled': rule.enabled,
                    'conditions': rule.conditions,
                    'metadata': rule.metadata
                }
                config['rules'].append(rule_data)
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Saved policies to {config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save policies to {config_path}: {e}")
            return False
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get a summary of current policies."""
        enabled_rules = [rule for rule in self.rules.values() if rule.enabled]
        disabled_rules = [rule for rule in self.rules.values() if not rule.enabled]
        
        action_counts = {}
        for rule in enabled_rules:
            action_counts[rule.action.value] = action_counts.get(rule.action.value, 0) + 1
        
        scope_counts = {}
        for rule in enabled_rules:
            scope_counts[rule.scope.value] = scope_counts.get(rule.scope.value, 0) + 1
        
        unresolved_violations = len([v for v in self.violations if not v.resolved])
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len(enabled_rules),
            'disabled_rules': len(disabled_rules),
            'action_distribution': action_counts,
            'scope_distribution': scope_counts,
            'total_violations': len(self.violations),
            'unresolved_violations': unresolved_violations,
            'thresholds': {
                'critical': self.thresholds.critical,
                'high': self.thresholds.high,
                'medium': self.thresholds.medium,
                'low': self.thresholds.low,
                'info': self.thresholds.info
            }
        }


class PolicyManager:
    """High-level manager for risk policies."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize the policy manager."""
        self.config_dir = config_dir or Path.cwd() / "config" / "policies"
        self.engines: Dict[str, RiskPolicyEngine] = {}
        
        # Create default engine
        self.engines['default'] = RiskPolicyEngine()
        
        # Load engines from config directory
        if self.config_dir.exists():
            self._load_engines()
    
    def _load_engines(self):
        """Load policy engines from configuration directory."""
        try:
            for config_file in self.config_dir.glob("*.json"):
                engine_name = config_file.stem
                if engine_name != 'default':
                    engine = RiskPolicyEngine(config_file)
                    self.engines[engine_name] = engine
                    logger.info(f"Loaded policy engine: {engine_name}")
        except Exception as e:
            logger.error(f"Failed to load policy engines: {e}")
    
    def get_engine(self, name: str = 'default') -> Optional[RiskPolicyEngine]:
        """Get a policy engine by name."""
        return self.engines.get(name)
    
    def create_engine(self, name: str, config_path: Optional[Path] = None) -> RiskPolicyEngine:
        """Create a new policy engine."""
        engine = RiskPolicyEngine(config_path)
        self.engines[name] = engine
        logger.info(f"Created policy engine: {name}")
        return engine
    
    def remove_engine(self, name: str) -> bool:
        """Remove a policy engine."""
        if name == 'default':
            logger.warning("Cannot remove default policy engine")
            return False
        
        if name in self.engines:
            del self.engines[name]
            logger.info(f"Removed policy engine: {name}")
            return True
        
        logger.warning(f"Policy engine not found: {name}")
        return False
    
    def list_engines(self) -> List[str]:
        """List all available policy engines."""
        return list(self.engines.keys())
    
    def evaluate_with_engine(self, engine_name: str, risks: List[SecurityRisk], 
                           context: Dict[str, Any] = None) -> List[PolicyViolation]:
        """Evaluate risks using a specific policy engine."""
        engine = self.get_engine(engine_name)
        if not engine:
            logger.error(f"Policy engine not found: {engine_name}")
            return []
        
        return engine.evaluate_risks(risks, context)
    
    def is_allowed_by_engine(self, engine_name: str, risk: SecurityRisk, 
                           context: Dict[str, Any] = None) -> bool:
        """Check if a risk is allowed by a specific policy engine."""
        engine = self.get_engine(engine_name)
        if not engine:
            logger.error(f"Policy engine not found: {engine_name}")
            return False
        
        return engine.is_allowed(risk, context)
    
    def save_all_engines(self) -> bool:
        """Save all policy engines to configuration files."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            for name, engine in self.engines.items():
                if name != 'default':  # Don't save default engine
                    config_path = self.config_dir / f"{name}.json"
                    engine.save_policies(config_path)
            
            logger.info("Saved all policy engines")
            return True
        except Exception as e:
            logger.error(f"Failed to save policy engines: {e}")
            return False
    
    def get_global_summary(self) -> Dict[str, Any]:
        """Get a summary of all policy engines."""
        summary = {
            'total_engines': len(self.engines),
            'engines': {}
        }
        
        for name, engine in self.engines.items():
            summary['engines'][name] = engine.get_policy_summary()
        
        return summary


# Convenience functions for common operations
def create_default_policy_engine() -> RiskPolicyEngine:
    """Create a policy engine with default policies."""
    return RiskPolicyEngine()


def evaluate_risk_with_default_policies(risk: SecurityRisk, 
                                       context: Dict[str, Any] = None) -> List[PolicyViolation]:
    """Evaluate a risk using default policies."""
    engine = create_default_policy_engine()
    return engine.evaluate_risk(risk, context)


def is_risk_allowed(risk: SecurityRisk, context: Dict[str, Any] = None) -> bool:
    """Check if a risk is allowed by default policies."""
    engine = create_default_policy_engine()
    return engine.is_allowed(risk, context)
