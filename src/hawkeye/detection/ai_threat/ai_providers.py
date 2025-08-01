"""
AI Provider Framework for Threat Analysis

This module provides AI provider abstractions and implementations for
generating dynamic threat analyses using various AI services.
"""


import json
import logging
import time
import re
import random
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime, timedelta
from enum import Enum

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AnalysisMetadata,
    ThreatLevel, AttackVector, AbuseScenario, MitigationStrategy, DetectionIndicator
)
from .prompts import ThreatAnalysisPrompts


logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """Types of errors for categorized retry strategies."""
    NETWORK_ERROR = "network_error"
    RATE_LIMIT = "rate_limit"
    API_ERROR = "api_error"
    AUTHENTICATION_ERROR = "authentication_error"
    QUOTA_EXCEEDED = "quota_exceeded"
    PARSING_ERROR = "parsing_error"
    TIMEOUT_ERROR = "timeout_error"
    UNKNOWN_ERROR = "unknown_error"


class RetryStrategy(Enum):
    """Retry strategy types."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_DELAY = "fixed_delay"
    NO_RETRY = "no_retry"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter: bool = True
    retry_on_errors: List[ErrorType] = None
    
    def __post_init__(self):
        if self.retry_on_errors is None:
            self.retry_on_errors = [
                ErrorType.NETWORK_ERROR,
                ErrorType.RATE_LIMIT,
                ErrorType.TIMEOUT_ERROR,
                ErrorType.API_ERROR
            ]


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    success_threshold: int = 2
    monitoring_window: float = 300.0  # 5 minutes


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class ProviderHealth:
    """Health tracking for AI providers."""
    provider_name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    consecutive_failures: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    average_response_time: float = 0.0
    circuit_breaker_state: CircuitBreakerState = CircuitBreakerState.CLOSED
    circuit_breaker_until: Optional[datetime] = None
    error_rates: Dict[ErrorType, int] = None
    
    def __post_init__(self):
        if self.error_rates is None:
            self.error_rates = {error_type: 0 for error_type in ErrorType}
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 1.0
        return self.successful_requests / self.total_requests
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        return 1.0 - self.success_rate
    
    @property
    def is_healthy(self) -> bool:
        """Check if provider is healthy."""
        return (
            self.circuit_breaker_state == CircuitBreakerState.CLOSED and
            self.consecutive_failures < 3 and
            self.success_rate > 0.7
        )


class ErrorClassifier:
    """Classifies errors for appropriate retry strategies."""
    
    def __init__(self):
        """Initialize error classifier with patterns."""
        self.error_patterns = {
            ErrorType.NETWORK_ERROR: [
                r'connection.*error',
                r'network.*error',
                r'socket.*error',
                r'dns.*error',
                r'connection.*timeout',
                r'connection.*refused'
            ],
            ErrorType.RATE_LIMIT: [
                r'rate.*limit',
                r'too.*many.*requests',
                r'quota.*exceeded',
                r'throttle',
                r'429'
            ],
            ErrorType.API_ERROR: [
                r'api.*error',
                r'internal.*server.*error',
                r'service.*unavailable',
                r'bad.*gateway',
                r'502|503|504'
            ],
            ErrorType.AUTHENTICATION_ERROR: [
                r'auth.*error',
                r'unauthorized',
                r'invalid.*key',
                r'access.*denied',
                r'401|403'
            ],
            ErrorType.QUOTA_EXCEEDED: [
                r'quota.*exceeded',
                r'limit.*exceeded',
                r'insufficient.*credits',
                r'billing.*error'
            ],
            ErrorType.PARSING_ERROR: [
                r'parse.*error',
                r'json.*error',
                r'invalid.*response',
                r'decode.*error'
            ],
            ErrorType.TIMEOUT_ERROR: [
                r'timeout',
                r'timed.*out',
                r'deadline.*exceeded'
            ]
        }
    
    def classify_error(self, error_message: str) -> ErrorType:
        """Classify error based on message content."""
        error_message_lower = error_message.lower()
        
        for error_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_message_lower):
                    return error_type
        
        return ErrorType.UNKNOWN_ERROR


class AdvancedRetryHandler:
    """Advanced retry handler with exponential backoff and circuit breaker."""
    
    def __init__(self, 
                 retry_config: RetryConfig,
                 circuit_breaker_config: CircuitBreakerConfig):
        """Initialize advanced retry handler."""
        self.retry_config = retry_config
        self.circuit_breaker_config = circuit_breaker_config
        self.error_classifier = ErrorClassifier()
        self.provider_health = {}
        
    def should_retry(self, error: Exception, error_type: ErrorType, attempt: int) -> bool:
        """Determine if operation should be retried."""
        if attempt >= self.retry_config.max_attempts:
            return False
        
        if error_type not in self.retry_config.retry_on_errors:
            return False
        
        # Don't retry authentication errors
        if error_type == ErrorType.AUTHENTICATION_ERROR:
            return False
        
        return True
    
    def calculate_delay(self, attempt: int, strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF) -> float:
        """Calculate retry delay based on strategy."""
        if strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = min(
                self.retry_config.base_delay * (self.retry_config.backoff_multiplier ** attempt),
                self.retry_config.max_delay
            )
        elif strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = min(
                self.retry_config.base_delay * attempt,
                self.retry_config.max_delay
            )
        else:  # FIXED_DELAY
            delay = self.retry_config.base_delay
        
        # Add jitter to prevent thundering herd
        if self.retry_config.jitter:
            jitter_amount = delay * 0.1 * random.random()
            delay += jitter_amount
        
        return delay
    
    def update_provider_health(self, 
                             provider_name: str, 
                             success: bool, 
                             response_time: float = 0.0,
                             error_type: Optional[ErrorType] = None):
        """Update provider health metrics."""
        if provider_name not in self.provider_health:
            self.provider_health[provider_name] = ProviderHealth(provider_name=provider_name)
        
        health = self.provider_health[provider_name]
        health.total_requests += 1
        
        if success:
            health.successful_requests += 1
            health.consecutive_failures = 0
            health.last_success = datetime.now()
            
            # Update average response time
            if health.total_requests == 1:
                health.average_response_time = response_time
            else:
                health.average_response_time = (
                    health.average_response_time * 0.9 + response_time * 0.1
                )
            
            # Check if circuit breaker should close
            if health.circuit_breaker_state == CircuitBreakerState.HALF_OPEN:
                if health.consecutive_failures == 0:
                    health.circuit_breaker_state = CircuitBreakerState.CLOSED
                    health.circuit_breaker_until = None
                    logger.info(f"Circuit breaker closed for provider {provider_name}")
        else:
            health.failed_requests += 1
            health.consecutive_failures += 1
            health.last_failure = datetime.now()
            
            if error_type:
                health.error_rates[error_type] += 1
            
            # Check if circuit breaker should open
            if (health.consecutive_failures >= self.circuit_breaker_config.failure_threshold and
                health.circuit_breaker_state == CircuitBreakerState.CLOSED):
                
                health.circuit_breaker_state = CircuitBreakerState.OPEN
                health.circuit_breaker_until = datetime.now() + timedelta(
                    seconds=self.circuit_breaker_config.recovery_timeout
                )
                logger.warning(f"Circuit breaker opened for provider {provider_name}")
    
    def is_circuit_breaker_open(self, provider_name: str) -> bool:
        """Check if circuit breaker is open for provider."""
        if provider_name not in self.provider_health:
            return False
        
        health = self.provider_health[provider_name]
        
        if health.circuit_breaker_state == CircuitBreakerState.OPEN:
            if datetime.now() >= health.circuit_breaker_until:
                health.circuit_breaker_state = CircuitBreakerState.HALF_OPEN
                logger.info(f"Circuit breaker half-open for provider {provider_name}")
                return False
            return True
        
        return False
    
    def get_best_provider(self, available_providers: List[str]) -> Optional[str]:
        """Get the best available provider based on health metrics."""
        healthy_providers = []
        
        for provider_name in available_providers:
            if self.is_circuit_breaker_open(provider_name):
                continue
            
            if provider_name in self.provider_health:
                health = self.provider_health[provider_name]
                if health.is_healthy:
                    healthy_providers.append((provider_name, health))
            else:
                # New provider - give it a chance
                healthy_providers.append((provider_name, None))
        
        if not healthy_providers:
            return None
        
        # Sort by success rate and response time
        def provider_score(provider_info):
            provider_name, health = provider_info
            if health is None:
                return 1.0  # New provider gets highest priority
            
            # Combine success rate and response time (lower is better for response time)
            response_time_score = 1.0 / (1.0 + health.average_response_time)
            return health.success_rate * 0.7 + response_time_score * 0.3
        
        healthy_providers.sort(key=provider_score, reverse=True)
        return healthy_providers[0][0]
    
    def get_health_statistics(self) -> Dict[str, Any]:
        """Get comprehensive health statistics."""
        stats = {
            "total_providers": len(self.provider_health),
            "healthy_providers": 0,
            "providers_with_open_circuit": 0,
            "provider_details": {}
        }
        
        for provider_name, health in self.provider_health.items():
            if health.is_healthy:
                stats["healthy_providers"] += 1
            
            if health.circuit_breaker_state == CircuitBreakerState.OPEN:
                stats["providers_with_open_circuit"] += 1
            
            stats["provider_details"][provider_name] = {
                "success_rate": health.success_rate,
                "failure_rate": health.failure_rate,
                "average_response_time": health.average_response_time,
                "consecutive_failures": health.consecutive_failures,
                "circuit_breaker_state": health.circuit_breaker_state.value,
                "total_requests": health.total_requests,
                "error_breakdown": {error_type.value: count for error_type, count in health.error_rates.items()}
            }
        
        return stats


def retry_with_backoff(
    operation: Callable,
    retry_handler: AdvancedRetryHandler,
    provider_name: str,
    max_attempts: int = 3,
    operation_name: str = "operation"
) -> Any:
    """
    Execute operation with advanced retry logic.
    
    Args:
        operation: Async operation to execute
        retry_handler: Advanced retry handler
        provider_name: Name of the provider
        max_attempts: Maximum retry attempts
        operation_name: Name of operation for logging
        
    Returns:
        Operation result
        
    Raises:
        Exception: If all retry attempts fail
    """
    last_exception = None
    
    for attempt in range(max_attempts):
        try:
            # Check circuit breaker
            if retry_handler.is_circuit_breaker_open(provider_name):
                raise Exception(f"Circuit breaker open for provider {provider_name}")
            
            start_time = time.time()
            result = operation()
            response_time = time.time() - start_time
            
            # Update success metrics
            retry_handler.update_provider_health(
                provider_name, 
                success=True, 
                response_time=response_time
            )
            
            if attempt > 0:
                logger.info(f"{operation_name} succeeded on attempt {attempt + 1}")
            
            return result
            
        except Exception as e:
            last_exception = e
            response_time = time.time() - start_time if 'start_time' in locals() else 0.0
            
            # Classify error
            error_type = retry_handler.error_classifier.classify_error(str(e))
            
            # Update failure metrics
            retry_handler.update_provider_health(
                provider_name,
                success=False,
                response_time=response_time,
                error_type=error_type
            )
            
            # Check if we should retry
            if not retry_handler.should_retry(e, error_type, attempt):
                logger.error(f"{operation_name} failed on attempt {attempt + 1}, no retry: {e}")
                break
            
            if attempt < max_attempts - 1:
                delay = retry_handler.calculate_delay(attempt)
                logger.warning(f"{operation_name} failed on attempt {attempt + 1}, retrying in {delay:.2f}s: {e}")
                time.sleep(delay)
    
    # All attempts failed
    logger.error(f"{operation_name} failed after {max_attempts} attempts")
    raise last_exception


class ResponseParser:
    """
    Comprehensive response parser for AI-generated threat analysis.
    
    Handles multiple response formats, validation, and fallback strategies
    to ensure robust parsing of AI responses into structured ThreatAnalysis objects.
    """
    
    def __init__(self):
        """Initialize the response parser."""
        self.parsing_stats = {
            "total_parses": 0,
            "successful_parses": 0,
            "failed_parses": 0,
            "fallback_parses": 0,
            "validation_errors": 0
        }
    
    def parse_analysis_response(self, 
                              content: str, 
                              analysis_type: str,
                              tool_capabilities: ToolCapabilities,
                              environment_context: EnvironmentContext,
                              response_schema: Optional[Dict[str, Any]] = None) -> Optional[ThreatAnalysis]:
        """
        Parse AI response into ThreatAnalysis object with comprehensive error handling.
        
        Args:
            content: Raw AI response content
            analysis_type: Type of analysis performed
            tool_capabilities: Original tool capabilities
            environment_context: Environment context used
            response_schema: Expected response schema for validation
            
        Returns:
            ThreatAnalysis object or None if parsing fails
        """
        self.parsing_stats["total_parses"] += 1
        
        try:
            logger.debug(f"Parsing {analysis_type} response ({len(content)} chars)")
            
            # DEBUG: Log the raw AI response to understand parsing failures
            logger.info(f"=== RAW AI RESPONSE DEBUG ({len(content)} chars) ===")
            logger.info(f"First 500 chars: {content[:500]}")
            logger.info(f"Last 500 chars: {content[-500:]}")
            logger.info("=== END RAW RESPONSE ===")
            
            # Strategy 1: Direct JSON extraction
            parsed_data = self._extract_json_data(content)
            if parsed_data:
                logger.debug("Successfully extracted JSON data")
                
                # Make schema validation more flexible - don't reject good content
                schema_valid = True
                if response_schema:
                    schema_valid = self._validate_response_schema(parsed_data, response_schema)
                    if not schema_valid:
                        logger.warning("Response failed strict schema validation, but attempting to use it anyway")
                        self.parsing_stats["validation_errors"] += 1
                
                            # Convert to ThreatAnalysis - attempt even if schema validation failed
            try:
                threat_analysis = self._convert_to_threat_analysis(
                    parsed_data, 
                    analysis_type,
                    tool_capabilities,
                    environment_context
                )
                if threat_analysis:
                    self.parsing_stats["successful_parses"] += 1
                    logger.info("Successfully converted AI response to ThreatAnalysis")
                    return threat_analysis
                else:
                    logger.warning("Failed to convert parsed data to ThreatAnalysis")
            except Exception as e:
                logger.error(f"Exception during ThreatAnalysis conversion: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Strategy 2: Structured text extraction
            logger.debug("JSON extraction failed, attempting structured text parsing")
            structured_data = self._extract_structured_text(content, analysis_type)
            if structured_data:
                logger.debug("Successfully extracted structured text data")
                threat_analysis = self._convert_to_threat_analysis(
                    structured_data,
                    analysis_type,
                    tool_capabilities,
                    environment_context
                )
                if threat_analysis:
                    self.parsing_stats["fallback_parses"] += 1
                    return threat_analysis
            
            # Strategy 3: Log parsing failure and return None to trigger rule-based fallback
            logger.debug("Structured parsing failed, will use enhanced rule-based analysis")
            self.parsing_stats["failed_parses"] += 1
            return None
            
        except Exception as e:
            logger.error(f"Response parsing error: {e}")
            self.parsing_stats["failed_parses"] += 1
            return None
    
    def _extract_json_data(self, content: str) -> Optional[Dict[str, Any]]:
        """Extract JSON data from AI response content with improved parsing."""
        if not content or not content.strip():
            return None
        
        # FIRST: Try direct parsing - most AI responses are clean JSON
        try:
            stripped_content = content.strip()
            logger.debug(f"Trying direct JSON parse on {len(stripped_content)} chars")
            direct_data = json.loads(stripped_content)
            if isinstance(direct_data, dict) and len(direct_data) > 0:
                logger.info(f"✅ Direct JSON parsing succeeded! Keys: {list(direct_data.keys())}")
                # Check if it's threat analysis data
                if any(key in direct_data for key in ['threat_level', 'attack_vectors', 'confidence_score']):
                    logger.info("✅ Contains threat analysis data - accepting!")
                    return direct_data
                else:
                    logger.debug(f"Direct parsed JSON missing threat keys: {list(direct_data.keys())}")
        except json.JSONDecodeError as e:
            logger.debug(f"Direct JSON parse failed: {e}")
            
        try:
            # Strategy 1: Look for complete JSON object with enhanced patterns
            json_patterns = [
                r'```json\s*(\{.*?\})\s*```',  # Markdown code blocks
                r'```\s*(\{.*?\})\s*```',      # Generic code blocks  
                r'<json>\s*(\{.*?\})\s*</json>',  # XML-style tags
                # Most permissive pattern - match any balanced braces structure
                r'(?s)(\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\})*)*\})*)*\})',  # Deeply nested JSON
                # If the content starts with { and looks like JSON, try to capture it all
                r'(?s)^(\{.*\})$',  # Entire content is JSON
                r'(?s)(\{.*"threat_level".*\})',  # Contains threat_level anywhere
            ]
            
            logger.debug(f"Trying to extract JSON from content of length {len(content)}")
            logger.debug(f"Content starts with: {content[:100]}")
            logger.debug(f"Content ends with: {content[-100:]}")
            
            # Quick test: try parsing the content directly after stripping whitespace
            try:
                stripped_content = content.strip()
                if stripped_content.startswith('{') and stripped_content.endswith('}'):
                    logger.debug("Content looks like pure JSON, trying direct parse")
                    direct_data = json.loads(stripped_content)
                    if isinstance(direct_data, dict) and 'threat_level' in direct_data:
                        logger.info("Direct JSON parsing succeeded!")
                        return direct_data
            except json.JSONDecodeError as e:
                logger.debug(f"Direct JSON parse failed: {e}")
            
            for i, pattern in enumerate(json_patterns):
                logger.debug(f"Trying pattern {i+1}/{len(json_patterns)}: {pattern[:50]}...")
                matches = re.findall(pattern, content, re.DOTALL)
                logger.debug(f"Pattern {i+1} found {len(matches)} matches")
                for match in matches:
                    try:
                        # Clean the JSON string
                        json_str = match if isinstance(match, str) else match
                        json_str = self._clean_json_string(json_str)
                        
                        logger.debug(f"Attempting to parse JSON string: {json_str[:200]}...")
                        
                        # Parse JSON
                        data = json.loads(json_str)
                        if isinstance(data, dict) and len(data) > 0:
                            logger.debug(f"Successfully parsed JSON with keys: {list(data.keys())}")
                            # Be more permissive - if it has threat analysis keys, accept it
                            threat_keys = ['threat_level', 'attack_vectors', 'confidence_score']
                            if any(key in data for key in threat_keys):
                                logger.info(f"JSON contains threat analysis data, accepting. Keys found: {[k for k in threat_keys if k in data]}")
                                return data
                            else:
                                logger.debug(f"JSON missing expected threat analysis keys. Available keys: {list(data.keys())}")
                                # For debugging - let's also check if the validation would pass
                                if self._validate_threat_analysis_structure(data):
                                    logger.info("JSON passed structure validation, accepting anyway")
                                    return data
                        else:
                            logger.debug(f"Parsed data is not a valid dict or is empty: {type(data)}, length: {len(data) if hasattr(data, '__len__') else 'N/A'}")
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON parsing failed: {e}")
                        continue
            
            # Strategy 2: Try parsing the entire content as JSON
            try:
                cleaned_content = self._clean_json_string(content)
                data = json.loads(cleaned_content)
                if isinstance(data, dict) and self._validate_threat_analysis_structure(data):
                    return data
            except json.JSONDecodeError:
                pass
            
            # Strategy 3: Extract the largest JSON-like structure and validate it
            json_candidates = re.findall(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content)
            for candidate in sorted(json_candidates, key=len, reverse=True):
                try:
                    cleaned = self._clean_json_string(candidate)
                    data = json.loads(cleaned)
                    if isinstance(data, dict) and len(data) > 0:
                        if self._validate_threat_analysis_structure(data):
                            return data
                except json.JSONDecodeError:
                    continue
            
            return None
            
        except Exception as e:
            logger.error(f"JSON extraction failed: {e}")
            return None
    
    def _clean_json_string(self, json_str: str) -> str:
        """Clean JSON string to improve parsing success."""
        # Remove common formatting issues
        json_str = json_str.strip()
        
        # Remove markdown formatting
        json_str = re.sub(r'^```json\s*', '', json_str, flags=re.MULTILINE)
        json_str = re.sub(r'^```\s*', '', json_str, flags=re.MULTILINE)
        json_str = re.sub(r'\s*```$', '', json_str, flags=re.MULTILINE)
        
        # Remove XML-style tags
        json_str = re.sub(r'^<json>\s*', '', json_str, flags=re.MULTILINE)
        json_str = re.sub(r'\s*</json>$', '', json_str, flags=re.MULTILINE)
        
        # Fix common JSON issues
        json_str = re.sub(r',\s*}', '}', json_str)  # Remove trailing commas
        json_str = re.sub(r',\s*]', ']', json_str)  # Remove trailing commas in arrays
        
        # Fix unescaped quotes in strings (basic attempt)
        json_str = re.sub(r'(?<!\\)"(?![,\]\}:\s])', r'\"', json_str)
        
        return json_str
    
    def _extract_structured_text(self, content: str, analysis_type: str) -> Optional[Dict[str, Any]]:
        """Extract structured data from text when JSON parsing fails."""
        try:
            extracted_data = {
                "threat_level": "medium",
                "attack_vectors": [],
                "abuse_scenarios": [],
                "mitigation_strategies": [],
                "confidence_score": 0.6
            }
            
            # Extract threat level
            threat_patterns = [
                r'threat\s+level[:\s]+(\w+)',
                r'risk\s+level[:\s]+(\w+)',
                r'overall\s+risk[:\s]+(\w+)',
                r'severity[:\s]+(\w+)'
            ]
            
            for pattern in threat_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    threat_level = match.group(1).lower()
                    if threat_level in ['low', 'medium', 'high', 'critical', 'minimal']:
                        extracted_data["threat_level"] = threat_level
                    break
            
            # Extract attack vectors
            attack_vector_patterns = [
                r'attack\s+vector[s]?[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)',
                r'vulnerabilit(?:y|ies)[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)',
                r'threats?[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)'
            ]
            
            for pattern in attack_vector_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    vectors = self._parse_list_items(match)
                    for vector in vectors:
                        if len(vector.strip()) > 10:  # Minimum meaningful length
                            extracted_data["attack_vectors"].append({
                                "name": vector[:50].strip(),
                                "description": vector.strip(),
                                "severity": "medium",
                                "likelihood": 0.5,
                                "attack_steps": [],
                                "prerequisites": [],
                                "impact": "Unknown",
                                "mitigations": []
                            })
            
            # Extract mitigation strategies
            mitigation_patterns = [
                r'mitigation[s]?[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)',
                r'recommendation[s]?[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)',
                r'prevention[:\s]*\n?(.*?)(?=\n\n|\n[A-Z]|\Z)'
            ]
            
            for pattern in mitigation_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    mitigations = self._parse_list_items(match)
                    for mitigation in mitigations:
                        if len(mitigation.strip()) > 10:
                            extracted_data["mitigation_strategies"].append({
                                "name": mitigation[:50].strip(),
                                "description": mitigation.strip(),
                                "implementation_steps": [],
                                "effectiveness_score": 0.7
                            })
            
            # Extract confidence score
            confidence_patterns = [
                r'confidence[:\s]+(\d*\.?\d+)',
                r'certainty[:\s]+(\d*\.?\d+)',
                r'accuracy[:\s]+(\d*\.?\d+)'
            ]
            
            for pattern in confidence_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    try:
                        confidence = float(match.group(1))
                        if 0 <= confidence <= 1:
                            extracted_data["confidence_score"] = confidence
                        elif 0 <= confidence <= 100:
                            extracted_data["confidence_score"] = confidence / 100
                    except ValueError:
                        pass
                    break
            
            return extracted_data if extracted_data["attack_vectors"] or extracted_data["mitigation_strategies"] else None
            
        except Exception as e:
            logger.error(f"Structured text extraction failed: {e}")
            return None
    
    def _parse_list_items(self, text: str) -> List[str]:
        """Parse list items from text."""
        items = []
        
        # Try different list formats
        list_patterns = [
            r'^\s*[-*+]\s+(.+)$',  # Bullet points
            r'^\s*\d+\.\s+(.+)$',  # Numbered lists
            r'^\s*[•‣▪▫]\s+(.+)$',  # Unicode bullets
        ]
        
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Skip JSON fragments - these are not valid attack vectors
            if (line.startswith('"') and line.endswith('",') or 
                line.startswith('"') and line.endswith('"') or
                line.startswith('{') or line.startswith('}') or
                line.startswith('[') or line.startswith(']') or
                line.strip() in ['{', '}', '[', ']', ','] or
                re.match(r'^\s*"[\w_]+"\s*:\s*', line) or  # JSON key-value pairs
                re.match(r'^\s*\d+\.\d+\s*,?\s*$', line) or  # Standalone numbers
                len(line) < 10):  # Too short to be meaningful
                continue
                
            for pattern in list_patterns:
                match = re.match(pattern, line, re.MULTILINE)
                if match:
                    item = match.group(1).strip()
                    if len(item) > 10 and not self._is_json_fragment(item):  # Minimum meaningful length and not JSON
                        items.append(item)
                    break
            else:
                # Only add as plain text if it's not a JSON fragment and has substance
                if (len(line) > 15 and 
                    not self._is_json_fragment(line) and
                    not line.startswith('//') and  # Skip comments
                    not line.startswith('#') and   # Skip comments
                    line.count(' ') >= 2):  # Ensure it has multiple words
                    items.append(line)
        
        return items
    
    def _is_json_fragment(self, text: str) -> bool:
        """Check if text looks like a JSON fragment that shouldn't be treated as valid content."""
        text = text.strip()
        
        # Enhanced JSON fragment detection patterns
        json_patterns = [
            r'^"[\w_]+"\s*:\s*',                    # Key-value start like "impact": 
            r'^\s*[\d.]+\s*$',                      # Numbers only
            r'^"[^"]*",?\s*$',                      # Quoted strings only
            r'^\s*[{\[\]},]\s*$',                   # JSON structural characters only
            r'^"(name|description|severity|impact|likelihood|confidence_score|attack_steps|example_code)"\s*:',  # Common JSON keys
            r'^"[^"]*"\s*:\s*"[^"]*"$',            # Simple key-value pairs
            r'^\s*\[\s*\]$',                        # Empty arrays
            r'^\s*\{\s*\}$',                        # Empty objects
            r'.*Complete\s+compromise.*',           # The specific fragment mentioned in memory
            r'^["\'][\w\s]+["\']$',                # Pure quoted strings
            r'^\s*,\s*$',                          # Lone commas
            r'^\s*:\s*$',                          # Lone colons
            r'^"_?[\w_]+"\s*:\s*.*,?\s*$',         # JSON key-value patterns like "_actor": "value",
            r'^.*"\s*:\s*".*",?\s*$',              # Any key-value pattern with quotes
            r'^\s*"[^"]*"\s*:\s*.*$',              # Quoted key with any value
            r'.*Corporate\s+Espionage\s+Agent.*',   # Specific problematic fragment
        ]
        
        for pattern in json_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                return True
        
        # Additional heuristics for detecting malformed JSON fragments
        # Check if it's just a value without context
        if ('"' in text and ':' in text and 
            text.count('"') % 2 == 0 and 
            len(text.split()) < 10):  # Short fragments are likely JSON pieces
            return True
            
        return False
    
    def _extract_partial_data(self, content: str, analysis_type: str) -> Dict[str, Any]:
        """Extract partial data with fallback values when other methods fail."""
        # Create minimal valid structure
        partial_data = {
            "threat_level": "medium",
            "attack_vectors": [],
            "abuse_scenarios": [],
            "mitigation_strategies": [],
            "confidence_score": 0.4  # Lower confidence for partial extraction
        }
        
        # Try to infer threat level from keywords
        content_lower = content.lower()
        if any(word in content_lower for word in ['critical', 'severe', 'dangerous', 'high risk']):
            partial_data["threat_level"] = "high"
        elif any(word in content_lower for word in ['low risk', 'minimal', 'safe', 'secure']):
            partial_data["threat_level"] = "low"
        
        # Add generic attack vector if security concerns are mentioned
        if any(word in content_lower for word in ['vulnerability', 'attack', 'exploit', 'risk', 'threat']):
            partial_data["attack_vectors"].append({
                "name": "Security Concern",
                "description": "Potential security concerns identified in analysis",
                "severity": "medium",
                "likelihood": 0.5,
                "attack_steps": [],
                "prerequisites": [],
                "impact": "Potential security impact",
                "mitigations": []
            })
        
        # Add generic mitigation
        partial_data["mitigation_strategies"].append({
            "name": "General Security Review",
            "description": "Conduct thorough security review and implement best practices",
            "implementation_steps": [
                "Review security configuration",
                "Apply security updates",
                "Implement monitoring"
            ],
            "effectiveness_score": 0.6
        })
        
        return partial_data
    
    def _validate_response_schema(self, data: Dict[str, Any], schema: Dict[str, Any]) -> bool:
        """Validate response data against expected schema."""
        try:
            # Basic schema validation - check required fields exist
            required_fields = schema.get("required", [])
            for field in required_fields:
                if field not in data:
                    logger.warning(f"Missing required field: {field}")
                    return False
            
            # Check data types for known fields
            properties = schema.get("properties", {})
            for field, field_schema in properties.items():
                if field in data:
                    expected_type = field_schema.get("type")
                    if expected_type == "array" and not isinstance(data[field], list):
                        logger.warning(f"Field {field} should be array but is {type(data[field])}")
                        return False
                    elif expected_type == "string" and not isinstance(data[field], str):
                        logger.warning(f"Field {field} should be string but is {type(data[field])}")
                        return False
                    elif expected_type == "number" and not isinstance(data[field], (int, float)):
                        logger.warning(f"Field {field} should be number but is {type(data[field])}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Schema validation error: {e}")
            return False
    
    def _validate_threat_analysis_structure(self, data: dict) -> bool:
        """Validate that the parsed JSON has the expected threat analysis structure."""
        if not isinstance(data, dict):
            return False
            
        # Check for required fields
        required_fields = ['threat_level']
        optional_fields = ['attack_vectors', 'mitigation_strategies', 'abuse_scenarios', 'confidence_score']
        
        # Must have at least the threat level
        if not any(field in data for field in required_fields):
            return False
            
        # Check that attack_vectors is a list if present
        if 'attack_vectors' in data:
            if not isinstance(data['attack_vectors'], list):
                return False
            # Validate attack vector structure
            for av in data['attack_vectors']:
                if isinstance(av, dict):
                    if not ('name' in av and 'description' in av):
                        return False
                elif isinstance(av, str):
                    # String attack vectors should be meaningful
                    if len(av.strip()) < 10 or self._is_json_fragment(av):
                        return False
                        
        # Check that mitigation_strategies is a list if present  
        if 'mitigation_strategies' in data:
            if not isinstance(data['mitigation_strategies'], list):
                return False
                
        return True
    
    def _convert_to_threat_analysis(self,
                                  data: Dict[str, Any],
                                  analysis_type: str,
                                  tool_capabilities: ToolCapabilities,
                                  environment_context: EnvironmentContext) -> Optional[ThreatAnalysis]:
        """Convert parsed AI JSON data to ThreatAnalysis object with proper mapping."""
        try:
            logger.info(f"Converting AI JSON to ThreatAnalysis object. Data keys: {list(data.keys()) if data else 'None'}")
            
            # Check if data is None
            if data is None:
                logger.error("Data is None in _convert_to_threat_analysis")
                return None
            
            # Import required classes
            from .models import (
                ThreatAnalysis, AttackVector, AbuseScenario, MitigationStrategy,
                DetectionIndicator, ComplianceImpact, AnalysisMetadata,
                SeverityLevel, ThreatLevel, ThreatActorType, AttackStep, BusinessImpact, AccessLevel,
                ComplianceFramework
            )
            from datetime import datetime
            
            # Parse attack vectors from AI JSON
            attack_vectors = []
            for av_data in data.get("attack_vectors", []):
                logger.debug(f"Processing attack vector: {av_data.get('name', 'Unknown')}")
                
                # Validate and sanitize attack vector data before processing
                vector_name = av_data.get("name", "Unknown Attack")
                vector_description = av_data.get("description", "")
                
                # Skip if name or description contains JSON fragments
                if (self._is_json_fragment(vector_name) or 
                    self._is_json_fragment(vector_description) or
                    len(vector_name.strip()) < 5):
                    logger.warning(f"Skipping malformed attack vector with name: {vector_name[:50]}...")
                    continue
                
                # Map severity level
                severity_str = av_data.get("severity", "medium")
                severity = SeverityLevel.from_string(severity_str)
                
                attack_vector = AttackVector(
                    name=vector_name,
                    severity=severity,
                    description=vector_description,
                    attack_steps=av_data.get("attack_steps", []),
                    example_code=av_data.get("example_code", "# Example code not provided"),
                    prerequisites=av_data.get("prerequisites", []),
                    impact=av_data.get("impact", ""),
                    likelihood=float(av_data.get("likelihood", 0.5)),
                    mitigations=av_data.get("mitigations", [])
                )
                attack_vectors.append(attack_vector)
            
            # If all attack vectors were filtered out as JSON fragments, create a fallback
            if not attack_vectors and data.get("attack_vectors"):
                logger.warning("All attack vectors were filtered as JSON fragments, creating fallback attack vector")
                
                # Try to create a more specific description based on server data
                server_info = data.get("server_info", {})
                transport = server_info.get("transport_type", "unknown transport")
                host = server_info.get("host", "unknown host")
                port = server_info.get("port", "unknown port")
                
                if transport != "unknown transport":
                    description = f"Security analysis of MCP server using {transport} transport on {host}:{port}"
                    impact = f"Potential unauthorized access via {transport} protocol"
                else:
                    description = "Security analysis of detected MCP server with unknown configuration"
                    impact = "Potential unauthorized access to MCP server functionality"
                
                attack_vectors.append(AttackVector(
                    name="MCP Server Security Analysis",
                    severity=SeverityLevel.MEDIUM,
                    description=description,
                    attack_steps=[
                        "Enumerate MCP server endpoints and capabilities",
                        "Test for authentication bypass vulnerabilities", 
                        "Analyze transport security configuration",
                        "Evaluate access control mechanisms",
                        "Assess potential for privilege escalation"
                    ],
                    example_code=f"# MCP server security assessment\n# Target: {host}:{port} via {transport}\n# Analyze server endpoints and security controls\nimport requests\nresponse = requests.get('http://{host}:{port}/mcp')\n# Analyze response for security indicators",
                    prerequisites=["Network access to MCP server"],
                    impact=impact,
                    mitigations=[]
                ))
            
            logger.info(f"Converted {len(attack_vectors)} attack vectors")
            
            # Parse abuse scenarios from AI JSON
            abuse_scenarios = []
            for as_data in data.get("abuse_scenarios", []):
                # Convert attack_flow to AttackStep objects
                attack_flow = []
                for i, step in enumerate(as_data.get("attack_flow", [])):
                    attack_step = AttackStep(
                        step_number=i + 1,
                        description=str(step),
                        prerequisites=[],
                        tools_required=[]
                    )
                    attack_flow.append(attack_step)
                
                business_impact = BusinessImpact(
                    financial_impact=as_data.get("impact", "Unknown"),
                    operational_impact=as_data.get("impact", "Unknown"),
                    reputation_impact=as_data.get("impact", "Unknown")
                )
                
                scenario = AbuseScenario(
                    scenario_name=as_data.get("scenario_name", "Unknown Scenario"),
                    threat_actor=ThreatActorType.EXTERNAL_ATTACKER,  # Default
                    motivation=as_data.get("motivation", "Unknown"),
                    attack_flow=attack_flow,
                    required_access=AccessLevel.USER,
                    business_impact=business_impact
                )
                abuse_scenarios.append(scenario)
            
            # Parse mitigation strategies
            mitigation_strategies = []
            for mit_data in data.get("mitigation_strategies", []):
                mitigation = MitigationStrategy(
                    name=mit_data.get("name", mit_data.get("description", "Security Control")[:50]),
                    description=mit_data.get("description", ""),
                    implementation_steps=mit_data.get("implementation_steps", []),
                    effectiveness_score=float(mit_data.get("effectiveness", 0.7))
                )
                mitigation_strategies.append(mitigation)
            
            # Map threat level
            threat_level_str = data.get("threat_level", "medium")
            logger.info(f"Extracted threat level: {threat_level_str}")
            threat_level = ThreatLevel.from_string(threat_level_str)
            
            # Create analysis metadata
            analysis_metadata = AnalysisMetadata(
                provider="anthropic",
                model="claude-3-5-sonnet-latest",
                timestamp=datetime.now(),
                analysis_duration=0.0,
                cost=0.0,
                confidence_score=float(data.get("confidence_score", 0.8))
            )
            
            # Create compliance impact (simplified)
            compliance_impact = ComplianceImpact(
                affected_frameworks=[ComplianceFramework.SOC2, ComplianceFramework.ISO_27001],
                violation_risk=threat_level,  # This should be a ThreatLevel enum
                required_controls=["Access controls", "Monitoring", "Incident response"]
            )
            
            # Create the ThreatAnalysis object
            threat_analysis = ThreatAnalysis(
                tool_signature=tool_capabilities.tool_id,
                tool_capabilities=tool_capabilities,
                environment_context=environment_context,
                threat_level=threat_level,
                attack_vectors=attack_vectors,
                abuse_scenarios=abuse_scenarios,
                mitigation_strategies=mitigation_strategies,
                detection_indicators=[],  # Will be populated by other methods
                compliance_impact=compliance_impact,
                confidence_score=float(data.get("confidence_score", 0.8)),
                analysis_metadata=analysis_metadata
            )
            
            logger.info(f"Successfully converted AI response to ThreatAnalysis with {len(attack_vectors)} attack vectors")
            return threat_analysis
            
        except Exception as e:
            logger.error(f"Failed to convert AI JSON to ThreatAnalysis: {e}")
            logger.error(f"AI data keys: {list(data.keys()) if data else 'No data'}")
            return None
    
    def get_parsing_statistics(self) -> Dict[str, Any]:
        """Get response parsing statistics."""
        total = max(self.parsing_stats["total_parses"], 1)
        return {
            **self.parsing_stats,
            "success_rate": (self.parsing_stats["successful_parses"] / total) * 100,
            "fallback_rate": (self.parsing_stats["fallback_parses"] / total) * 100,
            "failure_rate": (self.parsing_stats["failed_parses"] / total) * 100
        }


@dataclass
class AnalysisRequest:
    """Request for AI analysis."""
    tool_capabilities: ToolCapabilities
    environment_context: EnvironmentContext
    analysis_type: str = "comprehensive"
    max_tokens: int = 8000
    temperature: float = 0.1


@dataclass
class AnalysisResponse:
    """Response from AI analysis."""
    content: str
    metadata: AnalysisMetadata
    parsed_analysis: Optional[ThreatAnalysis] = None
    error: Optional[str] = None


class AIProvider(ABC):
    """Abstract interface for AI providers."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the AI provider with configuration."""
        self.config = config
        self.prompt_engine = ThreatAnalysisPrompts()
        self.response_parser = ResponseParser()
        
        # Initialize advanced retry and error handling
        retry_config = RetryConfig(
            max_attempts=config.get("max_retry_attempts", 3),
            base_delay=config.get("retry_base_delay", 1.0),
            max_delay=config.get("retry_max_delay", 60.0),
            backoff_multiplier=config.get("retry_backoff_multiplier", 2.0),
            jitter=config.get("retry_jitter", True)
        )
        
        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=config.get("circuit_breaker_failure_threshold", 5),
            recovery_timeout=config.get("circuit_breaker_recovery_timeout", 30.0),
            success_threshold=config.get("circuit_breaker_success_threshold", 2)
        )
        
        self.retry_handler = AdvancedRetryHandler(retry_config, circuit_breaker_config)
        
        self.usage_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_cost": 0.0,
            "total_tokens": 0
        }
    
    @abstractmethod
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        """Generate comprehensive threat analysis."""
        pass
    
    @abstractmethod
    def assess_risk_level(self, capabilities: List[str]) -> Tuple[ThreatLevel, float]:
        """Quick risk level assessment."""
        pass
    
    @abstractmethod
    def estimate_cost(self, request: AnalysisRequest) -> float:
        """Estimate cost for analysis request."""
        pass
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get provider usage statistics."""
        stats = self.usage_stats.copy()
        
        # Include parsing statistics
        parsing_stats = self.response_parser.get_parsing_statistics()
        stats.update({f"parsing_{k}": v for k, v in parsing_stats.items()})
        
        # Include retry and health statistics
        health_stats = self.retry_handler.get_health_statistics()
        stats.update({f"health_{k}": v for k, v in health_stats.items()})
        
        return stats
    
    def _update_stats(self, success: bool, cost: float = 0.0, tokens: int = 0):
        """Update usage statistics."""
        self.usage_stats["total_requests"] += 1
        if success:
            self.usage_stats["successful_requests"] += 1
        else:
            self.usage_stats["failed_requests"] += 1
        self.usage_stats["total_cost"] += cost
        self.usage_stats["total_tokens"] += tokens
    
    def _execute_with_retry(self, 
                          operation: Callable[[], Any], 
                          provider_name: str,
                          operation_name: str = "AI operation") -> Any:
        """
        Execute operation with retry logic (synchronous version).
        
        Args:
            operation: Operation to execute
            provider_name: Name of the provider
            operation_name: Name for logging
            
        Returns:
            Operation result
            
        Raises:
            Exception: If all retry attempts fail
        """
        retry_config = self.retry_handler.retry_config
        max_attempts = retry_config.max_attempts
        last_exception = None
        
        for attempt in range(max_attempts):
            try:
                # Check circuit breaker
                if self.retry_handler.is_circuit_breaker_open(provider_name):
                    raise Exception(f"Circuit breaker open for provider {provider_name}")
                
                start_time = time.time()
                result = operation()
                response_time = time.time() - start_time
                
                # Update success metrics
                self.retry_handler.update_provider_health(
                    provider_name, 
                    success=True, 
                    response_time=response_time
                )
                
                if attempt > 0:
                    logger.info(f"{operation_name} succeeded on attempt {attempt + 1}")
                
                return result
                
            except Exception as e:
                last_exception = e
                response_time = time.time() - start_time if 'start_time' in locals() else 0.0
                
                # Classify error
                error_type = self.retry_handler.error_classifier.classify_error(str(e))
                
                # Update failure metrics
                self.retry_handler.update_provider_health(
                    provider_name,
                    success=False,
                    response_time=response_time,
                    error_type=error_type
                )
                
                # Check if we should retry
                if not self.retry_handler.should_retry(e, error_type, attempt):
                    logger.error(f"{operation_name} failed on attempt {attempt + 1}, no retry: {e}")
                    break
                
                if attempt < max_attempts - 1:
                    delay = self.retry_handler.calculate_delay(attempt)
                    logger.warning(f"{operation_name} failed on attempt {attempt + 1}, retrying in {delay:.2f}s: {e}")
                    time.sleep(delay)
        
        # All attempts failed
        logger.error(f"{operation_name} failed after {max_attempts} attempts")
        raise last_exception


class OpenAIProvider(AIProvider):
    """OpenAI GPT implementation for threat analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenAI provider."""
        super().__init__(config)
        
        # Always set model even if initialization fails
        self.model = config.get("openai_model", "gpt-4")
        
        try:
            import openai
            api_key = config.get("openai_api_key")
            logger.info(f"OpenAI provider initializing with API key: {api_key[:20] if api_key else 'None'}...")
            self.client = openai.OpenAI(
                api_key=api_key,
                timeout=config.get("openai_timeout", 60)
            )
            self.available = True
            logger.info(f"OpenAI provider successfully initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI provider: {e}")
            self.client = None
            self.available = False
    
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        """Generate threat analysis using OpenAI GPT with advanced retry logic."""
        if not self.available:
            return AnalysisResponse(
                content="",
                metadata=AnalysisMetadata(
                    provider="openai",
                    model=self.model,
                    timestamp=datetime.now(),
                    analysis_duration=0,
                    cost=0.0
                ),
                error="OpenAI provider not available"
            )
        
        start_time = time.time()
        
        # Get appropriate prompt based on analysis type
        if request.analysis_type == "comprehensive":
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities, 
                request.environment_context
            )
        elif request.analysis_type == "capability_analysis":
            prompt_data = self.prompt_engine.build_capability_analysis_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        elif request.analysis_type == "context_aware":
            prompt_data = self.prompt_engine.build_context_aware_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        else:
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        
        try:
            # Define the API call operation for retry logic
            def make_api_call():
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": prompt_data["system_prompt"]},
                        {"role": "user", "content": prompt_data["user_prompt"]}
                    ],
                    max_tokens=prompt_data.get("max_tokens", request.max_tokens),
                    temperature=prompt_data.get("temperature", request.temperature)
                )
            
            # Execute API call with retry logic
            response = self._execute_with_retry(
                operation=make_api_call,
                provider_name="openai",
                operation_name=f"OpenAI {request.analysis_type} analysis"
            )
            
            duration = time.time() - start_time
            content = response.choices[0].message.content
            
            # Calculate cost
            prompt_tokens = response.usage.prompt_tokens if response.usage else 0
            completion_tokens = response.usage.completion_tokens if response.usage else 0
            cost = self._calculate_openai_cost(prompt_tokens, completion_tokens)
            
            # Update statistics
            self._update_stats(True, cost, prompt_tokens + completion_tokens)
            
            metadata = AnalysisMetadata(
                provider="openai",
                model=self.model,
                timestamp=datetime.now(),
                analysis_duration=duration,
                cost=cost,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens
            )
            
            # Parse the response using comprehensive parser
            parsed_analysis = None
            if content:
                try:
                    parsed_analysis = self.response_parser.parse_analysis_response(
                        content=content,
                        analysis_type=request.analysis_type,
                        tool_capabilities=request.tool_capabilities,
                        environment_context=request.environment_context,
                        response_schema=prompt_data.get("response_schema")
                    )
                    if parsed_analysis:
                        logger.debug(f"OpenAI: Successfully parsed {request.analysis_type} response")
                    else:
                        logger.warning(f"OpenAI: Failed to parse {request.analysis_type} response")
                except Exception as e:
                    logger.warning(f"OpenAI response parsing error: {e}")
            
            return AnalysisResponse(
                content=content,
                metadata=metadata,
                parsed_analysis=parsed_analysis
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self._update_stats(False)
            
            logger.error(f"OpenAI analysis failed: {e}")
            return AnalysisResponse(
                content="",
                metadata=AnalysisMetadata(
                    provider="openai",
                    model=self.model,
                    timestamp=datetime.now(),
                    analysis_duration=duration,
                    cost=0.0
                ),
                error=str(e)
            )
    
    def assess_risk_level(self, capabilities: List[str]) -> Tuple[ThreatLevel, float]:
        """Quick risk assessment using OpenAI."""
        if not self.available:
            return ThreatLevel.MEDIUM, 0.5
        
        try:
            # Use quick assessment template
            prompt_data = self.prompt_engine.build_quick_assessment_prompt(
                capabilities=", ".join(capabilities),
                context="Quick assessment context"
            )
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt_data["user_prompt"]}],
                max_tokens=100,
                temperature=0.0
            )
            
            content = response.choices[0].message.content.strip()
            
            # Parse response format: RISK_LEVEL|CONFIDENCE_SCORE|KEY_CONCERN
            parts = content.split('|')
            if len(parts) >= 2:
                risk_level_str = parts[0].strip().lower()
                confidence = float(parts[1].strip())
                
                risk_level = ThreatLevel.from_string(risk_level_str)
                return risk_level, confidence
            
            return ThreatLevel.MEDIUM, 0.5
            
        except Exception as e:
            logger.error(f"OpenAI risk assessment failed: {e}")
            return ThreatLevel.MEDIUM, 0.5
    
    def estimate_cost(self, request: AnalysisRequest) -> float:
        """Estimate cost for OpenAI analysis."""
        # Rough estimation based on prompt length and model
        estimated_prompt_tokens = len(str(request.tool_capabilities)) // 4  # ~4 chars per token
        estimated_completion_tokens = 1000  # Typical response length
        
        return self._calculate_openai_cost(estimated_prompt_tokens, estimated_completion_tokens)
    
    def _calculate_openai_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate cost for OpenAI API usage."""
        if self.model.startswith("gpt-4"):
            # GPT-4 pricing
            prompt_cost = prompt_tokens * 0.00003  # $0.03 per 1K tokens
            completion_cost = completion_tokens * 0.00006  # $0.06 per 1K tokens
        else:
            # GPT-3.5 pricing
            prompt_cost = prompt_tokens * 0.0000015  # $0.0015 per 1K tokens
            completion_cost = completion_tokens * 0.000002  # $0.002 per 1K tokens
        
        return prompt_cost + completion_cost
    



class AnthropicProvider(AIProvider):
    """Anthropic Claude implementation for threat analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Anthropic provider."""
        super().__init__(config)
        
        # Always set model even if initialization fails
        model_name = config.get("anthropic_model", "claude-3-5-sonnet-latest")
        # Fix invalid model names
        if model_name in ["claude-sonnet-4-0", "claude-sonnet-4-20250514"]:
            model_name = "claude-3-5-sonnet-latest"
        self.model = model_name
        
        try:
            import anthropic
            import os
            
            # Try multiple API key sources in order of preference
            api_key = None
            
            # 1. From config (AI_ANTHROPIC_API_KEY via our settings)
            if config.get("anthropic_api_key"):
                api_key = config.get("anthropic_api_key")
                logger.info("Using Anthropic API key from config (AI_ANTHROPIC_API_KEY)")
            
            # 2. From standard environment variable (ANTHROPIC_API_KEY)
            elif os.environ.get("ANTHROPIC_API_KEY"):
                api_key = os.environ.get("ANTHROPIC_API_KEY")
                logger.info("Using Anthropic API key from ANTHROPIC_API_KEY environment variable")
            
            # 3. From our custom environment variable (AI_ANTHROPIC_API_KEY) 
            elif os.environ.get("AI_ANTHROPIC_API_KEY"):
                api_key = os.environ.get("AI_ANTHROPIC_API_KEY")
                logger.info("Using Anthropic API key from AI_ANTHROPIC_API_KEY environment variable")
            
            if not api_key:
                raise ValueError("No Anthropic API key found. Please set ANTHROPIC_API_KEY or AI_ANTHROPIC_API_KEY environment variable.")
            
            logger.info(f"Anthropic provider initializing with API key: {api_key[:20] if api_key else 'None'}...")
            logger.info(f"Using model: {self.model}")
            
            self.client = anthropic.Anthropic(
                api_key=api_key,
                timeout=config.get("anthropic_timeout", 60)
            )
            self.available = True
            logger.info(f"Anthropic provider successfully initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic provider: {e}")
            self.client = None
            self.available = False
    
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        """Generate threat analysis using Anthropic Claude."""
        if not self.available:
            return AnalysisResponse(
                content="",
                metadata=AnalysisMetadata(
                    provider="anthropic",
                    model=self.model,
                    timestamp=datetime.now(),
                    analysis_duration=0,
                    cost=0.0
                ),
                error="Anthropic provider not available"
            )
        
        start_time = time.time()
        
        # Get appropriate prompt based on analysis type
        if request.analysis_type == "comprehensive":
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities, 
                request.environment_context
            )
        elif request.analysis_type == "capability_analysis":
            prompt_data = self.prompt_engine.build_capability_analysis_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        elif request.analysis_type == "context_aware":
            prompt_data = self.prompt_engine.build_context_aware_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        else:
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        
        try:
            # Define the API call operation for retry logic
            def make_api_call():
                return self.client.messages.create(
                    model=self.model,
                    max_tokens=prompt_data.get("max_tokens", request.max_tokens),
                    temperature=prompt_data.get("temperature", request.temperature),
                    system=prompt_data["system_prompt"],
                    messages=[{"role": "user", "content": prompt_data["user_prompt"]}]
                )
            
            # Execute API call with retry logic
            response = self._execute_with_retry(
                operation=make_api_call,
                provider_name="anthropic",
                operation_name=f"Anthropic {request.analysis_type} analysis"
            )
            
            duration = time.time() - start_time
            content = response.content[0].text
            
            # Calculate cost and tokens
            input_tokens = response.usage.input_tokens if hasattr(response, 'usage') else 0
            output_tokens = response.usage.output_tokens if hasattr(response, 'usage') else 0
            cost = self._calculate_anthropic_cost(input_tokens, output_tokens)
            
            # Update statistics
            self._update_stats(True, cost, input_tokens + output_tokens)
            
            metadata = AnalysisMetadata(
                provider="anthropic",
                model=self.model,
                timestamp=datetime.now(),
                analysis_duration=duration,
                cost=cost,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens
            )
            
            # Parse the response using comprehensive parser
            parsed_analysis = None
            if content:
                try:
                    parsed_analysis = self.response_parser.parse_analysis_response(
                        content=content,
                        analysis_type=request.analysis_type,
                        tool_capabilities=request.tool_capabilities,
                        environment_context=request.environment_context,
                        response_schema=prompt_data.get("response_schema")
                    )
                    if parsed_analysis:
                        logger.debug(f"Anthropic: Successfully parsed {request.analysis_type} response")
                    else:
                        logger.warning(f"Anthropic: Failed to parse {request.analysis_type} response")
                except Exception as e:
                    logger.warning(f"Anthropic response parsing error: {e}")
            
            return AnalysisResponse(
                content=content,
                metadata=metadata,
                parsed_analysis=parsed_analysis
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self._update_stats(False)
            
            logger.error(f"Anthropic analysis failed: {e}")
            return AnalysisResponse(
                content="",
                metadata=AnalysisMetadata(
                    provider="anthropic",
                    model=self.model,
                    timestamp=datetime.now(),
                    analysis_duration=duration,
                    cost=0.0
                ),
                error=str(e)
            )
    
    def assess_risk_level(self, capabilities: List[str]) -> Tuple[ThreatLevel, float]:
        """Quick risk assessment using Anthropic."""
        if not self.available:
            return ThreatLevel.MEDIUM, 0.5
        
        try:
            # Use quick assessment template
            prompt_data = self.prompt_engine.build_quick_assessment_prompt(
                capabilities=", ".join(capabilities),
                context="Quick assessment context"
            )
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=100,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt_data["user_prompt"]}]
            )
            
            content = response.content[0].text.strip()
            
            # Parse response format: RISK_LEVEL|CONFIDENCE_SCORE|KEY_CONCERN
            parts = content.split('|')
            if len(parts) >= 2:
                risk_level_str = parts[0].strip().lower()
                confidence = float(parts[1].strip())
                
                risk_level = ThreatLevel.from_string(risk_level_str)
                return risk_level, confidence
            
            return ThreatLevel.MEDIUM, 0.5
            
        except Exception as e:
            logger.error(f"Anthropic risk assessment failed: {e}")
            return ThreatLevel.MEDIUM, 0.5
    
    def estimate_cost(self, request: AnalysisRequest) -> float:
        """Estimate cost for Anthropic analysis."""
        # Rough estimation based on prompt length and model
        estimated_input_tokens = len(str(request.tool_capabilities)) // 4
        estimated_output_tokens = 1000
        
        return self._calculate_anthropic_cost(estimated_input_tokens, estimated_output_tokens)
    
    def _calculate_anthropic_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for Anthropic API usage."""
        # Claude-3 Sonnet pricing
        input_cost = input_tokens * 0.000003  # $3 per 1M tokens
        output_cost = output_tokens * 0.000015  # $15 per 1M tokens
        
        return input_cost + output_cost
    

class LocalLLMProvider(AIProvider):
    """Local LLM implementation for air-gapped environments."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Local LLM provider."""
        super().__init__(config)
        
        self.endpoint = config.get("endpoint", "http://localhost:11434")
        self.model = config.get("model", "llama2") 
        self.timeout = config.get("timeout", 60)
        self.available = True  # Assume available, will be tested on first use
    
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        """Generate threat analysis using Local LLM."""
        start_time = time.time()
        
        # Get appropriate prompt based on analysis type
        if request.analysis_type == "comprehensive":
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities, 
                request.environment_context
            )
        elif request.analysis_type == "capability_analysis":
            prompt_data = self.prompt_engine.build_capability_analysis_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        elif request.analysis_type == "context_aware":
            prompt_data = self.prompt_engine.build_context_aware_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        else:
            prompt_data = self.prompt_engine.build_comprehensive_prompt(
                request.tool_capabilities,
                request.environment_context
            )
        
        try:
            import requests
            
            # Combine system and user prompts for local LLM
            full_prompt = f"{prompt_data['system_prompt']}\n\n{prompt_data['user_prompt']}"
            
            # Define the API call operation for retry logic
            def make_api_call():
                response = requests.post(
                    f"{self.endpoint}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": full_prompt,
                        "stream": False,
                        "options": {
                            "temperature": prompt_data.get("temperature", request.temperature),
                            "num_predict": prompt_data.get("max_tokens", request.max_tokens)
                        }
                    },
                    timeout=self.timeout
                )
                response.raise_for_status()
                return response.json()
            
            # Execute API call with retry logic
            result = self._execute_with_retry(
                operation=make_api_call,
                provider_name="local_llm",
                operation_name=f"LocalLLM {request.analysis_type} analysis"
            )
            
            duration = time.time() - start_time
            content = result.get("response", "")
            
            # Update statistics (no cost for local LLM)
            self._update_stats(True, 0.0, 0)
            
            metadata = AnalysisMetadata(
                provider="local_llm",
                model=self.model,
                timestamp=datetime.now(),
                analysis_duration=duration,
                cost=0.0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0
            )
            
            # Parse the response using comprehensive parser
            parsed_analysis = None
            if content:
                try:
                    parsed_analysis = self.response_parser.parse_analysis_response(
                        content=content,
                        analysis_type=request.analysis_type,
                        tool_capabilities=request.tool_capabilities,
                        environment_context=request.environment_context,
                        response_schema=prompt_data.get("response_schema")
                    )
                    if parsed_analysis:
                        logger.debug(f"LocalLLM: Successfully parsed {request.analysis_type} response")
                    else:
                        logger.warning(f"LocalLLM: Failed to parse {request.analysis_type} response")
                except Exception as e:
                    logger.warning(f"LocalLLM response parsing error: {e}")
            
            return AnalysisResponse(
                content=content,
                metadata=metadata,
                parsed_analysis=parsed_analysis
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self._update_stats(False)
            
            logger.error(f"Local LLM analysis failed: {e}")
            return AnalysisResponse(
                content="",
                metadata=AnalysisMetadata(
                    provider="local_llm",
                    model=self.model,
                    timestamp=datetime.now(),
                    analysis_duration=duration,
                    cost=0.0
                ),
                error=str(e)
            )
    
    def assess_risk_level(self, capabilities: List[str]) -> Tuple[ThreatLevel, float]:
        """Quick risk assessment using Local LLM."""
        try:
            import requests
            
            # Use quick assessment template
            prompt_data = self.prompt_engine.build_quick_assessment_prompt(
                capabilities=", ".join(capabilities),
                context="Quick assessment context"
            )
            
            response = requests.post(
                f"{self.endpoint}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt_data["user_prompt"],
                    "stream": False,
                    "options": {
                        "temperature": 0.0,
                        "num_predict": 100
                    }
                },
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            content = result.get("response", "").strip()
            
            # Parse response format: RISK_LEVEL|CONFIDENCE_SCORE|KEY_CONCERN
            parts = content.split('|')
            if len(parts) >= 2:
                risk_level_str = parts[0].strip().lower()
                confidence = float(parts[1].strip())
                
                risk_level = ThreatLevel.from_string(risk_level_str)
                return risk_level, confidence
            
            return ThreatLevel.MEDIUM, 0.5
            
        except Exception as e:
            logger.error(f"Local LLM risk assessment failed: {e}")
            return ThreatLevel.MEDIUM, 0.5
    
    def estimate_cost(self, request: AnalysisRequest) -> float:
        """Estimate cost for Local LLM analysis (always free)."""
        return 0.0
    
 