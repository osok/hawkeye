"""
Threat Intelligence Database with Learning Capabilities

This module provides a sophisticated threat intelligence database that learns
from threat analyses, recognizes patterns, and provides similarity matching
for enhanced threat detection and cost optimization.
"""

import logging
import json
import hashlib
import statistics
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict
import sqlite3
import threading
from pathlib import Path

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AttackChain,
    ThreatLevel, CapabilityCategory, AttackVector, AbuseScenario
)


logger = logging.getLogger(__name__)


@dataclass
class ThreatPattern:
    """Represents a learned threat pattern."""
    pattern_id: str
    pattern_name: str
    capability_signature: str
    threat_indicators: List[str]
    common_attack_vectors: List[str]
    environment_factors: List[str]
    confidence_score: float
    occurrence_count: int
    last_seen: datetime
    avg_threat_level: float
    pattern_effectiveness: float  # How often this pattern leads to accurate assessments


@dataclass
class SimilarityMatch:
    """Represents a similarity match between tools."""
    target_tool_id: str
    similar_tool_id: str
    similarity_score: float
    matching_capabilities: List[str]
    matching_categories: List[str]
    confidence_level: float
    analysis_reusability: float  # How much of the analysis can be reused


@dataclass
class LearningMetrics:
    """Metrics for learning system performance."""
    total_analyses_stored: int
    patterns_discovered: int
    similarity_matches_found: int
    cache_hit_rate: float
    pattern_accuracy_rate: float
    learning_effectiveness: float
    database_size_mb: float
    last_learning_cycle: datetime


class ThreatIntelligenceDB:
    """
    Advanced threat intelligence database with learning capabilities.
    
    This class stores threat analyses, learns from patterns, and provides
    intelligent similarity matching to optimize future analyses and reduce costs.
    """
    
    def __init__(self, db_path: Optional[str] = None, enable_learning: bool = True):
        """
        Initialize the threat intelligence database.
        
        Args:
            db_path: Path to SQLite database file
            enable_learning: Whether to enable learning capabilities
        """
        self.db_path = db_path or "threat_intelligence.db"
        self.enable_learning = enable_learning
        self.lock = threading.RLock()
        
        # Learning configuration
        self.similarity_threshold = 0.7
        self.pattern_confidence_threshold = 0.6
        self.max_patterns = 1000
        self.learning_interval_hours = 24
        
        # In-memory caches for performance
        self.analysis_cache = {}  # tool_id -> ThreatAnalysis
        self.pattern_cache = {}   # pattern_id -> ThreatPattern
        self.similarity_cache = {}  # tool_id -> List[SimilarityMatch]
        
        # Learning metrics
        self.metrics = LearningMetrics(
            total_analyses_stored=0,
            patterns_discovered=0,
            similarity_matches_found=0,
            cache_hit_rate=0.0,
            pattern_accuracy_rate=0.0,
            learning_effectiveness=0.0,
            database_size_mb=0.0,
            last_learning_cycle=datetime.now()
        )
        
        # Initialize database
        self._initialize_database()
        
        # Load existing data
        self._load_caches()
        
        logger.info(f"Threat Intelligence DB initialized with learning {'enabled' if enable_learning else 'disabled'}")
    
    def store_threat_analysis(self, 
                            tool_capabilities: ToolCapabilities,
                            threat_analysis: ThreatAnalysis,
                            analysis_metadata: Dict[str, Any] = None) -> bool:
        """
        Store a threat analysis and trigger learning if enabled.
        
        Args:
            tool_capabilities: Tool capabilities analyzed
            threat_analysis: Threat analysis results
            analysis_metadata: Additional metadata about the analysis
            
        Returns:
            True if stored successfully
        """
        try:
            with self.lock:
                # Generate tool signature
                tool_signature = self._generate_tool_signature(tool_capabilities)
                
                # Store in database
                self._store_analysis_db(tool_signature, tool_capabilities, threat_analysis, analysis_metadata)
                
                # Update in-memory cache
                self.analysis_cache[tool_signature] = threat_analysis
                
                # Update metrics
                self.metrics.total_analyses_stored += 1
                
                # Trigger learning if enabled
                if self.enable_learning:
                    self._trigger_incremental_learning(tool_capabilities, threat_analysis)
                
                logger.debug(f"Stored threat analysis for tool: {tool_capabilities.tool_name}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to store threat analysis: {e}")
            return False
    
    def retrieve_similar_analysis(self, 
                                tool_capabilities: ToolCapabilities,
                                similarity_threshold: float = None) -> Optional[Tuple[ThreatAnalysis, float]]:
        """
        Retrieve similar threat analysis for optimization.
        
        Args:
            tool_capabilities: Tool capabilities to find similarity for
            similarity_threshold: Minimum similarity score (defaults to class setting)
            
        Returns:
            Tuple of (similar_analysis, similarity_score) or None
        """
        threshold = similarity_threshold or self.similarity_threshold
        
        try:
            with self.lock:
                tool_signature = self._generate_tool_signature(tool_capabilities)
                
                # Check direct cache hit first
                if tool_signature in self.analysis_cache:
                    logger.debug(f"Direct cache hit for tool: {tool_capabilities.tool_name}")
                    return self.analysis_cache[tool_signature], 1.0
                
                # Find similar tools
                similar_matches = self.find_similar_tools(tool_capabilities, threshold)
                
                if similar_matches:
                    # Get the most similar match
                    best_match = max(similar_matches, key=lambda x: x.similarity_score)
                    
                    if best_match.similar_tool_id in self.analysis_cache:
                        similar_analysis = self.analysis_cache[best_match.similar_tool_id]
                        logger.debug(f"Similar analysis found with score: {best_match.similarity_score:.3f}")
                        return similar_analysis, best_match.similarity_score
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to retrieve similar analysis: {e}")
            return None
    
    def find_similar_tools(self, 
                         tool_capabilities: ToolCapabilities,
                         similarity_threshold: float = None) -> List[SimilarityMatch]:
        """
        Find tools similar to the given capabilities.
        
        Args:
            tool_capabilities: Tool capabilities to find similarities for
            similarity_threshold: Minimum similarity score
            
        Returns:
            List of similarity matches
        """
        threshold = similarity_threshold or self.similarity_threshold
        
        try:
            with self.lock:
                tool_signature = self._generate_tool_signature(tool_capabilities)
                
                # Check similarity cache
                if tool_signature in self.similarity_cache:
                    cached_matches = [m for m in self.similarity_cache[tool_signature] 
                                    if m.similarity_score >= threshold]
                    if cached_matches:
                        return cached_matches
                
                # Calculate similarities with all stored tools
                similar_matches = []
                
                for stored_signature, stored_analysis in self.analysis_cache.items():
                    if stored_signature != tool_signature:
                        similarity_score = self._calculate_tool_similarity(
                            tool_capabilities, 
                            stored_analysis.tool_capabilities
                        )
                        
                        if similarity_score >= threshold:
                            match = SimilarityMatch(
                                target_tool_id=tool_signature,
                                similar_tool_id=stored_signature,
                                similarity_score=similarity_score,
                                matching_capabilities=self._find_matching_capabilities(
                                    tool_capabilities, stored_analysis.tool_capabilities
                                ),
                                matching_categories=self._find_matching_categories(
                                    tool_capabilities, stored_analysis.tool_capabilities
                                ),
                                confidence_level=min(0.9, similarity_score * 1.1),
                                analysis_reusability=self._calculate_reusability_score(
                                    tool_capabilities, stored_analysis.tool_capabilities
                                )
                            )
                            similar_matches.append(match)
                
                # Cache the results
                self.similarity_cache[tool_signature] = similar_matches
                
                logger.debug(f"Found {len(similar_matches)} similar tools for {tool_capabilities.tool_name}")
                return similar_matches
                
        except Exception as e:
            logger.error(f"Failed to find similar tools: {e}")
            return []
    
    def discover_threat_patterns(self) -> List[ThreatPattern]:
        """
        Discover threat patterns from stored analyses.
        
        Returns:
            List of discovered threat patterns
        """
        if not self.enable_learning:
            return list(self.pattern_cache.values())
        
        try:
            with self.lock:
                logger.info("Starting threat pattern discovery")
                
                # Group analyses by capability signatures
                capability_groups = defaultdict(list)
                
                for tool_signature, analysis in self.analysis_cache.items():
                    cap_signature = self._generate_capability_signature(analysis.tool_capabilities)
                    capability_groups[cap_signature].append((tool_signature, analysis))
                
                # Discover patterns from groups with sufficient data
                new_patterns = []
                
                for cap_signature, analyses in capability_groups.items():
                    if len(analyses) >= 3:  # Minimum for pattern
                        pattern = self._extract_threat_pattern(cap_signature, analyses)
                        if pattern and pattern.confidence_score >= self.pattern_confidence_threshold:
                            new_patterns.append(pattern)
                
                # Update pattern cache
                for pattern in new_patterns:
                    self.pattern_cache[pattern.pattern_id] = pattern
                
                # Store patterns in database
                self._store_patterns_db(new_patterns)
                
                # Update metrics
                self.metrics.patterns_discovered = len(self.pattern_cache)
                self.metrics.last_learning_cycle = datetime.now()
                
                logger.info(f"Pattern discovery complete: {len(new_patterns)} new patterns found")
                return new_patterns
                
        except Exception as e:
            logger.error(f"Pattern discovery failed: {e}")
            return []
    
    def get_pattern_recommendations(self, 
                                  tool_capabilities: ToolCapabilities) -> List[ThreatPattern]:
        """
        Get threat pattern recommendations for given capabilities.
        
        Args:
            tool_capabilities: Tool capabilities to get recommendations for
            
        Returns:
            List of relevant threat patterns
        """
        try:
            cap_signature = self._generate_capability_signature(tool_capabilities)
            matching_patterns = []
            
            for pattern in self.pattern_cache.values():
                if self._pattern_matches_capabilities(pattern, cap_signature):
                    matching_patterns.append(pattern)
            
            # Sort by confidence and relevance
            matching_patterns.sort(key=lambda p: p.confidence_score, reverse=True)
            
            return matching_patterns[:5]  # Top 5 recommendations
            
        except Exception as e:
            logger.error(f"Failed to get pattern recommendations: {e}")
            return []
    
    def estimate_analysis_cost(self, 
                             tool_capabilities: ToolCapabilities,
                             analysis_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Estimate the cost of analyzing given tool capabilities.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            analysis_type: Type of analysis to perform
            
        Returns:
            Cost estimation details
        """
        try:
            # Check for existing similar analysis
            similar_result = self.retrieve_similar_analysis(tool_capabilities)
            
            if similar_result:
                similar_analysis, similarity_score = similar_result
                # Reduced cost due to similarity
                base_cost = 0.10  # Base cost for similar analysis
                adjustment_cost = base_cost * (1.0 - similarity_score) * 2
                total_cost = base_cost + adjustment_cost
                
                return {
                    "estimated_cost": total_cost,
                    "cost_basis": "similar_analysis",
                    "similarity_score": similarity_score,
                    "cost_savings": 0.50 - total_cost,  # Assuming $0.50 for full analysis
                    "analysis_reusability": similarity_score * 0.8
                }
            
            # Check for pattern-based estimation
            patterns = self.get_pattern_recommendations(tool_capabilities)
            if patterns:
                pattern_confidence = patterns[0].confidence_score
                estimated_cost = 0.30 * (1.0 - pattern_confidence * 0.5)
                
                return {
                    "estimated_cost": estimated_cost,
                    "cost_basis": "pattern_based",
                    "pattern_confidence": pattern_confidence,
                    "cost_savings": 0.50 - estimated_cost,
                    "pattern_count": len(patterns)
                }
            
            # Full analysis required
            return {
                "estimated_cost": 0.50,
                "cost_basis": "full_analysis",
                "cost_savings": 0.0,
                "reason": "No similar analyses or patterns found"
            }
            
        except Exception as e:
            logger.error(f"Cost estimation failed: {e}")
            return {"estimated_cost": 0.50, "error": str(e)}
    
    def update_analysis_feedback(self, 
                               tool_signature: str,
                               feedback: Dict[str, Any]) -> bool:
        """
        Update analysis with user feedback for learning improvement.
        
        Args:
            tool_signature: Tool signature for the analysis
            feedback: Feedback data
            
        Returns:
            True if updated successfully
        """
        try:
            with self.lock:
                # Store feedback in database
                self._store_feedback_db(tool_signature, feedback)
                
                # Update pattern effectiveness if applicable
                if 'accuracy_rating' in feedback:
                    self._update_pattern_effectiveness(tool_signature, feedback['accuracy_rating'])
                
                logger.debug(f"Updated feedback for tool: {tool_signature}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to update feedback: {e}")
            return False
    
    def get_learning_metrics(self) -> LearningMetrics:
        """Get current learning system metrics."""
        try:
            with self.lock:
                # Update database size
                if Path(self.db_path).exists():
                    self.metrics.database_size_mb = Path(self.db_path).stat().st_size / 1024 / 1024
                
                # Calculate cache hit rate
                total_queries = getattr(self, '_total_queries', 0)
                cache_hits = getattr(self, '_cache_hits', 0)
                self.metrics.cache_hit_rate = cache_hits / max(total_queries, 1)
                
                return self.metrics
                
        except Exception as e:
            logger.error(f"Failed to get learning metrics: {e}")
            return self.metrics
    
    def cleanup_old_data(self, retention_days: int = 90) -> int:
        """
        Clean up old data beyond retention period.
        
        Args:
            retention_days: Number of days to retain data
            
        Returns:
            Number of records cleaned up
        """
        try:
            with self.lock:
                cutoff_date = datetime.now() - timedelta(days=retention_days)
                
                # Clean up database
                cleanup_count = self._cleanup_old_data_db(cutoff_date)
                
                # Clean up in-memory caches (pattern-based cleanup)
                self._cleanup_memory_caches(cutoff_date)
                
                logger.info(f"Cleaned up {cleanup_count} old records")
                return cleanup_count
                
        except Exception as e:
            logger.error(f"Data cleanup failed: {e}")
            return 0
    
    # Private helper methods
    
    def _initialize_database(self):
        """Initialize SQLite database with required tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Threat analyses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_analyses (
                    tool_signature TEXT PRIMARY KEY,
                    tool_name TEXT,
                    capability_signature TEXT,
                    threat_analysis TEXT,
                    analysis_metadata TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            ''')
            
            # Threat patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_name TEXT,
                    capability_signature TEXT,
                    pattern_data TEXT,
                    confidence_score REAL,
                    occurrence_count INTEGER,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            ''')
            
            # Feedback table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_signature TEXT,
                    feedback_data TEXT,
                    created_at TIMESTAMP
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_capability_signature ON threat_analyses(capability_signature)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_pattern_signature ON threat_patterns(capability_signature)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON threat_analyses(created_at)')
            
            conn.commit()
            conn.close()
            
            logger.debug("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def _load_caches(self):
        """Load existing data into memory caches."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load threat analyses
            cursor.execute('SELECT tool_signature, threat_analysis FROM threat_analyses')
            for row in cursor.fetchall():
                tool_signature, analysis_json = row
                analysis_data = json.loads(analysis_json)
                # Note: This is simplified - would need proper deserialization
                self.analysis_cache[tool_signature] = analysis_data
            
            # Load threat patterns
            cursor.execute('SELECT pattern_id, pattern_data FROM threat_patterns')
            for row in cursor.fetchall():
                pattern_id, pattern_json = row
                pattern_data = json.loads(pattern_json)
                # Note: This is simplified - would need proper deserialization
                self.pattern_cache[pattern_id] = pattern_data
            
            conn.close()
            
            self.metrics.total_analyses_stored = len(self.analysis_cache)
            self.metrics.patterns_discovered = len(self.pattern_cache)
            
            logger.debug(f"Loaded {len(self.analysis_cache)} analyses and {len(self.pattern_cache)} patterns from database")
            
        except Exception as e:
            logger.error(f"Cache loading failed: {e}")
    
    def _generate_tool_signature(self, tool_capabilities: ToolCapabilities) -> str:
        """Generate unique signature for tool capabilities."""
        # Create signature from tool name and capabilities
        signature_data = {
            "tool_name": tool_capabilities.tool_name,
            "capabilities": sorted([cat.value for cat in tool_capabilities.capability_categories]),
            "function_count": len(tool_capabilities.tool_functions)
        }
        
        signature_str = json.dumps(signature_data, sort_keys=True)
        return hashlib.md5(signature_str.encode()).hexdigest()
    
    def _generate_capability_signature(self, tool_capabilities: ToolCapabilities) -> str:
        """Generate signature based on capabilities only."""
        capabilities = sorted([cat.value for cat in tool_capabilities.capability_categories])
        return hashlib.md5("|".join(capabilities).encode()).hexdigest()
    
    def _calculate_tool_similarity(self, 
                                 tool1: ToolCapabilities, 
                                 tool2: ToolCapabilities) -> float:
        """Calculate similarity score between two tools."""
        try:
            # Capability category similarity
            caps1 = set(cat.value for cat in tool1.capability_categories)
            caps2 = set(cat.value for cat in tool2.capability_categories)
            
            if not caps1 or not caps2:
                return 0.0
            
            intersection = len(caps1.intersection(caps2))
            union = len(caps1.union(caps2))
            category_similarity = intersection / union if union > 0 else 0.0
            
            # Function name similarity (basic)
            funcs1 = set(tool1.tool_functions)
            funcs2 = set(tool2.tool_functions)
            
            func_intersection = len(funcs1.intersection(funcs2))
            func_union = len(funcs1.union(funcs2))
            function_similarity = func_intersection / func_union if func_union > 0 else 0.0
            
            # Weighted similarity score
            similarity = (category_similarity * 0.7) + (function_similarity * 0.3)
            return min(1.0, similarity)
            
        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return 0.0
    
    def _find_matching_capabilities(self, 
                                  tool1: ToolCapabilities, 
                                  tool2: ToolCapabilities) -> List[str]:
        """Find matching capabilities between two tools."""
        caps1 = set(cat.value for cat in tool1.capability_categories)
        caps2 = set(cat.value for cat in tool2.capability_categories)
        return list(caps1.intersection(caps2))
    
    def _find_matching_categories(self, 
                                tool1: ToolCapabilities, 
                                tool2: ToolCapabilities) -> List[str]:
        """Find matching capability categories."""
        return self._find_matching_capabilities(tool1, tool2)  # Same as capabilities for now
    
    def _calculate_reusability_score(self, 
                                   tool1: ToolCapabilities, 
                                   tool2: ToolCapabilities) -> float:
        """Calculate how much analysis can be reused between tools."""
        similarity = self._calculate_tool_similarity(tool1, tool2)
        # Higher similarity means higher reusability
        return min(0.95, similarity * 1.2)
    
    def _trigger_incremental_learning(self, 
                                    tool_capabilities: ToolCapabilities,
                                    threat_analysis: ThreatAnalysis):
        """Trigger incremental learning from new analysis."""
        try:
            # Check if it's time for pattern discovery
            hours_since_last = (datetime.now() - self.metrics.last_learning_cycle).total_seconds() / 3600
            
            if hours_since_last >= self.learning_interval_hours:
                self.discover_threat_patterns()
            
        except Exception as e:
            logger.error(f"Incremental learning failed: {e}")
    
    def _extract_threat_pattern(self, 
                              capability_signature: str, 
                              analyses: List[Tuple[str, ThreatAnalysis]]) -> Optional[ThreatPattern]:
        """Extract threat pattern from group of similar analyses."""
        try:
            if len(analyses) < 3:
                return None
            
            # Extract common elements
            all_attack_vectors = []
            threat_levels = []
            environment_factors = []
            
            for tool_sig, analysis in analyses:
                all_attack_vectors.extend([av.name for av in analysis.attack_vectors])
                threat_levels.append(analysis.threat_level)
                # Would extract environment factors from analysis
            
            # Find common attack vectors
            vector_counts = defaultdict(int)
            for vector in all_attack_vectors:
                vector_counts[vector] += 1
            
            common_vectors = [v for v, count in vector_counts.items() 
                            if count >= len(analyses) * 0.6]  # Present in 60% of analyses
            
            # Calculate average threat level
            threat_values = [self._threat_level_to_numeric(tl) for tl in threat_levels]
            avg_threat_level = statistics.mean(threat_values)
            
            # Generate pattern
            pattern_id = hashlib.md5(f"{capability_signature}_{datetime.now().isoformat()}".encode()).hexdigest()[:8]
            
            pattern = ThreatPattern(
                pattern_id=pattern_id,
                pattern_name=f"Pattern for capability {capability_signature[:8]}",
                capability_signature=capability_signature,
                threat_indicators=common_vectors,
                common_attack_vectors=common_vectors,
                environment_factors=environment_factors,
                confidence_score=min(0.9, len(analyses) / 10.0),  # Higher confidence with more data
                occurrence_count=len(analyses),
                last_seen=datetime.now(),
                avg_threat_level=avg_threat_level,
                pattern_effectiveness=0.7  # Initial effectiveness
            )
            
            return pattern
            
        except Exception as e:
            logger.error(f"Pattern extraction failed: {e}")
            return None
    
    def _threat_level_to_numeric(self, threat_level: ThreatLevel) -> float:
        """Convert threat level to numeric value for calculations."""
        mapping = {
            ThreatLevel.MINIMAL: 0.1,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.8,
            ThreatLevel.CRITICAL: 1.0
        }
        return mapping.get(threat_level, 0.5)
    
    def _pattern_matches_capabilities(self, pattern: ThreatPattern, capability_signature: str) -> bool:
        """Check if pattern matches given capability signature."""
        return pattern.capability_signature == capability_signature
    
    def _store_analysis_db(self, tool_signature: str, tool_capabilities: ToolCapabilities,
                          threat_analysis: ThreatAnalysis, metadata: Dict[str, Any]):
        """Store analysis in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Serialize data (simplified)
            analysis_json = json.dumps(asdict(threat_analysis), default=str)
            metadata_json = json.dumps(metadata or {}, default=str)
            capability_signature = self._generate_capability_signature(tool_capabilities)
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_analyses 
                (tool_signature, tool_name, capability_signature, threat_analysis, analysis_metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                tool_signature,
                tool_capabilities.tool_name,
                capability_signature,
                analysis_json,
                metadata_json,
                datetime.now(),
                datetime.now()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Database storage failed: {e}")
            raise
    
    def _store_patterns_db(self, patterns: List[ThreatPattern]):
        """Store patterns in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for pattern in patterns:
                pattern_json = json.dumps(asdict(pattern), default=str)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_patterns
                    (pattern_id, pattern_name, capability_signature, pattern_data, confidence_score, occurrence_count, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id,
                    pattern.pattern_name,
                    pattern.capability_signature,
                    pattern_json,
                    pattern.confidence_score,
                    pattern.occurrence_count,
                    datetime.now(),
                    datetime.now()
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Pattern storage failed: {e}")
    
    def _store_feedback_db(self, tool_signature: str, feedback: Dict[str, Any]):
        """Store feedback in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            feedback_json = json.dumps(feedback, default=str)
            
            cursor.execute('''
                INSERT INTO analysis_feedback (tool_signature, feedback_data, created_at)
                VALUES (?, ?, ?)
            ''', (tool_signature, feedback_json, datetime.now()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Feedback storage failed: {e}")
    
    def _update_pattern_effectiveness(self, tool_signature: str, accuracy_rating: float):
        """Update pattern effectiveness based on feedback."""
        # Implementation would update pattern effectiveness scores
        pass
    
    def _cleanup_old_data_db(self, cutoff_date: datetime) -> int:
        """Clean up old data from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Clean old analyses
            cursor.execute('DELETE FROM threat_analyses WHERE created_at < ?', (cutoff_date,))
            analyses_cleaned = cursor.rowcount
            
            # Clean old feedback
            cursor.execute('DELETE FROM analysis_feedback WHERE created_at < ?', (cutoff_date,))
            feedback_cleaned = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return analyses_cleaned + feedback_cleaned
            
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
            return 0
    
    def _cleanup_memory_caches(self, cutoff_date: datetime):
        """Clean up old data from memory caches."""
        # Implementation would clean memory caches based on age
        pass 