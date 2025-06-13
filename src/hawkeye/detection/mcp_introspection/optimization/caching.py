"""
Advanced Result Caching with Configurable TTL

Provides intelligent caching mechanisms for MCP introspection results with
configurable TTL, cache strategies, eviction policies, and performance optimization.
"""

import time
import hashlib
import pickle
import threading
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict, defaultdict
from enum import Enum
import weakref
import logging

from ..models import MCPServerInfo, MCPTool, MCPResource, MCPCapabilities


class CacheStrategy(Enum):
    """Cache strategy options."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL_ONLY = "ttl_only"  # TTL-based only


@dataclass
class CacheConfig:
    """Configuration for result caching."""
    # Basic settings
    enabled: bool = True
    default_ttl: float = 300.0  # 5 minutes
    max_size: int = 1000
    strategy: CacheStrategy = CacheStrategy.LRU
    
    # TTL settings per data type
    server_info_ttl: float = 600.0  # 10 minutes
    tools_ttl: float = 300.0  # 5 minutes
    resources_ttl: float = 300.0  # 5 minutes
    capabilities_ttl: float = 900.0  # 15 minutes
    
    # Performance settings
    cleanup_interval: float = 60.0  # 1 minute
    enable_compression: bool = True
    enable_persistence: bool = False
    persistence_file: Optional[str] = None


@dataclass
class CacheEntry:
    """A single cache entry with metadata."""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: float = 300.0
    compressed: bool = False
    size_bytes: int = 0
    
    def __post_init__(self):
        if self.size_bytes == 0:
            self.size_bytes = self._calculate_size()
    
    def _calculate_size(self) -> int:
        """Calculate the approximate size of the cached value."""
        try:
            return len(pickle.dumps(self.value))
        except Exception:
            return len(str(self.value).encode('utf-8'))
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.created_at > self.ttl
    
    def touch(self) -> None:
        """Update access time and count."""
        self.last_accessed = time.time()
        self.access_count += 1


@dataclass
class CacheStatistics:
    """Cache performance statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expired_entries: int = 0
    total_size_bytes: int = 0
    average_access_time: float = 0.0
    cache_efficiency: float = 0.0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


class CacheKeyGenerator:
    """Generates consistent cache keys for different data types."""
    
    @staticmethod
    def generate_key(prefix: str, *args, **kwargs) -> str:
        """Generate a cache key from arguments."""
        # Create a consistent string representation
        key_parts = [prefix]
        
        # Add positional arguments
        for arg in args:
            if hasattr(arg, '__dict__'):
                key_parts.append(str(sorted(arg.__dict__.items())))
            else:
                key_parts.append(str(arg))
        
        # Add keyword arguments
        if kwargs:
            key_parts.append(str(sorted(kwargs.items())))
        
        # Create hash for consistent key length
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode('utf-8')).hexdigest()
    
    @staticmethod
    def server_info_key(server_config: Dict[str, Any]) -> str:
        """Generate cache key for server info."""
        return CacheKeyGenerator.generate_key("server_info", server_config)
    
    @staticmethod
    def tools_key(server_config: Dict[str, Any]) -> str:
        """Generate cache key for tools."""
        return CacheKeyGenerator.generate_key("tools", server_config)


class ResultCache:
    """
    Advanced result cache with configurable TTL and strategies.
    
    Provides intelligent caching for MCP introspection results with
    multiple eviction strategies, TTL management, and performance optimization.
    """
    
    def __init__(self, config: Optional[CacheConfig] = None):
        """Initialize the result cache."""
        self.config = config or CacheConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Cache storage
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: OrderedDict = OrderedDict()  # For LRU
        self._access_frequency: defaultdict = defaultdict(int)  # For LFU
        self._insertion_order: List[str] = []  # For FIFO
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self._stats = CacheStatistics()
        
        # Background cleanup
        self._cleanup_thread: Optional[threading.Thread] = None
        self._shutdown = False
        
        # Key generator
        self._key_gen = CacheKeyGenerator()
        
        if self.config.enabled:
            self._start_cleanup_thread()
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        if not self.config.enabled:
            return None
        
        start_time = time.time()
        
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats.misses += 1
                return None
            
            if entry.is_expired():
                self._remove_entry(key)
                self._stats.misses += 1
                self._stats.expired_entries += 1
                return None
            
            # Update access information
            entry.touch()
            self._update_access_tracking(key)
            
            self._stats.hits += 1
            
            # Update average access time
            access_time = time.time() - start_time
            self._update_average_access_time(access_time)
            
            return entry.value
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Put a value into the cache."""
        if not self.config.enabled:
            return
        
        if ttl is None:
            ttl = self.config.default_ttl
        
        with self._lock:
            # Check if we need to evict entries
            if len(self._cache) >= self.config.max_size and key not in self._cache:
                self._evict_entry()
            
            # Create cache entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                ttl=ttl
            )
            
            # Store entry
            self._cache[key] = entry
            self._update_access_tracking(key)
            
            # Update statistics
            self._stats.total_size_bytes += entry.size_bytes
    
    def get_server_info(self, server_config: Dict[str, Any]) -> Optional[MCPServerInfo]:
        """Get cached server info."""
        key = self._key_gen.server_info_key(server_config)
        return self.get(key)
    
    def put_server_info(self, server_config: Dict[str, Any], server_info: MCPServerInfo) -> None:
        """Cache server info."""
        key = self._key_gen.server_info_key(server_config)
        self.put(key, server_info, self.config.server_info_ttl)
    
    def get_tools(self, server_config: Dict[str, Any]) -> Optional[List[MCPTool]]:
        """Get cached tools."""
        key = self._key_gen.tools_key(server_config)
        return self.get(key)
    
    def put_tools(self, server_config: Dict[str, Any], tools: List[MCPTool]) -> None:
        """Cache tools."""
        key = self._key_gen.tools_key(server_config)
        self.put(key, tools, self.config.tools_ttl)
    
    def get_statistics(self) -> CacheStatistics:
        """Get cache statistics."""
        with self._lock:
            # Update cache efficiency
            self._stats.cache_efficiency = self._calculate_cache_efficiency()
            return self._stats
    
    def _update_access_tracking(self, key: str) -> None:
        """Update access tracking for different strategies."""
        if self.config.strategy == CacheStrategy.LRU:
            # Move to end for LRU
            self._access_order.pop(key, None)
            self._access_order[key] = True
        elif self.config.strategy == CacheStrategy.LFU:
            # Increment frequency for LFU
            self._access_frequency[key] += 1
        elif self.config.strategy == CacheStrategy.FIFO:
            # Add to insertion order if new
            if key not in self._insertion_order:
                self._insertion_order.append(key)
    
    def _evict_entry(self) -> None:
        """Evict an entry based on the configured strategy."""
        if not self._cache:
            return
        
        key_to_evict = None
        
        if self.config.strategy == CacheStrategy.LRU:
            # Remove least recently used
            key_to_evict = next(iter(self._access_order))
        elif self.config.strategy == CacheStrategy.LFU:
            # Remove least frequently used
            key_to_evict = min(self._access_frequency.keys(), 
                             key=lambda k: self._access_frequency[k])
        elif self.config.strategy == CacheStrategy.FIFO:
            # Remove first inserted
            if self._insertion_order:
                key_to_evict = self._insertion_order[0]
        elif self.config.strategy == CacheStrategy.TTL_ONLY:
            # Remove oldest entry
            key_to_evict = min(self._cache.keys(), 
                             key=lambda k: self._cache[k].created_at)
        
        if key_to_evict and key_to_evict in self._cache:
            self._remove_entry(key_to_evict)
            self._stats.evictions += 1
    
    def _remove_entry(self, key: str) -> None:
        """Remove an entry and update tracking."""
        if key in self._cache:
            entry = self._cache[key]
            self._stats.total_size_bytes -= entry.size_bytes
            del self._cache[key]
        
        # Clean up tracking structures
        self._access_order.pop(key, None)
        self._access_frequency.pop(key, None)
        if key in self._insertion_order:
            self._insertion_order.remove(key)
    
    def _cleanup_expired_entries(self) -> None:
        """Clean up expired cache entries."""
        current_time = time.time()
        expired_keys = []
        
        with self._lock:
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_entry(key)
                self._stats.expired_entries += 1
        
        if expired_keys:
            self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _start_cleanup_thread(self) -> None:
        """Start the background cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        def cleanup_loop():
            while not self._shutdown:
                try:
                    time.sleep(self.config.cleanup_interval)
                    if not self._shutdown:
                        self._cleanup_expired_entries()
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def _update_average_access_time(self, access_time: float) -> None:
        """Update average access time statistic."""
        if self._stats.hits == 1:
            self._stats.average_access_time = access_time
        else:
            # Exponential moving average
            alpha = 0.1
            self._stats.average_access_time = (
                alpha * access_time + 
                (1 - alpha) * self._stats.average_access_time
            )
    
    def _calculate_cache_efficiency(self) -> float:
        """Calculate overall cache efficiency."""
        if not self._cache:
            return 0.0
        
        # Combine hit rate, memory efficiency, and access patterns
        hit_rate = self.hit_rate
        memory_efficiency = min(1.0, self.config.max_size / len(self._cache))
        
        return (hit_rate * 0.7 + memory_efficiency * 0.3)
    
    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        return self._stats.hit_rate
    
    @property
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)
    
    @property
    def memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        return self._stats.total_size_bytes
