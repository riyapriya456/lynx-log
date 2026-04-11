"""
Lynx VAPT - Modular Plugin Architecture

Features:
- Plugin discovery in scanners/
- Plugin interface definition
- Hot-reload capability
- Plugin lifecycle management

Author: Lynx Team
"""

import asyncio
import importlib
import importlib.util
import inspect
import os
import sys
import ast
import hashlib
import time
import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, Callable, Set
from enum import Enum


class PluginStatus(Enum):
    """Plugin lifecycle status."""
    DISCOVERED = "discovered"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class PluginInfo:
    """Information about a plugin."""
    name: str
    version: str
    author: str
    description: str
    category: str
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginState:
    """Runtime state of a plugin."""
    info: PluginInfo
    status: PluginStatus
    module_path: str
    module_hash: str
    loaded_at: float
    instance: Optional[Any] = None
    error: Optional[str] = None


class PluginInterface(ABC):
    """
    Base interface for all Lynx plugins.
    
    All plugins must inherit from this class and implement
    the required methods.
    """
    
    # Plugin metadata - override in subclasses
    PLUGIN_INFO = PluginInfo(
        name="BasePlugin",
        version="1.0.0",
        author="Unknown",
        description="Base plugin interface",
        category="general"
    )
    
    def __init__(self, context: Any = None):
        self.context = context
        self._is_initialized = False
        self._is_running = False
    
    @classmethod
    def get_info(cls) -> PluginInfo:
        """Get plugin information."""
        return cls.PLUGIN_INFO
    
    async def initialize(self, config: Dict[str, Any] = None):
        """
        Initialize the plugin.
        
        Called once when the plugin is first loaded.
        Override to set up resources, connections, etc.
        """
        self._is_initialized = True
    
    @abstractmethod
    async def run(self, *args, **kwargs) -> Any:
        """
        Run the plugin's main logic.
        
        Must be implemented by all plugins.
        """
        pass
    
    async def cleanup(self):
        """
        Cleanup plugin resources.
        
        Called when the plugin is being unloaded or the scan ends.
        Override to close connections, free resources, etc.
        """
        self._is_running = False
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate plugin configuration.
        
        Returns True if config is valid.
        Override to add custom validation.
        """
        return True
    
    @property
    def is_initialized(self) -> bool:
        return self._is_initialized
    
    @property
    def is_running(self) -> bool:
        return self._is_running


class ScannerPlugin(PluginInterface):
    """
    Base class for scanner plugins.
    
    Extends PluginInterface with scanner-specific functionality.
    """
    
    PLUGIN_INFO = PluginInfo(
        name="ScannerPlugin",
        version="1.0.0",
        author="Unknown",
        description="Base scanner plugin",
        category="scanner"
    )
    
    async def emit_vulnerability(self, *args, **kwargs):
        """Emit a vulnerability finding."""
        # Will be connected to the main scan context
        pass


class PluginSecurityError(Exception):
    """Raised when plugin security checks fail."""
    pass


class PluginSecurityScanner:
    """
    Security scanner for plugin files.
    Detects malicious code patterns and validates plugin safety.
    """
    
    # Dangerous operations that should be flagged
    DANGEROUS_PATTERNS = {
        'os': ['system', 'popen', 'execve', 'spawn', 'kill', 'remove', 'rmdir'],
        'subprocess': ['Popen', 'call', 'run', 'check_call', 'check_output'],
        'sys': ['exit', '_exit', 'exec', 'settrace'],
        'builtins': ['eval', 'exec', 'compile', '__import__', 'open'],
        'file_operations': ['open', 'write', 'delete', 'remove', 'unlink'],
        'network': ['socket', 'connect', 'bind', 'listen', 'accept'],
    }
    
    # Allowed imports for plugins
    ALLOWED_IMPORTS = {
        'asyncio', 'json', 're', 'hashlib', 'hmac', 'base64', 'time',
        'typing', 'dataclasses', 'abc', 'pathlib', 'collections',
        'urllib', 'datetime', 'itertools', 'functools', 'operator',
        'scanners', 'common', 'cache', 'logger'
    }
    
    # Whitelisted plugin files (pre-approved)
    PLUGIN_WHITELIST = set()
    
    def __init__(self):
        self.security_violations: List[Dict[str, Any]] = []
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def _scan_ast(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse and scan Python AST for security issues.
        
        Returns list of violations.
        """
        violations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse AST
            tree = ast.parse(content)
            
            # Check for dangerous imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name.split('.')[0]
                        if module_name not in self.ALLOWED_IMPORTS:
                            violations.append({
                                'type': 'UNAUTHORIZED_IMPORT',
                                'module': module_name,
                                'line': node.lineno,
                                'severity': 'HIGH'
                            })
                
                elif isinstance(node, ast.ImportFrom):
                    module_name = node.module.split('.')[0] if node.module else ""
                    if module_name not in self.ALLOWED_IMPORTS:
                        violations.append({
                            'type': 'UNAUTHORIZED_IMPORT',
                            'module': module_name,
                            'line': node.lineno,
                            'severity': 'HIGH'
                        })
                
                # Check for dangerous function calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                        value = node.func.value
                        
                        # Check os.system, subprocess calls
                        if isinstance(value, ast.Name):
                            module_name = value.id
                            if module_name in self.DANGEROUS_PATTERNS:
                                if func_name in self.DANGEROUS_PATTERNS[module_name]:
                                    violations.append({
                                        'type': 'DANGEROUS_CALL',
                                        'call': f"{module_name}.{func_name}",
                                        'line': node.lineno,
                                        'severity': 'CRITICAL'
                                    })
                    
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ['eval', 'exec', 'compile']:
                            violations.append({
                                'type': 'DANGEROUS_BUILTIN',
                                'call': func_name,
                                'line': node.lineno,
                                'severity': 'CRITICAL'
                            })
                
                # Check for dangerous string operations (potential code injection)
                elif isinstance(node, ast.Str) or isinstance(node, ast.Constant):
                    if isinstance(node.value, str):
                        # Check for common injection patterns
                        dangerous_patterns = [
                            'import os', 'import subprocess', 'eval(', 'exec(',
                            'system(', 'popen(', 'bash -c', 'cmd /c',
                            'base64.b64decode', 'compile('
                        ]
                        for pattern in dangerous_patterns:
                            if pattern in node.value.lower():
                                violations.append({
                                    'type': 'SUSPICIOUS_STRING',
                                    'pattern': pattern,
                                    'line': node.lineno,
                                    'severity': 'MEDIUM'
                                })
                
                # Check for dynamic code execution
                elif isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id in ['getattr', 'setattr', 'delattr']:
                        violations.append({
                            'type': 'DYNAMIC_ACCESS',
                            'call': node.func.id,
                            'line': node.lineno,
                            'severity': 'MEDIUM'
                        })
        
        except SyntaxError as e:
            violations.append({
                'type': 'SYNTAX_ERROR',
                'error': str(e),
                'severity': 'HIGH'
            })
        except Exception as e:
            violations.append({
                'type': 'PARSE_ERROR',
                'error': str(e),
                'severity': 'MEDIUM'
            })
        
        return violations
    
    def _check_file_operations(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check for dangerous file operations."""
        violations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for path traversal patterns
            dangerous_patterns = [
                '../', '..\\', '/etc/passwd', '/bin/sh', 'C:\\Windows',
                'os.remove', 'os.rmdir', 'shutil.rmtree',
                'open(', 'write(', 'delete', 'unlink'
            ]
            
            for pattern in dangerous_patterns:
                if pattern in content:
                    violations.append({
                        'type': 'DANGEROUS_FILE_OP',
                        'pattern': pattern,
                        'severity': 'HIGH'
                    })
                    break  # One violation per file is enough
        
        except Exception:
            pass
        
        return violations
    
    def _check_network_operations(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check for suspicious network operations."""
        violations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for socket operations
            if 'socket.socket' in content:
                violations.append({
                    'type': 'RAW_SOCKET_USAGE',
                    'pattern': 'socket.socket',
                    'severity': 'MEDIUM'
                })
            
            # Check for external connections
            if 'requests.' in content or 'urllib.request' in content:
                violations.append({
                    'type': 'EXTERNAL_REQUESTS',
                    'pattern': 'HTTP requests to external services',
                    'severity': 'MEDIUM'
                })
        
        except Exception:
            pass
        
        return violations
    
    def scan_plugin(self, file_path: Path) -> tuple[bool, List[Dict[str, Any]]]:
        """
        Scan a plugin file for security issues.
        
        Returns: (is_safe, violations)
        """
        violations = []
        
        # Check whitelist first
        file_hash = self._calculate_file_hash(file_path)
        if file_hash in self.PLUGIN_WHITELIST:
            return True, []
        
        # AST-based security scan
        violations.extend(self._scan_ast(file_path))
        
        # File operation checks
        violations.extend(self._check_file_operations(file_path))
        
        # Network operation checks
        violations.extend(self._check_network_operations(file_path))
        
        # Determine if safe (allow medium violations, flag high/critical)
        critical_or_high = [v for v in violations if v.get('severity', '') in ['CRITICAL', 'HIGH']]
        
        return len(critical_or_high) == 0, violations
    
    def add_to_whitelist(self, file_path: Path):
        """Add a plugin to the whitelist."""
        file_hash = self._calculate_file_hash(file_path)
        if file_hash:
            self.PLUGIN_WHITELIST.add(file_hash)


class PluginManager:
    """
    Manages plugin discovery, loading, and lifecycle with security features.
    """
    
    def __init__(self, plugin_dirs: List[str] = None):
        self.plugin_dirs = plugin_dirs or ['scanners', 'plugins']
        self.plugins: Dict[str, PluginState] = {}
        self._watchers: Dict[str, float] = {}  # For hot reload
        self._running = False
        self.security_scanner = PluginSecurityScanner()
        self.security_enabled = True  # Can be disabled for trusted environments
    
    def discover(self) -> List[PluginInfo]:
        """
        Discover all available plugins.
        
        Scans plugin directories for Python files that implement
        the PluginInterface.
        """
        discovered = []
        
        for plugin_dir in self.plugin_dirs:
            dir_path = Path(plugin_dir)
            
            if not dir_path.exists():
                continue
            
            for file_path in dir_path.glob("*.py"):
                if file_path.name.startswith('_'):
                    continue
                
                try:
                    info = self._probe_plugin(file_path)
                    if info:
                        discovered.append(info)
                        
                        # Track for hot reload
                        self._watchers[str(file_path)] = file_path.stat().st_mtime
                        
                except Exception as e:
                    print(f"Error probing {file_path}: {e}")
        
        return discovered
    
    def _probe_plugin(self, file_path: Path) -> Optional[PluginInfo]:
        """
        Probe a file to check if it's a valid plugin.
        """
        try:
            spec = importlib.util.spec_from_file_location(
                file_path.stem, file_path
            )
            if spec is None or spec.loader is None:
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, PluginInterface) and 
                    obj not in (PluginInterface, ScannerPlugin)):
                    return obj.get_info()
            
            return None
            
        except Exception:
            return None
    
    def load(self, plugin_name: str) -> bool:
        """
        Load a plugin by name.
        """
        # Find the plugin file
        for plugin_dir in self.plugin_dirs:
            dir_path = Path(plugin_dir)
            
            for file_path in dir_path.glob("*.py"):
                if file_path.stem == plugin_name:
                    return self._load_from_file(file_path)
        
        return False
    
    def _load_from_file(self, file_path: Path) -> bool:
        """
        Load a plugin from a specific file with security validation.
        """
        try:
            # Security scan before loading
            if self.security_enabled:
                is_safe, violations = self.security_scanner.scan_plugin(file_path)
                
                if not is_safe:
                    critical_violations = [v for v in violations if v.get('severity', '') in ['CRITICAL', 'HIGH']]
                    
                    print(f"\n[SECURITY] Plugin rejected: {file_path.name}")
                    print(f"Reason: {len(critical_violations)} critical security issues found")
                    
                    for v in critical_violations:
                        print(f"  - {v.get('type', 'Unknown')}: {v.get('pattern', v.get('module', 'unknown'))} (line {v.get('line', 'N/A')})")
                    
                    print(f"\nPlugin will not be loaded due to security concerns.")
                    print(f"To override, add hash to whitelist or disable security checks.\n")
                    
                    return False
                
                # Log warnings for medium severity
                medium_violations = [v for v in violations if v.get('severity', '') == 'MEDIUM']
                if medium_violations:
                    from common import debug_log
                    debug_log(f"[PLUGIN_SECURITY] Medium violations in {file_path.name}: {medium_violations}")
            
            # Calculate file hash for change detection
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            # Load module with restricted globals
            spec = importlib.util.spec_from_file_location(
                file_path.stem, file_path
            )
            if spec is None or spec.loader is None:
                return False
            
            module = importlib.util.module_from_spec(spec)
            
            # Restrict module globals for security
            module.__dict__.update({
                '__builtins__': {
                    # Only safe builtins
                    'len': len, 'str': str, 'int': int, 'float': float,
                    'list': list, 'dict': dict, 'tuple': tuple, 'set': set,
                    'bool': bool, 'type': type, 'isinstance': isinstance,
                    'range': range, 'enumerate': enumerate, 'zip': zip,
                    'map': map, 'filter': filter, 'sum': sum, 'max': max, 'min': min,
                    'abs': abs, 'round': round, 'repr': repr, 'print': print,
                    'Exception': Exception, 'ValueError': ValueError,
                    'TypeError': TypeError, 'KeyError': KeyError,
                    'IndexError': IndexError, 'AttributeError': AttributeError,
                }
            })
            
            sys.modules[file_path.stem] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, PluginInterface) and 
                    obj not in (PluginInterface, ScannerPlugin)):
                    plugin_class = obj
                    break
            
            if plugin_class is None:
                return False
            
            info = plugin_class.get_info()
            
            # Additional runtime safety check
            if not self._validate_plugin_class(plugin_class):
                print(f"[SECURITY] Plugin {info.name} failed runtime validation")
                return False
            
            self.plugins[info.name] = PluginState(
                info=info,
                status=PluginStatus.LOADED,
                module_path=str(file_path),
                module_hash=file_hash,
                loaded_at=time.time(),
                instance=None
            )
            
            return True
            
        except Exception as e:
            print(f"Error loading plugin from {file_path}: {e}")
            if self.security_enabled:
                import traceback
                traceback.print_exc()
            return False
    
    def _validate_plugin_class(self, plugin_class) -> bool:
        """
        Additional runtime validation of plugin class.
        
        Checks for dangerous attributes or methods.
        """
        try:
            # Check class attributes
            dangerous_attrs = ['__subclasses__', '__bases__', '__mro__']
            for attr in dangerous_attrs:
                if hasattr(plugin_class, attr):
                    # Allow these for normal class operations
                    pass
            
            # Check for suspicious class-level code execution
            if hasattr(plugin_class, '__init__'):
                init_source = inspect.getsource(plugin_class.__init__)
                if 'eval(' in init_source or 'exec(' in init_source:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def load_all(self) -> int:
        """
        Load all discovered plugins.
        
        Returns the number of successfully loaded plugins.
        """
        loaded = 0
        
        for plugin_dir in self.plugin_dirs:
            dir_path = Path(plugin_dir)
            
            if not dir_path.exists():
                continue
            
            for file_path in dir_path.glob("*.py"):
                if file_path.name.startswith('_'):
                    continue
                
                if self._load_from_file(file_path):
                    loaded += 1
        
        return loaded
    
    async def initialize(self, plugin_name: str, config: Dict = None) -> bool:
        """
        Initialize a loaded plugin.
        """
        if plugin_name not in self.plugins:
            return False
        
        state = self.plugins[plugin_name]
        
        if state.status != PluginStatus.LOADED:
            return False
        
        try:
            # Get the plugin class again
            spec = importlib.util.spec_from_file_location(
                Path(state.module_path).stem,
                state.module_path
            )
            if spec is None or spec.loader is None:
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find and instantiate plugin class
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, PluginInterface) and 
                    obj not in (PluginInterface, ScannerPlugin)):
                    instance = obj()
                    
                    if config and not instance.validate_config(config):
                        return False
                    
                    await instance.initialize(config)
                    
                    state.instance = instance
                    state.status = PluginStatus.INITIALIZED
                    return True
            
            return False
            
        except Exception as e:
            state.status = PluginStatus.ERROR
            state.error = str(e)
            return False
    
    async def run(self, plugin_name: str, *args, **kwargs) -> Any:
        """
        Run a plugin.
        """
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin {plugin_name} not found")
        
        state = self.plugins[plugin_name]
        
        if state.instance is None:
            raise ValueError(f"Plugin {plugin_name} not initialized")
        
        state.status = PluginStatus.RUNNING
        
        try:
            result = await state.instance.run(*args, **kwargs)
            state.status = PluginStatus.STOPPED
            return result
        except Exception as e:
            state.status = PluginStatus.ERROR
            state.error = str(e)
            raise
    
    async def cleanup(self, plugin_name: str):
        """
        Cleanup a plugin.
        """
        if plugin_name not in self.plugins:
            return
        
        state = self.plugins[plugin_name]
        
        if state.instance:
            await state.instance.cleanup()
            state.instance = None
        
        state.status = PluginStatus.STOPPED
    
    async def cleanup_all(self):
        """
        Cleanup all plugins.
        """
        for name in list(self.plugins.keys()):
            await self.cleanup(name)
    
    def unload(self, plugin_name: str):
        """
        Unload a plugin.
        """
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
    
    def check_for_updates(self) -> List[str]:
        """
        Check for plugin file changes (for hot reload).
        
        Returns list of plugin names that have been modified.
        """
        updated = []
        
        for file_path_str, last_mtime in list(self._watchers.items()):
            file_path = Path(file_path_str)
            
            if not file_path.exists():
                continue
            
            current_mtime = file_path.stat().st_mtime
            
            if current_mtime > last_mtime:
                self._watchers[file_path_str] = current_mtime
                
                # Find the plugin name for this file
                for name, state in self.plugins.items():
                    if state.module_path == file_path_str:
                        updated.append(name)
                        break
        
        return updated
    
    async def hot_reload(self, plugin_name: str) -> bool:
        """
        Hot reload a plugin.
        
        Unloads the current version and loads the new one.
        """
        if plugin_name not in self.plugins:
            return False
        
        state = self.plugins[plugin_name]
        module_path = state.module_path
        
        # Cleanup existing instance
        await self.cleanup(plugin_name)
        
        # Unload
        self.unload(plugin_name)
        
        # Reload
        return self._load_from_file(Path(module_path))
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get info for a specific plugin."""
        if plugin_name in self.plugins:
            return self.plugins[plugin_name].info
        return None
    
    def get_all_plugins(self) -> List[PluginInfo]:
        """Get info for all loaded plugins."""
        return [state.info for state in self.plugins.values()]
    
    def get_plugins_by_category(self, category: str) -> List[PluginInfo]:
        """Get plugins by category."""
        return [
            state.info for state in self.plugins.values()
            if state.info.category == category
        ]


# Global plugin manager
_plugin_manager: Optional[PluginManager] = None


def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
