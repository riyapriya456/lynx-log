"""
Lynx VAPT - Structured Logging System

Features:
- JSON structured logging
- Severity categories
- Async log writers
- Log rotation
- Contextual logging

Author: Lynx Team
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import queue
import threading


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    VULN = 35  # Custom level for vulnerabilities


class LogCategory(Enum):
    """Log categories for filtering."""
    SCANNER = "scanner"
    HTTP = "http"
    CRAWLER = "crawler"
    VULN = "vulnerability"
    SYSTEM = "system"
    ERROR = "error"
    PERFORMANCE = "performance"


@dataclass
class LogEntry:
    """A structured log entry."""
    timestamp: str
    level: str
    category: str
    message: str
    scanner: Optional[str] = None
    url: Optional[str] = None
    duration_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        data = {k: v for k, v in asdict(self).items() if v is not None}
        return json.dumps(data)
    
    def to_text(self) -> str:
        """Convert to human-readable text."""
        parts = [f"[{self.timestamp}]", f"[{self.level}]"]
        
        if self.category:
            parts.append(f"[{self.category}]")
        if self.scanner:
            parts.append(f"[{self.scanner}]")
        
        parts.append(self.message)
        
        if self.url:
            parts.append(f"URL: {self.url}")
        if self.duration_ms:
            parts.append(f"({self.duration_ms:.2f}ms)")
        
        return " ".join(parts)


class AsyncLogWriter:
    """
    Async log writer that writes logs without blocking.
    
    Uses a background thread for file I/O with proper synchronization,
    backpressure handling, and dropped log notifications.
    """
    
    def __init__(self, log_path: str, max_queue_size: int = 10000):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread-safe queue with proper synchronization
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._file = None
        
        # Statistics and monitoring
        self.dropped_logs = 0
        self.total_queued = 0
        self.total_written = 0
        self.backpressure_events = 0
        self._lock = threading.Lock()
        
        # Backpressure threshold (queue at 80% capacity)
        self.backpressure_threshold = int(max_queue_size * 0.8)
        
        # Dropped log cache (keep last 10 for debugging)
        self._dropped_cache: queue.Queue = queue.Queue(maxsize=10)
    
    def start(self):
        """Start the background writer thread."""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(
            target=self._write_loop,
            daemon=True,
            name="LogWriterThread"
        )
        self._thread.start()
    
    def stop(self):
        """Stop the writer and flush remaining logs."""
        self._running = False
        
        # Wait for thread to finish with timeout
        if self._thread:
            self._thread.join(timeout=10)
        
        # Flush any remaining items
        remaining = self._queue.qsize()
        if remaining > 0:
            print(f"[Logger] Flushing {remaining} remaining log entries...", file=sys.stderr)
            self._flush_remaining()
        
        if self._file:
            self._file.close()
        
        # Print final stats
        self._print_stats()
    
    def _flush_remaining(self):
        """Flush remaining logs in the queue."""
        try:
            while not self._queue.empty():
                entry = self._queue.get_nowait()
                if self._file:
                    self._file.write(entry.to_json() + '\n')
                    self._file.flush()
                    self.total_written += 1
        except queue.Empty:
            pass
    
    def _print_stats(self):
        """Print final statistics."""
        if self.total_queued > 0:
            drop_rate = (self.dropped_logs / self.total_queued) * 100
            print(f"\n[Logger] Final Statistics:", file=sys.stderr)
            print(f"  Total queued: {self.total_queued}", file=sys.stderr)
            print(f"  Total written: {self.total_written}", file=sys.stderr)
            print(f"  Dropped: {self.dropped_logs} ({drop_rate:.2f}%)", file=sys.stderr)
            print(f"  Backpressure events: {self.backpressure_events}", file=sys.stderr)
    
    def write(self, entry: LogEntry):
        """
        Queue a log entry for writing with backpressure handling.
        
        Returns: True if queued, False if dropped
        """
        with self._lock:
            self.total_queued += 1
            
            # Check queue size for backpressure
            current_size = self._queue.qsize()
            if current_size >= self.backpressure_threshold:
                self.backpressure_events += 1
                
                # Try to drop oldest to make room
                try:
                    dropped = self._queue.get_nowait()
                    self.dropped_logs += 1
                    
                    # Cache dropped entry for debugging
                    try:
                        self._dropped_cache.put_nowait(dropped)
                    except queue.Full:
                        pass
                    
                    # Log the drop (to stderr since logger might be the issue)
                    print(f"[Logger] Backpressure: dropped oldest log to make room", file=sys.stderr)
                except queue.Empty:
                    pass
            
            try:
                self._queue.put_nowait(entry)
                return True
            except queue.Full:
                # Queue is full, drop this log
                self.dropped_logs += 1
                
                # Cache for debugging
                try:
                    self._dropped_cache.put_nowait(entry)
                except queue.Full:
                    pass
                
                print(f"[Logger] Queue full: dropped log entry", file=sys.stderr)
                return False
    
    def _write_loop(self):
        """Background loop that writes logs to file with rotation check."""
        try:
            self._file = open(self.log_path, 'a', encoding='utf-8')
            
            consecutive_errors = 0
            max_consecutive_errors = 5
            
            while self._running or not self._queue.empty():
                try:
                    # Use timeout to allow periodic checks
                    entry = self._queue.get(timeout=0.5)
                    
                    # Write with error handling
                    try:
                        line = entry.to_json() + '\n'
                        self._file.write(line)
                        self._file.flush()
                        self.total_written += 1
                        consecutive_errors = 0
                        
                    except (IOError, OSError) as e:
                        consecutive_errors += 1
                        print(f"[Logger] Write error {consecutive_errors}/{max_consecutive_errors}: {e}", file=sys.stderr)
                        
                        if consecutive_errors >= max_consecutive_errors:
                            print(f"[Logger] Too many write errors, stopping logger", file=sys.stderr)
                            self._running = False
                            break
                        
                        # Try to reopen file
                        try:
                            if self._file:
                                self._file.close()
                            self._file = open(self.log_path, 'a', encoding='utf-8')
                        except Exception:
                            pass
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"[Logger] Unexpected error in write loop: {e}", file=sys.stderr)
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    
        except Exception as e:
            print(f"[Logger] Fatal error in write loop: {e}", file=sys.stderr)
        finally:
            if self._file:
                try:
                    self._file.close()
                except Exception:
                    pass


class RotatingLogWriter(AsyncLogWriter):
    """
    Log writer with rotation support and thread safety.
    
    Rotates logs when they exceed max_size_mb, with proper synchronization.
    """
    
    def __init__(
        self,
        log_path: str,
        max_size_mb: float = 10,
        max_files: int = 5
    ):
        super().__init__(log_path)
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)
        self.max_files = max_files
        self._current_size = 0
        self._rotation_lock = threading.Lock()
        self.rotation_count = 0
    
    def _write_loop(self):
        """Background loop with rotation and thread safety."""
        try:
            self._open_file()
            
            consecutive_errors = 0
            max_consecutive_errors = 5
            
            while self._running or not self._queue.empty():
                try:
                    entry = self._queue.get(timeout=0.5)
                    line = entry.to_json() + '\n'
                    
                    # Check rotation with lock
                    with self._rotation_lock:
                        if self._current_size + len(line.encode('utf-8')) >= self.max_size_bytes:
                            self._rotate()
                    
                    # Write
                    try:
                        self._file.write(line)
                        self._file.flush()
                        self._current_size += len(line.encode('utf-8'))
                        self.total_written += 1
                        consecutive_errors = 0
                        
                    except (IOError, OSError) as e:
                        consecutive_errors += 1
                        print(f"[Logger] Write error {consecutive_errors}/{max_consecutive_errors}: {e}", file=sys.stderr)
                        
                        if consecutive_errors >= max_consecutive_errors:
                            print(f"[Logger] Too many write errors, stopping logger", file=sys.stderr)
                            self._running = False
                            break
                        
                        # Try to recover
                        try:
                            if self._file:
                                self._file.close()
                            self._open_file()
                        except Exception:
                            pass
                            
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"[Logger] Unexpected error: {e}", file=sys.stderr)
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    
        except Exception as e:
            print(f"[Logger] Fatal error: {e}", file=sys.stderr)
        finally:
            if self._file:
                try:
                    self._file.close()
                except Exception:
                    pass
    
    def _open_file(self):
        """Open the log file with size tracking."""
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
        
        try:
            self._file = open(self.log_path, 'a', encoding='utf-8')
            
            # Get current size
            try:
                self._current_size = self.log_path.stat().st_size
            except Exception:
                self._current_size = 0
        except Exception as e:
            print(f"[Logger] Failed to open log file: {e}", file=sys.stderr)
            self._current_size = 0
    
    def _rotate(self):
        """Rotate log files with thread safety."""
        try:
            # Close current file
            if self._file:
                try:
                    self._file.close()
                except Exception:
                    pass
                self._file = None
            
            # Rotate existing files
            for i in range(self.max_files - 1, 0, -1):
                old_path = Path(f"{self.log_path}.{i}")
                new_path = Path(f"{self.log_path}.{i + 1}")
                
                if old_path.exists():
                    if i == self.max_files - 1:
                        try:
                            old_path.unlink()
                        except Exception:
                            pass
                    else:
                        try:
                            old_path.rename(new_path)
                        except Exception:
                            pass
            
            # Rename current to .1
            if self.log_path.exists():
                try:
                    self.log_path.rename(Path(f"{self.log_path}.1"))
                except Exception:
                    pass
            
            # Open new file
            self._open_file()
            self.rotation_count += 1
            
            print(f"[Logger] Log rotated (rotation #{self.rotation_count})", file=sys.stderr)
            
        except Exception as e:
            print(f"[Logger] Rotation error: {e}", file=sys.stderr)


class LynxLogger:
    """
    Main logger for Lynx VAPT.
    
    Features:
    - Structured JSON logging
    - Multiple output targets (file, console, callback)
    - Contextual logging (scanner, URL, etc.)
    - Async-safe
    """
    
    def __init__(
        self,
        log_dir: str = "logs",
        log_level: LogLevel = LogLevel.INFO,
        json_logs: bool = True,
        console_output: bool = True,
        rotate_logs: bool = True,
        max_size_mb: float = 10
    ):
        self.log_level = log_level
        self.json_logs = json_logs
        self.console_output = console_output
        
        # Set up log directory
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamp for log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"lynx_{timestamp}.log"
        
        # Set up writer
        if rotate_logs:
            self._writer = RotatingLogWriter(str(log_file), max_size_mb)
        else:
            self._writer = AsyncLogWriter(str(log_file))
        
        self._writer.start()
        
        # Callbacks for real-time log processing
        self._callbacks: List[Callable[[LogEntry], None]] = []
        
        # Context stack for nested logging
        self._context: Dict[str, Any] = {}
    
    def add_callback(self, callback: Callable[[LogEntry], None]):
        """Add a callback for real-time log processing."""
        self._callbacks.append(callback)
    
    def set_context(self, **kwargs):
        """Set persistent context for subsequent logs."""
        self._context.update(kwargs)
    
    def clear_context(self):
        """Clear the logging context."""
        self._context.clear()
    
    def _log(
        self,
        level: LogLevel,
        category: LogCategory,
        message: str,
        **kwargs
    ):
        """Internal log method with error isolation."""
        if level.value < self.log_level.value:
            return
        
        # Merge context
        metadata = {**self._context, **kwargs.pop('metadata', {})}
        
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level.name,
            category=category.value,
            message=message,
            metadata=metadata if metadata else None,
            **kwargs
        )
        
        # Write to file (with error handling)
        try:
            queued = self._writer.write(entry)
            if not queued:
                # Log to console if dropped
                if self.console_output:
                    print(f"[LOG DROPPED] {entry.to_text()}", file=sys.stderr)
        except Exception as e:
            # Fallback to console if writer fails
            if self.console_output:
                print(f"[LOG ERROR] {e}: {entry.to_text()}", file=sys.stderr)
        
        # Console output
        if self.console_output:
            self._print_entry(entry)
        
        # Callbacks with error isolation
        for callback in self._callbacks:
            try:
                callback(entry)
            except Exception:
                # Silently ignore callback errors to prevent log loop
                pass
    
    def _print_entry(self, entry: LogEntry):
        """Print entry to console with colors."""
        colors = {
            'DEBUG': '\033[90m',
            'INFO': '\033[94m',
            'WARNING': '\033[93m',
            'ERROR': '\033[91m',
            'CRITICAL': '\033[1;91m',
            'VULN': '\033[1;92m',
        }
        reset = '\033[0m'
        
        color = colors.get(entry.level, '')
        print(f"{color}{entry.to_text()}{reset}")
    
    # Convenience methods
    def debug(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        self._log(LogLevel.DEBUG, category, message, **kwargs)
    
    def info(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        self._log(LogLevel.INFO, category, message, **kwargs)
    
    def warning(self, message: str, category: LogCategory = LogCategory.SYSTEM, **kwargs):
        self._log(LogLevel.WARNING, category, message, **kwargs)
    
    def error(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        self._log(LogLevel.ERROR, category, message, **kwargs)
    
    def critical(self, message: str, category: LogCategory = LogCategory.ERROR, **kwargs):
        self._log(LogLevel.CRITICAL, category, message, **kwargs)
    
    def vuln(self, message: str, **kwargs):
        """Log a vulnerability finding."""
        self._log(LogLevel.VULN, LogCategory.VULN, message, **kwargs)
    
    def scanner(self, scanner_name: str, message: str, **kwargs):
        """Log a scanner event."""
        self._log(LogLevel.INFO, LogCategory.SCANNER, message, scanner=scanner_name, **kwargs)
    
    def http(self, method: str, url: str, status: int, duration_ms: float, **kwargs):
        """Log an HTTP request."""
        message = f"{method} {url} -> {status}"
        self._log(
            LogLevel.DEBUG, LogCategory.HTTP, message,
            url=url, duration_ms=duration_ms, **kwargs
        )
    
    def performance(self, operation: str, duration_ms: float, **kwargs):
        """Log a performance metric."""
        message = f"{operation} completed"
        self._log(
            LogLevel.DEBUG, LogCategory.PERFORMANCE, message,
            duration_ms=duration_ms, **kwargs
        )
    
    def close(self):
        """Close the logger and flush logs."""
        self._writer.stop()


# Global logger instance
_logger: Optional[LynxLogger] = None


def get_logger() -> LynxLogger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = LynxLogger()
    return _logger


def configure_logger(**kwargs) -> LynxLogger:
    """Configure and return the global logger."""
    global _logger
    _logger = LynxLogger(**kwargs)
    return _logger


# Integration with existing event_manager
async def log_event_handler(data: Any):
    """Handler to bridge event_manager logs to structured logger."""
    logger = get_logger()
    
    if isinstance(data, str):
        # Determine level from message content
        if "[Error]" in data or "Error:" in data:
            logger.error(data)
        elif "[Warning]" in data:
            logger.warning(data)
        elif "[Debug]" in data:
            logger.debug(data)
        else:
            logger.info(data)
    elif isinstance(data, dict):
        logger.info(str(data), metadata=data)
    else:
        logger.info(str(data))
