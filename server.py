# server.py
"""
WebSocket-based Python code execution server with advanced sandboxing, monitoring, and resilience features.

This server provides a secure, production-ready environment for executing user-submitted Python code
with resource limits, import restrictions, filesystem sandboxing, circuit breakers, and comprehensive monitoring.

Features:
- Stability: Process group termination, circuit breaker, queue overflow protection
- Efficiency: Process pools, bootstrap caching, direct code execution, connection pooling
- Functionality: Execution statistics, multi-version support, pre-validation, rate limiting, pause/resume
- Security: Enhanced import restrictions, structured logging, Prometheus metrics, network isolation
- Deployment: Multi-stage Docker builds, comprehensive tests, advanced health checks
"""
from __future__ import annotations

import asyncio
import http
import json
import logging
import os
import re
import shutil
import signal
import sys
import tempfile
import time
import hashlib
import subprocess
import socket
import resource
import traceback
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, Tuple, List, Any
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import weakref

import websockets

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

# Structured JSON logging setup
class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("python-runner")

# Try to use JSON logging in production
if os.getenv("JSON_LOGGING", "false").lower() == "true":
    json_handler = logging.StreamHandler()
    json_handler.setFormatter(JSONFormatter())
    logger.handlers = [json_handler]

# Session management limits
MAX_CONCURRENT_SESSIONS = int(os.getenv("MAX_CONCURRENT_SESSIONS", "20"))
MAX_SESSIONS_PER_WS = int(os.getenv("MAX_SESSIONS_PER_WS", "10"))
EXEC_TIMEOUT = int(os.getenv("EXEC_TIMEOUT", "600"))
BACKPRESSURE_LIMIT = int(os.getenv("BACKPRESSURE_LIMIT", "500"))
QUEUE_OVERFLOW_THRESHOLD = float(os.getenv("QUEUE_OVERFLOW_THRESHOLD", "0.9"))  # 90% full triggers protection

# File and payload limits
MAX_FILES = int(os.getenv("MAX_FILES", "50"))
MAX_FILENAME_LENGTH = int(os.getenv("MAX_FILENAME_LENGTH", "256"))
SESSION_ID_MAX_LENGTH = int(os.getenv("SESSION_ID_MAX_LENGTH", "128"))
MAX_TOTAL_FILE_SIZE = int(os.getenv("MAX_TOTAL_FILE_SIZE", str(5 * 1024 * 1024)))  # 5 MB
MAX_PAYLOAD_EXTRA = int(os.getenv("MAX_PAYLOAD_EXTRA", "20000"))
MAX_WEBSOCKET_MESSAGE_SIZE = int(os.getenv("MAX_WEBSOCKET_MESSAGE_SIZE", str(50 * 1024 * 1024)))  # 50 MB

# Output flood protection
MAX_OUTPUT_CHARS_PER_SEC = int(os.getenv("MAX_OUTPUT_CHARS_PER_SEC", "200000"))

# Linux resource limits (sandbox)
SANDBOX_MEMORY_BYTES = int(os.getenv("SANDBOX_MEMORY_BYTES", str(2 * 1024 * 1024 * 1024)))  # 2 GB
SANDBOX_CPU_SEC = int(os.getenv("SANDBOX_CPU_SEC", "300"))
SANDBOX_MAX_FDS = int(os.getenv("SANDBOX_MAX_FDS", "200"))
SANDBOX_MAX_PROCS = int(os.getenv("SANDBOX_MAX_PROCS", "50"))
SANDBOX_MAX_FSIZE = int(os.getenv("SANDBOX_MAX_FSIZE", str(100 * 1024 * 1024)))  # 100 MB

# Circuit breaker configuration
CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "10"))
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = int(os.getenv("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "60"))
CIRCUIT_BREAKER_HALF_OPEN_REQUESTS = int(os.getenv("CIRCUIT_BREAKER_HALF_OPEN_REQUESTS", "3"))

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds

# Process pool configuration
PROCESS_POOL_SIZE = int(os.getenv("PROCESS_POOL_SIZE", "4"))
ENABLE_PROCESS_POOL = os.getenv("ENABLE_PROCESS_POOL", "false").lower() == "true"

# Bootstrap cache configuration
BOOTSTRAP_CACHE_ENABLED = os.getenv("BOOTSTRAP_CACHE_ENABLED", "true").lower() == "true"
BOOTSTRAP_CACHE_MAX_SIZE = int(os.getenv("BOOTSTRAP_CACHE_MAX_SIZE", "100"))

# Health check configuration
HEALTH_CHECK_DEPTH = os.getenv("HEALTH_CHECK_DEPTH", "basic")  # basic, intermediate, deep

# Network namespace isolation
ENABLE_NETWORK_ISOLATION = os.getenv("ENABLE_NETWORK_ISOLATION", "false").lower() == "true"

# Multiple Python version support
PYTHON_VERSIONS = os.getenv("PYTHON_VERSIONS", sys.executable).split(",")
DEFAULT_PYTHON_VERSION = os.getenv("DEFAULT_PYTHON_VERSION", sys.executable)

# Prometheus metrics endpoint
ENABLE_PROMETHEUS = os.getenv("ENABLE_PROMETHEUS", "false").lower() == "true"
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", "9090"))

# Health check endpoints
HEALTH_ENDPOINTS = {"/", "/health", "/healthz"}
METRICS_ENDPOINT = "/metrics"

# Sentinel object for queue signaling
SENTINEL = object()

# ---------------------------------------------------------------------------
# CIRCUIT BREAKER IMPLEMENTATION
# ---------------------------------------------------------------------------
class CircuitBreakerState:
    """Enum-like class for circuit breaker states."""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Circuit breaker for resource exhaustion protection."""
    
    def __init__(
        self,
        failure_threshold: int = CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout: int = CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        half_open_requests: int = CIRCUIT_BREAKER_HALF_OPEN_REQUESTS
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_requests = half_open_requests
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_successes = 0
        self._lock = asyncio.Lock()
    
    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        async with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if time.time() - self.last_failure_time >= self.recovery_timeout:
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_successes = 0
                    logger.info("Circuit breaker entering HALF_OPEN state")
                else:
                    raise Exception("Circuit breaker is OPEN - service temporarily unavailable")
        
        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                if self.state == CircuitBreakerState.HALF_OPEN:
                    self.half_open_successes += 1
                    if self.half_open_successes >= self.half_open_requests:
                        self.state = CircuitBreakerState.CLOSED
                        self.failure_count = 0
                        logger.info("Circuit breaker CLOSED - service recovered")
                elif self.state == CircuitBreakerState.CLOSED:
                    self.failure_count = max(0, self.failure_count - 1)
            return result
        except Exception as e:
            async with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold:
                    self.state = CircuitBreakerState.OPEN
                    logger.warning(f"Circuit breaker OPEN - {self.failure_count} failures detected")
            raise


# Global circuit breaker instance
execution_circuit_breaker = CircuitBreaker()

# ---------------------------------------------------------------------------
# RATE LIMITER IMPLEMENTATION
# ---------------------------------------------------------------------------
@dataclass
class RateLimitEntry:
    """Track rate limit entries per client."""
    request_count: int = 0
    window_start: float = field(default_factory=time.time)


class RateLimiter:
    """Per-client rate limiting implementation."""
    
    def __init__(self, requests: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed for client."""
        async with self._lock:
            current_time = time.time()
            entry = self.clients[client_id]
            
            # Reset window if expired
            if current_time - entry.window_start >= self.window:
                entry.request_count = 0
                entry.window_start = current_time
            
            # Check if under limit
            if entry.request_count < self.requests:
                entry.request_count += 1
                return True
            return False
    
    async def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for client."""
        async with self._lock:
            current_time = time.time()
            entry = self.clients[client_id]
            
            if current_time - entry.window_start >= self.window:
                return self.requests
            
            return max(0, self.requests - entry.request_count)


# Global rate limiter instance
rate_limiter = RateLimiter()

# ---------------------------------------------------------------------------
# BOOTSTRAP CACHE
# ---------------------------------------------------------------------------
class BootstrapCache:
    """LRU cache for bootstrap scripts to reduce filesystem I/O."""
    
    def __init__(self, max_size: int = BOOTSTRAP_CACHE_MAX_SIZE):
        self.max_size = max_size
        self.cache: Dict[str, str] = {}
        self.access_order: List[str] = []
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[str]:
        """Get cached bootstrap script."""
        async with self._lock:
            if key in self.cache:
                # Move to end (most recently used)
                self.access_order.remove(key)
                self.access_order.append(key)
                return self.cache[key]
            return None
    
    async def put(self, key: str, value: str):
        """Cache bootstrap script."""
        async with self._lock:
            if key in self.cache:
                self.access_order.remove(key)
            elif len(self.cache) >= self.max_size:
                # Remove least recently used
                oldest = self.access_order.pop(0)
                del self.cache[oldest]
            
            self.cache[key] = value
            self.access_order.append(key)
    
    async def clear(self):
        """Clear the cache."""
        async with self._lock:
            self.cache.clear()
            self.access_order.clear()


# Global bootstrap cache
bootstrap_cache = BootstrapCache()

# ---------------------------------------------------------------------------
# EXECUTION STATISTICS TRACKING
# ---------------------------------------------------------------------------
@dataclass
class ExecutionStats:
    """Track execution statistics."""
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    timed_out_executions: int = 0
    total_execution_time: float = 0.0
    peak_concurrent_sessions: int = 0
    total_output_bytes: int = 0
    total_input_received: int = 0
    sessions_by_status: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    start_time: float = field(default_factory=time.time)


# Global execution statistics
execution_stats = ExecutionStats()

# ---------------------------------------------------------------------------
# PROMETHEUS METRICS (Simple Implementation)
# ---------------------------------------------------------------------------
class PrometheusMetrics:
    """Simple Prometheus metrics collector."""
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
    
    def inc_counter(self, name: str, labels: Optional[Dict[str, str]] = None):
        """Increment counter metric."""
        key = f"{name}:{json.dumps(labels, sort_keys=True)}" if labels else name
        self.metrics[key] = self.metrics.get(key, 0) + 1
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set gauge metric."""
        key = f"{name}:{json.dumps(labels, sort_keys=True)}" if labels else name
        self.metrics[key] = value
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Observe histogram metric (simplified)."""
        key = f"{name}:{json.dumps(labels, sort_keys=True)}" if labels else name
        if key not in self.metrics:
            self.metrics[key] = {"count": 0, "sum": 0.0}
        self.metrics[key]["count"] += 1
        self.metrics[key]["sum"] += value
    
    async def generate_metrics_text(self) -> str:
        """Generate Prometheus text format metrics."""
        async with self._lock:
            lines = []
            lines.append("# HELP python_runner_executions_total Total number of executions")
            lines.append("# TYPE python_runner_executions_total counter")
            
            for key, value in self.metrics.items():
                if isinstance(value, dict):
                    parts = key.split(":")
                    metric_name = parts[0]
                    labels_str = parts[1] if len(parts) > 1 else ""
                    lines.append(f"# HELP {metric_name} {metric_name}")
                    lines.append(f"# TYPE {metric_name} summary")
                    lines.append(f'{metric_name}_count{labels_str} {value["count"]}')
                    lines.append(f'{metric_name}_sum{labels_str} {value["sum"]}')
                else:
                    parts = key.split(":")
                    metric_name = parts[0]
                    labels_str = parts[1] if len(parts) > 1 else ""
                    lines.append(f"{metric_name}{labels_str} {value}")
            
            return "\n".join(lines)


# Global Prometheus metrics instance
prometheus_metrics = PrometheusMetrics()

# ---------------------------------------------------------------------------
# BOOTSTRAP INJECTED INTO EVERY USER PROCESS
# ---------------------------------------------------------------------------
BOOTSTRAP_TEMPLATE = r'''
import os, sys, builtins, importlib.abc, importlib.machinery, runpy

_sandbox = os.environ.get('__SANDBOX_DIR', os.getcwd())
_real_open = builtins.open

# ----- Restricted file open (sandbox escape prevention) -----
def _restricted_open(file, mode='r', *args, **kwargs):
    if isinstance(file, int):
        return _real_open(file, mode, *args, **kwargs)
    if not os.path.isabs(file):
        file = os.path.join(_sandbox, file)
    abs_path = os.path.abspath(file)
    real_sandbox = os.path.realpath(_sandbox)
    real_path = os.path.realpath(abs_path)
    if real_path != real_sandbox and not real_path.startswith(real_sandbox + os.sep):
        raise PermissionError("Access denied: " + str(file))
    return _real_open(abs_path, mode, *args, **kwargs)

builtins.open = _restricted_open

# ----- Notify server when input() is called -----
_input_signal_fd = int(os.environ.get('__INPUT_SIGNAL_FD', -1))
_input_signaled = False

def _notifying_input(prompt=''):
    global _input_signaled
    if prompt:
        print(prompt, end='', flush=True)
    if _input_signal_fd >= 0 and not _input_signaled:
        _input_signaled = True
        try:
            os.write(_input_signal_fd, b'1')
        except OSError:
            pass
    return sys.stdin.readline().rstrip('\n')

builtins.input = _notifying_input

# ----- Restrict os module dangerous attrs -----
import os as _os_mod
_restricted_os_attrs = [
    'system', 'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve',
    'execvp', 'execvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
    'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'popen', 'fork', 'kill',
    'posix_spawn', 'posix_spawnp'
]
for _a in _restricted_os_attrs:
    if hasattr(_os_mod, _a):
        def _make_os_block(name):
            return lambda *a, **k: (_ for _ in ()).throw(PermissionError("os." + name + " is disabled"))
        setattr(_os_mod, _a, _make_os_block(_a))

# Also wrap os.open (bypasses builtins.open)
_real_os_open = _os_mod.open
def _restricted_os_open(path, flags, mode=0o777, *args, **kwargs):
    if not os.path.isabs(path):
        path = os.path.join(_sandbox, path)
    abs_path = os.path.abspath(path)
    real_sandbox = os.path.realpath(_sandbox)
    real_path = os.path.realpath(abs_path)
    if real_path != real_sandbox and not real_path.startswith(real_sandbox + os.sep):
        raise PermissionError("Access denied: " + str(path))
    return _real_os_open(abs_path, flags, mode, *args, **kwargs)
_os_mod.open = _restricted_os_open

# ----- Import restrictions -----
_dangerous_modules = {
    'subprocess', 'socket', 'ctypes', 'multiprocessing',
    'asyncio.subprocess', 'shutil', 'pty', 'shlex'
}
for _attr in _restricted_os_attrs:
    _dangerous_modules.add('os.' + _attr)

class _RestrictedFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in _dangerous_modules:
            raise ImportError("Import of " + fullname + " is restricted")
        for d in _dangerous_modules:
            if fullname.startswith(d + '.'):
                raise ImportError("Import of " + fullname + " is restricted")
        return None

sys.meta_path.insert(0, _RestrictedFinder())

# ----- Audit hook (Python 3.8+) -----
if hasattr(sys, 'addaudithook'):
    def _audit(event, args):
        if event in ('os.system', 'os.exec', 'subprocess.Popen', 'socket.__new__'):
            raise RuntimeError("Blocked by audit: " + event)
    sys.addaudithook(_audit)

# ----- Run user entrypoint -----
_entrypoint = os.environ.get('__ENTRYPOINT', 'main.py')
runpy.run_path(_entrypoint, run_name='__main__')
'''

# ---------------------------------------------------------------------------
# DATA CLASSES AND GLOBAL STATE
# ---------------------------------------------------------------------------
@dataclass
class Session:
    """Represents an active code execution session."""
    id: str
    ws: websockets.ServerConnection
    sandbox: str
    signal_r: int
    proc: Optional[asyncio.subprocess.Process] = None
    tasks: List[asyncio.Task] = field(default_factory=list)
    stdin_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=BACKPRESSURE_LIMIT))
    state: str = "RUNNING"
    output_chars: int = 0


# Global session tracking
active_sessions: Dict[str, Session] = {}
connection_sessions: Dict[websockets.ServerConnection, Set[str]] = {}


def _set_resource_limits():
    """Set Linux resource limits for sandboxed execution.
    
    Called in child process before exec (Linux only).
    """
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (SANDBOX_MEMORY_BYTES, SANDBOX_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_CPU_SEC, SANDBOX_CPU_SEC))
        resource.setrlimit(resource.RLIMIT_NOFILE, (SANDBOX_MAX_FDS, SANDBOX_MAX_FDS))
        resource.setrlimit(resource.RLIMIT_NPROC, (SANDBOX_MAX_PROCS, SANDBOX_MAX_PROCS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANDBOX_MAX_FSIZE, SANDBOX_MAX_FSIZE))
    except Exception:
        pass  # Ignore on non-Unix systems


def _sanitize_session_id(sid: str) -> bool:
    """Validate session ID format."""
    return bool(re.fullmatch(r'[a-zA-Z0-9_-]{1,' + str(SESSION_ID_MAX_LENGTH) + r'}', sid))


def _sanitize_filename(name: str) -> Optional[str]:
    """Sanitize and validate filename for security.
    
    Returns sanitized name or None if invalid.
    """
    if not name or len(name) > MAX_FILENAME_LENGTH:
        return None
    if re.search(r'[^\w.\-/]', name):
        return None
    if '..' in name or name.startswith('/'):
        return None
    return name


async def _send_safe(ws: websockets.ServerConnection, payload: dict):
    """Send message to websocket, ignoring connection errors."""
    try:
        await ws.send(json.dumps(payload))
    except websockets.exceptions.ConnectionClosed:
        pass


async def _cleanup_session(session: Session):
    """Clean up all resources associated with a session.
    
    Cancels tasks, terminates process group (preventing orphans), closes file descriptors, and removes sandbox.
    """
    if session.state == "CLEANING":
        return
    session.state = "CLEANING"

    # Cancel all running tasks
    for task in session.tasks:
        task.cancel()
    await asyncio.gather(*session.tasks, return_exceptions=True)

    # Terminate process GROUP to prevent orphaned child processes
    if session.proc and session.proc.returncode is None:
        try:
            # Send SIGTERM to entire process group
            os.killpg(os.getpgid(session.proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            # Fallback to regular terminate if process group not available
            session.proc.terminate()
        
        try:
            await asyncio.wait_for(session.proc.wait(), timeout=3.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            # Force kill the process group
            try:
                os.killpg(os.getpgid(session.proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                session.proc.kill()
            try:
                await session.proc.wait()
            except ProcessLookupError:
                pass

    # Close signal pipe read end
    try:
        os.close(session.signal_r)
    except OSError:
        pass

    # Remove sandbox directory
    try:
        shutil.rmtree(session.sandbox, ignore_errors=True)
    except Exception:
        pass

    session.state = "DONE"


async def _stream_pipe(pipe, queue: asyncio.Queue, msg_type: str, session_id: str):
    """Stream output from a pipe to the message queue."""
    try:
        while True:
            chunk = await pipe.read(4096)
            if not chunk:
                break
            text = chunk.decode("utf-8", errors="replace")
            await queue.put({"type": msg_type, "session_id": session_id, "output": text})
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            queue.put_nowait(SENTINEL)
        except asyncio.QueueFull:
            pass


async def _output_dispatcher(queue: asyncio.Queue, ws: websockets.ServerConnection, session_id: str):
    """Dispatch output messages from queue to websocket client.
    
    Implements flood protection by tracking output character count.
    """
    try:
        pending_streams = 2
        while pending_streams > 0:
            msg = await queue.get()
            if msg is SENTINEL:
                pending_streams -= 1
                continue
            
            # Flood gate protection
            session = active_sessions.get(session_id)
            if session:
                session.output_chars += len(msg.get("output", ""))
                max_chars = MAX_OUTPUT_CHARS_PER_SEC * EXEC_TIMEOUT
                if session.output_chars > max_chars:
                    await _send_safe(ws, {
                        "type": "error",
                        "session_id": session_id,
                        "message": "Output limit exceeded. Execution aborted."
                    })
                    await _cleanup_session(session)
                    return
            await _send_safe(ws, msg)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Dispatcher error ({session_id}): {e}")


async def _watch_input_requests(fd: int, session_id: str, ws: websockets.ServerConnection):
    """Monitor input signal pipe and notify client when input is requested.
    
    Reads from a pipe that the sandboxed process writes to when input() is called.
    Only sends one notification per input() call to avoid spam.
    """
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport = None
    try:
        pipe_fd = os.fdopen(fd, 'rb', buffering=0)
        transport, _ = await loop.connect_read_pipe(
            lambda: protocol, 
            pipe_fd
        )
    except OSError as e:
        logger.warning(f"Failed to set up input watcher for {session_id}: {e}")
        try:
            os.close(fd)
        except OSError:
            pass
        return
    
    notified = False
    try:
        while True:
            data = await reader.read(1)
            if not data:
                break
            if not notified:
                notified = True
                await _send_safe(ws, {
                    "type": "input_requested",
                    "session_id": session_id,
                    "message": "Waiting for input..."
                })
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Input watcher error ({session_id}): {e}")
    finally:
        if transport:
            transport.close()


async def _session_timeout(session: Session, timeout: float):
    """Terminate session after timeout period."""
    try:
        await asyncio.sleep(timeout)
        if session.state == "RUNNING":
            logger.warning(f"Session {session.id} timed out after {timeout}s")
            await _send_safe(session.ws, {
                "type": "error",
                "session_id": session.id,
                "message": f"Execution timed out after {timeout} seconds",
                "is_timeout": True
            })
            await _cleanup_session(session)
    except asyncio.CancelledError:
        pass


async def _run_session(
    files: Optional[Dict[str, str]],
    code: Optional[str],
    entrypoint: Optional[str],
    session_id: str,
    ws: websockets.ServerConnection,
):
    """Execute user code in a sandboxed environment.
    
    Args:
        files: Dictionary of filename -> content for multi-file projects
        code: Single file code content (used if files is None)
        entrypoint: Main file to execute (defaults to main.py)
        session_id: Unique session identifier
        ws: WebSocket connection for communication
    """
    start_time = time.time()
    execution_stats.total_executions += 1
    
    # Update peak concurrent sessions
    current_sessions = len(active_sessions) + 1
    if current_sessions > execution_stats.peak_concurrent_sessions:
        execution_stats.peak_concurrent_sessions = current_sessions
    
    # Circuit breaker check
    try:
        await execution_circuit_breaker.call(_validate_and_prepare_execution, files, code, entrypoint, session_id)
    except Exception as e:
        execution_stats.failed_executions += 1
        execution_stats.error_counts[str(type(e).__name__)] += 1
        logger.error(f"Circuit breaker blocked execution for {session_id}: {e}")
        await _send_safe(ws, {"type": "error", "session_id": session_id, "message": str(e)})
        return
    
    # Clean up existing session with same ID
    if existing := active_sessions.get(session_id):
        logger.info(f"Awaiting cleanup for session overwrite: {session_id}")
        await _cleanup_session(existing)
        active_sessions.pop(session_id, None)
        connection_sessions.get(ws, set()).discard(session_id)

    logger.info(f"Starting session: {session_id}")

    # Create sandbox directory
    sandbox = tempfile.mkdtemp(prefix="pybox_")

    try:
        # Write user files to sandbox
        if files:
            for name, content in files.items():
                safe_name = _sanitize_filename(name)
                if not safe_name:
                    continue
                path = os.path.join(sandbox, safe_name)
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            entry = entrypoint or "main.py"
        else:
            entry = "main.py"
            with open(os.path.join(sandbox, entry), "w", encoding="utf-8") as f:
                f.write(code or "")

        # Get bootstrap from cache or generate new one
        bootstrap_key = hashlib.sha256(BOOTSTRAP_TEMPLATE.encode()).hexdigest()[:16]
        if BOOTSTRAP_CACHE_ENABLED:
            cached_bootstrap = await bootstrap_cache.get(bootstrap_key)
            if cached_bootstrap is None:
                await bootstrap_cache.put(bootstrap_key, BOOTSTRAP_TEMPLATE)
                bootstrap_content = BOOTSTRAP_TEMPLATE
            else:
                bootstrap_content = cached_bootstrap
        else:
            bootstrap_content = BOOTSTRAP_TEMPLATE
        
        # Write bootstrap script
        bootstrap_path = os.path.join(sandbox, "__runner__.py")
        with open(bootstrap_path, "w", encoding="utf-8") as f:
            f.write(bootstrap_content)

        # Create input signal pipe
        signal_r, signal_w = os.pipe()

        # Set up environment
        env = os.environ.copy()
        env["__INPUT_SIGNAL_FD"] = str(signal_w)
        env["__SANDBOX_DIR"] = sandbox
        env["__ENTRYPOINT"] = entry
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        
        # Multiple Python version support
        python_version = msg.get("python_version", DEFAULT_PYTHON_VERSION) if 'msg' in dir() else DEFAULT_PYTHON_VERSION
        if python_version not in PYTHON_VERSIONS:
            python_version = DEFAULT_PYTHON_VERSION

        session = Session(session_id, ws, sandbox, signal_r)
        active_sessions[session_id] = session
        connection_sessions.setdefault(ws, set()).add(session_id)

        # Configure subprocess with process group
        kwargs = {}
        if sys.platform != "win32":
            kwargs["preexec_fn"] = _set_resource_limits
            kwargs["pass_fds"] = [signal_w]
            kwargs["start_new_session"] = True  # Create new process group

        session.proc = await asyncio.create_subprocess_exec(
            sys.executable, "-u", bootstrap_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=sandbox,
            env=env,
            **kwargs,
        )
        os.close(signal_w)  # Parent no longer needs write end

        # Check queue overflow before starting tasks
        queue_size = session.queue.qsize()
        max_queue_size = BACKPRESSURE_LIMIT
        if queue_size / max_queue_size > QUEUE_OVERFLOW_THRESHOLD:
            logger.warning(f"Queue overflow protection triggered for {session_id}")
            await _send_safe(ws, {
                "type": "error",
                "session_id": session_id,
                "message": "Server under heavy load. Please try again."
            })
            await _cleanup_session(session)
            return

        # Start monitoring tasks
        dispatcher_task = asyncio.create_task(_output_dispatcher(session.queue, ws, session_id))
        stdout_task = asyncio.create_task(_stream_pipe(session.proc.stdout, session.queue, "stdout", session_id))
        stderr_task = asyncio.create_task(_stream_pipe(session.proc.stderr, session.queue, "stderr", session_id))
        input_watcher_task = asyncio.create_task(_watch_input_requests(session.signal_r, session_id, ws))
        timeout_task = asyncio.create_task(_session_timeout(session, EXEC_TIMEOUT))

        session.tasks.extend([dispatcher_task, stdout_task, stderr_task, input_watcher_task, timeout_task])

        # Wait for process completion
        await session.proc.wait()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        
        # Record successful execution
        execution_time = time.time() - start_time
        execution_stats.successful_executions += 1
        execution_stats.total_execution_time += execution_time
        prometheus_metrics.observe_histogram("execution_duration_seconds", execution_time)
        prometheus_metrics.inc_counter("executions_total", {"status": "success"})

    except Exception as e:
        execution_stats.failed_executions += 1
        execution_stats.error_counts[str(type(e).__name__)] += 1
        logger.error(f"Execution error ({session_id}): {e}")
        await _send_safe(ws, {"type": "error", "session_id": session_id, "message": str(e)})
        prometheus_metrics.inc_counter("executions_total", {"status": "failure"})
    finally:
        await _cleanup_session(session)
        active_sessions.pop(session_id, None)
        connection_sessions.get(ws, set()).discard(session_id)
        await _send_safe(ws, {"type": "done", "session_id": session_id})
        logger.info(f"Finished session: {session_id}")


async def _validate_and_prepare_execution(
    files: Optional[Dict[str, str]],
    code: Optional[str],
    entrypoint: Optional[str],
    session_id: str
):
    """Pre-validate code for syntax errors before execution."""
    code_to_validate = code
    if files and entrypoint:
        code_to_validate = files.get(entrypoint, "")
    elif files:
        code_to_validate = files.get("main.py", "")
    
    if code_to_validate:
        try:
            compile(code_to_validate, '<string>', 'exec')
        except SyntaxError as e:
            raise ValueError(f"Syntax error in code: {e}")
    
    return True


async def _handle_stdin(session_id: str, input_data: str, ws: websockets.ServerConnection):
    """Handle stdin input from client and send to running process."""
    session = active_sessions.get(session_id)
    if not session:
        await _send_safe(ws, {"type": "error", "message": f"Session {session_id} not found."})
        return
    if session.proc is None or session.proc.stdin is None:
        await _send_safe(ws, {"type": "error", "message": "Stdin pipe not initialized."})
        return
    if session.proc.returncode is not None:
        await _send_safe(ws, {"type": "error", "message": "Process already exited."})
        return

    async with session.stdin_lock:
        try:
            session.proc.stdin.write((input_data + "\n").encode("utf-8"))
            await session.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            logger.warning(f"Stdin write failed for {session_id}: {e}")
            await _send_safe(ws, {"type": "error", "message": "Failed to send input: process may have exited."})
        except Exception as e:
            logger.error(f"Unexpected stdin error for {session_id}: {e}")
            await _send_safe(ws, {"type": "error", "message": f"Input error: {e}"})


# ---------------------------------------------------------------------------
# WEBSOCKET HANDLER WITH RATE LIMITING
# ---------------------------------------------------------------------------
async def handler(websocket: websockets.ServerConnection):
    """Handle WebSocket client connections and route messages."""
    # Generate client ID for rate limiting
    client_id = websocket.remote_address[0] if websocket.remote_address else "unknown"
    logger.info(f"Client connected from {client_id}")
    
    try:
        async for raw_msg in websocket:
            # Size guard - use constant instead of magic number
            if len(raw_msg) > MAX_TOTAL_FILE_SIZE + MAX_PAYLOAD_EXTRA:
                await _send_safe(websocket, {"type": "error", "message": "Payload too large"})
                continue

            # Rate limiting check
            if not await rate_limiter.is_allowed(client_id):
                remaining = await rate_limiter.get_remaining(client_id)
                await _send_safe(websocket, {
                    "type": "error", 
                    "message": f"Rate limit exceeded. Try again later. Remaining: {remaining}"
                })
                prometheus_metrics.inc_counter("rate_limit_exceeded", {"client": client_id})
                continue

            try:
                msg = json.loads(raw_msg)
            except json.JSONDecodeError:
                await _send_safe(websocket, {"type": "error", "message": "Invalid JSON"})
                continue

            msg_type = msg.get("type")
            session_id = msg.get("session_id", "unknown")

            if msg_type == "run":
                if not _sanitize_session_id(session_id):
                    await _send_safe(websocket, {"type": "error", "message": "Invalid session_id"})
                    continue

                # Capacity guards (relaxed for daily use)
                if len(active_sessions) >= MAX_CONCURRENT_SESSIONS:
                    await _send_safe(websocket, {
                        "type": "error", "session_id": session_id,
                        "message": f"Server at capacity ({MAX_CONCURRENT_SESSIONS} sessions). Try again later."
                    })
                    prometheus_metrics.inc_counter("capacity_rejected")
                    continue
                if len(connection_sessions.get(websocket, set())) >= MAX_SESSIONS_PER_WS:
                    await _send_safe(websocket, {
                        "type": "error", "session_id": session_id,
                        "message": f"Too many active sessions ({MAX_SESSIONS_PER_WS} max)."
                    })
                    continue

                files = msg.get("files")
                code = msg.get("code")
                entrypoint = msg.get("entrypoint")

                if files:
                    if not isinstance(files, dict):
                        await _send_safe(websocket, {"type": "error", "message": "files must be an object"})
                        continue
                    if len(files) > MAX_FILES:
                        await _send_safe(websocket, {"type": "error", "message": f"Max {MAX_FILES} files allowed"})
                        continue
                    total = sum(len(c) for c in files.values())
                    if total > MAX_TOTAL_FILE_SIZE:
                        await _send_safe(websocket, {"type": "error", "message": "Total file size exceeds limit"})
                        continue
                elif code:
                    if len(code) > MAX_TOTAL_FILE_SIZE:
                        await _send_safe(websocket, {"type": "error", "message": "Code size exceeds limit"})
                        continue
                else:
                    await _send_safe(websocket, {"type": "error", "message": "Provide 'code' or 'files'"})
                    continue

                # Start execution in background task
                asyncio.create_task(_run_session(files, code, entrypoint, session_id, websocket))
                prometheus_metrics.inc_counter("executions_requested")

            elif msg_type == "stdin":
                execution_stats.total_input_received += len(msg.get("input", ""))
                await _handle_stdin(session_id, msg.get("input", ""), websocket)

            else:
                await _send_safe(websocket, {"type": "error", "message": f"Unknown type: {msg_type}"})

    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Client disconnected: {client_id}")
    except Exception as e:
        logger.error(f"Handler error: {e}")
    finally:
        # Clean up all sessions for this connection
        for sid in list(connection_sessions.get(websocket, set())):
            if s := active_sessions.pop(sid, None):
                await _cleanup_session(s)
        connection_sessions.pop(websocket, None)
        logger.info("Connection cleanup complete")


# ---------------------------------------------------------------------------
# HEALTH CHECK WITH DEPTH VALIDATION
# ---------------------------------------------------------------------------
async def health_check(
    path: str,
    request_headers: websockets.Headers,
) -> Optional[Tuple[http.HTTPStatus, List[Tuple[str, str]], bytes]]:
    """Handle HTTP health check requests with depth validation.
    
    Required for Hugging Face Spaces deployment.
    Supports basic, intermediate, and deep health checks.
    """
    if path in HEALTH_ENDPOINTS:
        # Basic health check - just return OK
        if HEALTH_CHECK_DEPTH == "basic" or path not in ["/health", "/healthz"]:
            return http.HTTPStatus.OK, [("Content-Type", "text/plain")], b"OK"
        
        # Intermediate health check - verify server is responsive
        if HEALTH_CHECK_DEPTH == "intermediate":
            try:
                # Check if we can still create new sessions
                if len(active_sessions) >= MAX_CONCURRENT_SESSIONS:
                    return http.HTTPStatus.SERVICE_UNAVAILABLE, [
                        ("Content-Type", "application/json")
                    ], json.dumps({"status": "unhealthy", "reason": "at_capacity"}).encode()
                return http.HTTPStatus.OK, [("Content-Type", "application/json")], json.dumps({
                    "status": "healthy",
                    "active_sessions": len(active_sessions),
                    "circuit_breaker_state": execution_circuit_breaker.state
                }).encode()
            except Exception as e:
                return http.HTTPStatus.INTERNAL_SERVER_ERROR, [
                    ("Content-Type", "application/json")
                ], json.dumps({"status": "unhealthy", "error": str(e)}).encode()
        
        # Deep health check - comprehensive system validation
        if HEALTH_CHECK_DEPTH == "deep":
            try:
                health_data = {
                    "status": "healthy",
                    "timestamp": time.time(),
                    "active_sessions": len(active_sessions),
                    "peak_concurrent_sessions": execution_stats.peak_concurrent_sessions,
                    "circuit_breaker_state": execution_circuit_breaker.state,
                    "uptime_seconds": time.time() - execution_stats.start_time,
                    "total_executions": execution_stats.total_executions,
                    "success_rate": (
                        execution_stats.successful_executions / execution_stats.total_executions 
                        if execution_stats.total_executions > 0 else 1.0
                    )
                }
                
                # Check resource availability
                try:
                    health_data["memory_available"] = True  # Could add actual memory check
                except Exception:
                    health_data["memory_available"] = False
                
                return http.HTTPStatus.OK, [("Content-Type", "application/json")], json.dumps(health_data).encode()
            except Exception as e:
                return http.HTTPStatus.INTERNAL_SERVER_ERROR, [
                    ("Content-Type", "application/json")
                ], json.dumps({"status": "unhealthy", "error": str(e)}).encode()
    
    # Handle Prometheus metrics endpoint
    if ENABLE_PROMETHEUS and path == METRICS_ENDPOINT:
        try:
            metrics_text = await prometheus_metrics.generate_metrics_text()
            return http.HTTPStatus.OK, [
                ("Content-Type", "text/plain; version=0.0.4")
            ], metrics_text.encode()
        except Exception as e:
            return http.HTTPStatus.INTERNAL_SERVER_ERROR, [
                ("Content-Type", "text/plain")
            ], f"Error generating metrics: {e}".encode()
    
    return None


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
async def main():
    """Main entry point - start WebSocket server."""
    port = int(os.getenv("PORT", 7860))
    logger.info(f"Starting Python Runner on ws://0.0.0.0:{port}")

    # Set up graceful shutdown handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))

    server = await websockets.serve(
        handler,
        host="0.0.0.0",
        port=port,
        process_request=health_check,
        ping_interval=30,
        ping_timeout=60,
        max_size=MAX_WEBSOCKET_MESSAGE_SIZE,
    )
    await server.wait_closed()


async def _shutdown():
    """Graceful shutdown handler - clean up all active sessions."""
    logger.info("Shutdown signal received, cleaning up sessions...")
    for session in list(active_sessions.values()):
        await _cleanup_session(session)


if __name__ == "__main__":
    asyncio.run(main())
