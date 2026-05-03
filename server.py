# server.py
"""
WebSocket-based Python code execution server with sandboxing and security features.

This server provides a secure environment for executing user-submitted Python code
with resource limits, import restrictions, and filesystem sandboxing.
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
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, Tuple, List, Any

import websockets

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("python-runner")

# Session management limits (relaxed for daily use)
MAX_CONCURRENT_SESSIONS = 20
MAX_SESSIONS_PER_WS = 10
EXEC_TIMEOUT = 600
BACKPRESSURE_LIMIT = 500

# File and payload limits
MAX_FILES = 50
MAX_FILENAME_LENGTH = 256
SESSION_ID_MAX_LENGTH = 128
MAX_TOTAL_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_PAYLOAD_EXTRA = 20_000
MAX_WEBSOCKET_MESSAGE_SIZE = 50 * 1024 * 1024  # 50 MB

# Output flood protection (relaxed for daily use)
MAX_OUTPUT_CHARS_PER_SEC = 200_000

# Linux resource limits (sandbox) - relaxed for daily use
SANDBOX_MEMORY_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB
SANDBOX_CPU_SEC = 300
SANDBOX_MAX_FDS = 200
SANDBOX_MAX_PROCS = 50
SANDBOX_MAX_FSIZE = 100 * 1024 * 1024       # 100 MB

# Health check endpoints
HEALTH_ENDPOINTS = {"/", "/health", "/healthz"}

# Sentinel object for queue signaling
SENTINEL = object()

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
    
    Cancels tasks, terminates process, closes file descriptors, and removes sandbox.
    """
    if session.state == "CLEANING":
        return
    session.state = "CLEANING"

    # Cancel all running tasks
    for task in session.tasks:
        task.cancel()
    await asyncio.gather(*session.tasks, return_exceptions=True)

    # Terminate process if still running
    if session.proc and session.proc.returncode is None:
        session.proc.terminate()
        try:
            await asyncio.wait_for(session.proc.wait(), timeout=3.0)
        except (asyncio.TimeoutError, ProcessLookupError):
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

        # Write bootstrap script
        bootstrap_path = os.path.join(sandbox, "__runner__.py")
        with open(bootstrap_path, "w", encoding="utf-8") as f:
            f.write(BOOTSTRAP_TEMPLATE)

        # Create input signal pipe
        signal_r, signal_w = os.pipe()

        # Set up environment
        env = os.environ.copy()
        env["__INPUT_SIGNAL_FD"] = str(signal_w)
        env["__SANDBOX_DIR"] = sandbox
        env["__ENTRYPOINT"] = entry
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"

        session = Session(session_id, ws, sandbox, signal_r)
        active_sessions[session_id] = session
        connection_sessions.setdefault(ws, set()).add(session_id)

        # Configure subprocess
        kwargs = {}
        if sys.platform != "win32":
            kwargs["preexec_fn"] = _set_resource_limits
            kwargs["pass_fds"] = [signal_w]

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

    except Exception as e:
        logger.error(f"Execution error ({session_id}): {e}")
        await _send_safe(ws, {"type": "error", "session_id": session_id, "message": str(e)})
    finally:
        await _cleanup_session(session)
        active_sessions.pop(session_id, None)
        connection_sessions.get(ws, set()).discard(session_id)
        await _send_safe(ws, {"type": "done", "session_id": session_id})
        logger.info(f"Finished session: {session_id}")


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
# WEBSOCKET HANDLER
# ---------------------------------------------------------------------------
async def handler(websocket: websockets.ServerConnection):
    """Handle WebSocket client connections and route messages."""
    logger.info("Client connected")
    try:
        async for raw_msg in websocket:
            # Size guard - use constant instead of magic number
            if len(raw_msg) > MAX_TOTAL_FILE_SIZE + MAX_PAYLOAD_EXTRA:
                await _send_safe(websocket, {"type": "error", "message": "Payload too large"})
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

            elif msg_type == "stdin":
                await _handle_stdin(session_id, msg.get("input", ""), websocket)

            else:
                await _send_safe(websocket, {"type": "error", "message": f"Unknown type: {msg_type}"})

    except websockets.exceptions.ConnectionClosed:
        logger.info("Client disconnected")
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
# HEALTH CHECK (HF Spaces requirement)
# ---------------------------------------------------------------------------
async def health_check(
    path: str,
    request_headers: websockets.Headers,
) -> Optional[Tuple[http.HTTPStatus, List[Tuple[str, str]], bytes]]:
    """Handle HTTP health check requests.
    
    Required for Hugging Face Spaces deployment.
    """
    if path in HEALTH_ENDPOINTS:
        return http.HTTPStatus.OK, [("Content-Type", "text/plain")], b"OK"
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
