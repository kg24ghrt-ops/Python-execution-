# server.py
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
from typing import Dict, Set, Optional, Tuple, List

import websockets

# ---------------------------------------------------------------------------
# CONFIGURATION  (tuned for Hugging Face Free tier containers)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("python-runner")

SENTINEL = object()
BACKPRESSURE_LIMIT = 200

# Security / resource knobs
MAX_CONCURRENT_SESSIONS = 5          # Global sessions
MAX_SESSIONS_PER_WS = 2              # Per-connection sessions
MAX_TOTAL_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GiB
MAX_FILES = 20                       # Max files in one run
EXEC_TIMEOUT = 300                   # Hard kill after N seconds
MAX_OUTPUT_CHARS_PER_SEC = 50_000    # Rough flood-gate (enforced in dispatcher)

# Sandbox limits (Linux only — HF uses Linux containers)
SANDBOX_MEMORY_BYTES = 512 * 1024 * 1024   # 512 MB
SANDBOX_CPU_SEC = 60                       # 60 sec CPU
SANDBOX_MAX_FDS = 50
SANDBOX_MAX_PROCS = 0                      # No fork bombs
SANDBOX_MAX_FSIZE = 10 * 1024 * 1024       # 10 MB written files

# ---------------------------------------------------------------------------
# BOOTSTRAP INJECTED INTO EVERY USER PROCESS
# ---------------------------------------------------------------------------
# This restricts builtins, file access, imports, and patches input() so it
# signals the server when a prompt is waiting.
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

# ----- Disable code-evaluation builtins -----
for _name in ('exec', 'eval', 'compile'):
    if hasattr(builtins, _name):
        def _make_disabled(n):
            return lambda *a, **k: (_ for _ in ()).throw(PermissionError(n + " is disabled"))
        setattr(builtins, _name, _make_disabled(_name))

# ----- Notify server when input() is called -----
_input_signal = int(os.environ.get('__INPUT_SIGNAL_FD', -1))

def _notifying_input(prompt=''):
    if prompt:
        print(prompt, end='', flush=True)
    if _input_signal >= 0:
        try:
            os.write(_input_signal, b'1')
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
_dangerous = {
    'subprocess', 'socket', 'ctypes', 'multiprocessing',
    'asyncio.subprocess', 'shutil', 'pty', 'shlex'
}
for _attr in _restricted_os_attrs:
    _dangerous.add('os.' + _attr)

class _RestrictedFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in _dangerous:
            raise ImportError("Import of " + fullname + " is restricted")
        for d in _dangerous:
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
# HELPERS
# ---------------------------------------------------------------------------
active_sessions: Dict[str, "Session"] = {}
connection_sessions: Dict[websockets.ServerConnection, Set[str]] = {}


class Session:
    def __init__(self, session_id: str, ws: websockets.ServerConnection, sandbox: str, signal_r: int):
        self.id = session_id
        self.ws = ws
        self.sandbox = sandbox
        self.signal_r = signal_r
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.tasks: list[asyncio.Task] = []
        self.stdin_lock = asyncio.Lock()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=BACKPRESSURE_LIMIT)
        self.state: str = "RUNNING"
        self.output_chars = 0


def _set_resource_limits():
    """Called in child process before exec (Linux only)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (SANDBOX_MEMORY_BYTES, SANDBOX_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_CPU_SEC, SANDBOX_CPU_SEC))
        resource.setrlimit(resource.RLIMIT_NOFILE, (SANDBOX_MAX_FDS, SANDBOX_MAX_FDS))
        resource.setrlimit(resource.RLIMIT_NPROC, (SANDBOX_MAX_PROCS, SANDBOX_MAX_PROCS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (SANDBOX_MAX_FSIZE, SANDBOX_MAX_FSIZE))
    except Exception:
        pass


def _sanitize_session_id(sid: str) -> bool:
    return bool(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', sid))


def _sanitize_filename(name: str) -> Optional[str]:
    if not name or len(name) > 128:
        return None
    if re.search(r'[^\w.\-/]', name):
        return None
    if '..' in name or name.startswith('/'):
        return None
    return name


async def _send_safe(ws: websockets.ServerConnection, payload: dict):
    try:
        await ws.send(json.dumps(payload))
    except websockets.exceptions.ConnectionClosed:
        pass


async def _cleanup_session(session: Session):
    if session.state == "CLEANING":
        return
    session.state = "CLEANING"

    for task in session.tasks:
        task.cancel()
    await asyncio.gather(*session.tasks, return_exceptions=True)

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

    # Remove sandbox
    try:
        shutil.rmtree(session.sandbox, ignore_errors=True)
    except Exception:
        pass

    session.state = "DONE"


async def _stream_pipe(pipe, queue: asyncio.Queue, msg_type: str, session_id: str):
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
    try:
        pending_streams = 2
        while pending_streams > 0:
            msg = await queue.get()
            if msg is SENTINEL:
                pending_streams -= 1
                continue
            # Flood gate
            session = active_sessions.get(session_id)
            if session:
                session.output_chars += len(msg.get("output", ""))
                if session.output_chars > MAX_OUTPUT_CHARS_PER_SEC * EXEC_TIMEOUT:
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
    """Reads the input-request pipe and tells the client to show a prompt."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    try:
        transport, _ = await loop.connect_read_pipe(lambda: protocol, os.fdopen(fd, 'rb'))
    except OSError:
        return
    try:
        while True:
            data = await reader.read(1)
            if not data:
                break
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
        transport.close()


async def _session_timeout(session: Session, timeout: float):
    try:
        await asyncio.sleep(timeout)
        if session.state == "RUNNING":
            logger.warning(f"Session {session.id} timed out after {timeout}s")
            await _send_safe(session.ws, {
                "type": "error",
                "session_id": session.id,
                "message": f"Execution timed out after {timeout} seconds",
                "is_timeout": True  # ✅ ADDED: Protocol-level timeout flag
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
    # --- overwrite existing session with same id ---
    if existing := active_sessions.get(session_id):
        logger.info(f"Awaiting cleanup for session overwrite: {session_id}")
        await _cleanup_session(existing)
        active_sessions.pop(session_id, None)
        connection_sessions.get(ws, set()).discard(session_id)

    logger.info(f"Starting session: {session_id}")

    # --- build sandbox ---
    sandbox = tempfile.mkdtemp(prefix="pybox_")

    # --- write user files ---
    if files:
        for name, content in files.items():
            safe_name = _sanitize_filename(name)
            if not safe_name:
                continue
            path = os.path.join(sandbox, safe_name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        entry = entrypoint or "main.py"
    else:
        entry = "main.py"
        with open(os.path.join(sandbox, entry), "w", encoding="utf-8") as f:
            f.write(code or "")

    # --- write bootstrap ---
    bootstrap_path = os.path.join(sandbox, "__runner__.py")
    with open(bootstrap_path, "w", encoding="utf-8") as f:
        f.write(BOOTSTRAP_TEMPLATE)

    # --- input signal pipe ---
    signal_r, signal_w = os.pipe()

    # --- environment ---
    env = os.environ.copy()
    env["__INPUT_SIGNAL_FD"] = str(signal_w)
    env["__SANDBOX_DIR"] = sandbox
    env["__ENTRYPOINT"] = entry
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"

    session = Session(session_id, ws, sandbox, signal_r)
    active_sessions[session_id] = session
    connection_sessions.setdefault(ws, set()).add(session_id)

    try:
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
        os.close(signal_w)  # parent no longer needs write end

        # --- tasks ---
        dispatcher_task = asyncio.create_task(_output_dispatcher(session.queue, ws, session_id))
        stdout_task = asyncio.create_task(_stream_pipe(session.proc.stdout, session.queue, "stdout", session_id))
        stderr_task = asyncio.create_task(_stream_pipe(session.proc.stderr, session.queue, "stderr", session_id))
        input_watcher_task = asyncio.create_task(_watch_input_requests(session.signal_r, session_id, ws))
        timeout_task = asyncio.create_task(_session_timeout(session, EXEC_TIMEOUT))

        session.tasks.extend([dispatcher_task, stdout_task, stderr_task, input_watcher_task, timeout_task])

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


# ---------------------------------------------------------------------------
# WEBSOCKET HANDLER
# ---------------------------------------------------------------------------
async def handler(websocket: websockets.ServerConnection):
    logger.info("Client connected")
    try:
        async for raw_msg in websocket:
            # size guard
            if len(raw_msg) > MAX_TOTAL_FILE_SIZE + 10_000:
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

                # capacity guards
                if len(active_sessions) >= MAX_CONCURRENT_SESSIONS:
                    await _send_safe(websocket, {
                        "type": "error", "session_id": session_id,
                        "message": "Server at capacity. Try again later."
                    })
                    continue
                if len(connection_sessions.get(websocket, set())) >= MAX_SESSIONS_PER_WS:
                    await _send_safe(websocket, {
                        "type": "error", "session_id": session_id,
                        "message": "Too many active sessions for this connection."
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

                asyncio.create_task(_run_session(files, code, entrypoint, session_id, websocket))

            elif msg_type == "stdin":
                await _handle_stdin(session_id, msg.get("input", ""), websocket)

            else:
                await _send_safe(websocket, {"type": "error", "message": f"Unknown type: {msg_type}"})

    except websockets.exceptions.ConnectionClosed:
        logger.info("Client disconnected")
    finally:
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
    if path in ("/", "/health", "/healthz"):
        return http.HTTPStatus.OK, [("Content-Type", "text/plain")], b"OK"
    return None


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
async def main():
    port = int(os.getenv("PORT", 7860))
    logger.info(f"Starting Python Runner on ws://0.0.0.0:{port}")

    # Graceful shutdown on SIGTERM (HF Spaces sends this)
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
        max_size=10 * 1024 * 1024,
    )
    await server.wait_closed()


async def _shutdown():
    logger.info("Shutdown signal received, cleaning up sessions...")
    for session in list(active_sessions.values()):
        await _cleanup_session(session)


if __name__ == "__main__":
    asyncio.run(main())
