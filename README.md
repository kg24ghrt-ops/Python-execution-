---
title: Python Running-api
emoji: 📉
colorFrom: gray
colorTo: red
sdk: docker
pinned: false
---

Check out the configuration reference at https://huggingface.co/docs/hub/spaces-config-reference
# 📡 Python Runner WebSocket API Documentation

## 🔗 Connection Details
| Property | Value |
|----------|-------|
| **Endpoint** | `wss://<user>-<space>.hf.space` |
| **Protocol** | WebSocket (RFC 6455) |
| **Payload Format** | JSON-encoded strings only |
| **Keep-Alive** | Server pings every `30s`, disconnects after `60s` of inactivity |
| **Max Frame Size** | `10 MB` (configurable in `server.py`) |
| **TLS** | Handled automatically by Hugging Face edge proxy |

---

## 🩺 HTTP Health Check
Used by HF infrastructure to verify container liveness. **Not a WebSocket endpoint.**

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/` | `200 OK` → `OK` |
| `GET` | `/health` | `200 OK` → `OK` |
| `GET` | `/healthz` | `200 OK` → `OK` |

*Any other path delegates to the WebSocket upgrade handler.*

---

## 📦 WebSocket Message Protocol

All messages are JSON objects. The `type` field is mandatory.

### 📤 Client → Server

| Type | Schema | Description |
|------|--------|-------------|
| `run` | `{"type":"run", "session_id":"string", "code":"string"}` | Starts a new Python execution session. Overwrites existing session with same ID. |
| `stdin` | `{"type":"stdin", "session_id":"string", "input":"string"}` | Sends interactive input to a running session. **Do not include trailing newlines.** |

### 📥 Server → Client

| Type | Schema | Description |
|------|--------|-------------|
| `stdout` | `{"type":"stdout", "session_id":"string", "output":"string"}` | Real-time standard output chunks. May arrive multiple times per line. |
| `stderr` | `{"type":"stderr", "session_id":"string", "output":"string"}` | Real-time standard error chunks. |
| `error` | `{"type":"error", "session_id":"string?", "message":"string"}` | Runtime or protocol error. `session_id` omitted for global/connection errors. |
| `done` | `{"type":"done", "session_id":"string"}` | Session finished (success or failure). Process has exited and resources are freed. |

---

## 🔄 Session Lifecycle

```
Client sends: {"type":"run", "session_id":"abc", "code":"..."}
        ↓
Server spawns: python -u -c "..."
        ↓
Server streams: {"type":"stdout", ...} / {"type":"stderr", ...}
        ↓
Client (optional): {"type":"stdin", "session_id":"abc", "input":"user data"}
        ↓
Process exits → Server sends: {"type":"done", "session_id":"abc"}
```

### Key Behaviors
- **Isolation**: Each `session_id` runs in a separate `asyncio.subprocess` with independent I/O pipes.
- **Overwrite Safety**: Sending `run` with an active `session_id` gracefully terminates the previous process, drains its output queue, then spawns the new one.
- **Stdin Handling**: The server automatically appends `\n` to all `stdin` payloads to simulate pressing `Enter`.
- **Backpressure**: Internal queue caps at ~200 chunks (~800KB). Child process throttles naturally if client falls behind. No client action required.
- **Disconnect Cleanup**: Dropping the WebSocket connection immediately terminates all attached sessions and frees resources.

---

## ⚠️ Error Scenarios

| Situation | Server Response | Client Action |
|-----------|----------------|---------------|
| Malformed JSON | `{"type":"error", "message":"Invalid JSON"}` | Fix payload format |
| Unknown `type` | `{"type":"error", "message":"Unknown type: X"}` | Use supported message types |
| `stdin` to finished/missing session | `{"type":"error", "message":"..."}` | Check session state or start new `run` |
| Code execution crashes | Streams `stderr` → sends `{"type":"done", ...}` | Parse `stderr` for traceback |
| Network drop | Connection closes → server cleans up silently | Reconnect & resend `run` |

---

## 🚧 Constraints & Limits

| Constraint | Value / Behavior |
|------------|------------------|
| **Storage** | Ephemeral. No disk persistence across restarts. |
| **CPU/Memory** | HF Space tier limits apply (CPU Basic: ~2 vCPU, 8GB RAM) |
| **Concurrency** | Optimized for 1–3 concurrent sessions. Not multi-tenant hardened. |
| **Code Execution** | Runs as container user. No sandbox/namespace isolation. Trust your own code. |
| **Timeouts** | No hard execution timeout. Process runs until exit or disconnect. |
| **Stdin/Stdout Order** | Slight interleaving possible. True TTY ordering requires merging `stderr` into `stdout`. |

---

## 💻 Client Integration Examples

### JavaScript (Browser)
```javascript
const ws = new WebSocket("wss://<your-space>.hf.space");
let sessionId = crypto.randomUUID();

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  switch (msg.type) {
    case "stdout": terminal.write(msg.output); break;
    case "stderr": terminal.write(msg.output, "red"); break;
    case "error": console.error(msg.message); break;
    case "done": console.log("✅ Execution complete"); break;
  }
};

// Run code
ws.send(JSON.stringify({
  type: "run",
  session_id: sessionId,
  code: "name = input('Name: ')\nprint(f'Hi {name}!')"
}));

// Send interactive input (when prompted)
ws.send(JSON.stringify({
  type: "stdin",
  session_id: sessionId,
  input: "Alice"  // No \n needed
}));
```

### Python (`websockets` client)
```python
import asyncio, json, websockets

async def main():
    uri = "wss://<your-space>.hf.space"
    sid = "test-01"
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({
            "type": "run", "session_id": sid,
            "code": "import time\nfor i in range(3):\n  print(i)\n  time.sleep(1)"
        }))
        async for raw in ws:
            msg = json.loads(raw)
            print(f"[{msg['type']}] {msg.get('output', msg.get('message', ''))}")
            if msg["type"] == "done": break

asyncio.run(main())
```

---

## 🔍 Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `InvalidMessage` handshake errors | HF health probes hitting WS port | Already handled in server. Check `GET /health` returns `200`. |
| Output delayed/lagging | Client UI not processing fast enough | Normal. Backpressure throttles child process automatically. |
| `stdin` ignored | Client sent `\n` or wrong `session_id` | Send raw text only. Verify `session_id` matches active run. |
| Space sleeps after idle | HF free tier auto-suspends containers | Enable `Always On` (paid) or implement client-side ping/keepalive. |
| `SyntaxError` on startup | Newline corruption during copy-paste | Ensure hard returns after `session.proc.terminate()` and `async for` lines. |

---

This API is designed for **low-latency, single-user IDE workloads** on ephemeral infrastructure. If you need OpenAPI/Swagger generation, rate-limiting hooks, or orchestrator routing docs next, let me know.