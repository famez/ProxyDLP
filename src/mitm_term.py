import asyncio
import os, pty, fcntl, termios, signal, sys
import threading
import websockets

# ── 1. Your async handler ──────────────────────────────────────────────────────
async def echo(websocket, path):
    """
    Echo every message back to the client, prefixing it for clarity.
    """
    async for msg in websocket:
        await websocket.send(f"Echo: {msg}")

# ──────────────────────────────────────────────────────────────────────────────
# Low-level helper: spawn bash in a new PTY and return (child_pid, master_fd)
# ──────────────────────────────────────────────────────────────────────────────
def spawn_pty_shell(argv: list[str] | None = None):
    if argv is None:
        #argv = ["/bin/bash", "--login"]
        argv = ["tmux", "attach-session", "-t", "mysession"]
    pid, master_fd = pty.fork()
    if pid == 0:                      # ── Child: exec bash ──
        os.execvp(argv[0], argv)
    else:                             # ── Parent: master FD
        # non-blocking master fd
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        return pid, master_fd

# ──────────────────────────────────────────────────────────────────────────────
# Per-connection handler
# ──────────────────────────────────────────────────────────────────────────────
async def pty_session(websocket):
    child_pid, master_fd = spawn_pty_shell()
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    async def pty_to_ws():
        try:
            while not stop_event.is_set():
                # Wait until the fd is readable without blocking the loop
                await loop.run_in_executor(None, lambda: os.read(master_fd, 0))
                try:
                    data = os.read(master_fd, 4096)
                    #print(f"Received data: {data}")
                    if data:
                        await websocket.send(data)   # send as binary frame
                    else:            # EOF
                        stop_event.set()
                except BlockingIOError:
                    await asyncio.sleep(0.01)
        finally:
            stop_event.set()

    async def ws_to_pty():
        try:
            async for msg in websocket:
                if isinstance(msg, str):
                    #print(f"Received message {msg}")
                    os.write(master_fd, msg.encode())
                else:                # already bytes
                    os.write(master_fd, msg)
        finally:
            stop_event.set()

    # Run both directions concurrently until one ends
    await asyncio.gather(pty_to_ws(), ws_to_pty(), return_exceptions=True)

    # Cleanup
    try:
        os.kill(child_pid, signal.SIGHUP)
    except ProcessLookupError:
        pass
    os.close(master_fd)

# ── 2. The thread target: create *its own* event-loop ──────────────────────────
def run_ws_server(host='0.0.0.0', port=8765):
    async def echo(websocket):
        async for msg in websocket:
            await websocket.send(f"Echo: {msg}")

    async def start_server():
        async with websockets.serve(pty_session, host, port):
            print(f"WebSocket server running at ws://{host}:{port}")
            await asyncio.Future()  # Keep the server running

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())


def launch_ws_term():
    # ── 3. Kick off the server in a daemon thread ─────────────────────────────────
    ws_thread = threading.Thread(target=run_ws_server, daemon=True, name="WS-Server")
    ws_thread.start()