from __future__ import annotations

import asyncio
import os
import pty
import fcntl
import termios
import signal
import struct
import threading
import json
from typing import Any

import jwt
import websockets


def set_pty_winsize(fd: int, rows: int, cols: int) -> None:
    winsize: bytes = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def spawn_pty_shell(argv: list[str] | None = None) -> tuple[int, int]:
    if argv is None:
        #argv = ["/bin/bash", "--login"]
        argv = ["tmux", "attach-session", "-t", "mitmsession"]
    pid: int
    master_fd: int
    pid, master_fd = pty.fork()
    if pid == 0:                      # ── Child: exec bash ──
        os.execvp(argv[0], argv)
    else:                             # ── Parent: master FD
        # non-blocking master fd
        flags: int = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        return pid, master_fd


async def pty_session(websocket: Any) -> None:
    child_pid: int
    master_fd: int
    child_pid, master_fd = spawn_pty_shell()
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    stop_event: asyncio.Event = asyncio.Event()
    try:
        cookies_header: str = websocket.request.headers.get('Cookie')
        cookies: dict[str, str] = dict(item.strip().split("=", 1) for item in cookies_header.split(";"))

        secret_key: str | None = os.getenv("JWT_SECRET")
        payload: dict[str, Any] = jwt.decode(cookies['token'], secret_key, algorithms=["HS256"])

        if not 'permissions' in payload or 'mitmterminal' not in payload['permissions']:
            return

    except jwt.ExpiredSignatureError:
        print("Token has expired.")     #If token expired, then return
        return
    except jwt.InvalidTokenError:
        print("Invalid token.")     #If token invalid, then return
        return
    except Exception as e:
        print("Exception:", e)
        return


    async def pty_to_ws() -> None:
        try:
            while not stop_event.is_set():
                # Wait until the fd is readable without blocking the loop
                await loop.run_in_executor(None, lambda: os.read(master_fd, 0))
                try:
                    data: bytes = os.read(master_fd, 4096)
                    #print(f"Received data: {data}")
                    if data:
                        await websocket.send(data)   # send as binary frame
                    else:            # EOF
                        stop_event.set()
                except BlockingIOError:
                    await asyncio.sleep(0.01)
        finally:
            stop_event.set()

    async def ws_to_pty() -> None:
        try:
            async for msg in websocket:
                if isinstance(msg, str):
                    try:
                        data: dict[str, Any] = json.loads(msg)
                        if isinstance(data, dict) and data.get("type") == "resize":
                            set_pty_winsize(master_fd, int(data["rows"]), int(data["cols"]))
                            continue
                    except Exception:
                        pass

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


def run_ws_server(host: str = '0.0.0.0', port: int = 8765) -> None:
    async def start_server() -> None:
        async with websockets.serve(pty_session, host, port):
            print(f"WebSocket server running at ws://{host}:{port}")
            await asyncio.Future()  # Keep the server running

    loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())


def launch_ws_term() -> None:
    ws_thread: threading.Thread = threading.Thread(target=run_ws_server, daemon=True, name="WS-Server")
    ws_thread.start()
