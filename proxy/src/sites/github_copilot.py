from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from mitmproxy import ctx, http

from proxy import Site, ProxyCallbacks, EmailNotFoundException, decode_jwt, extract_substring_between

SESSION_TTL: int = 600  # 10 minutes


class Github_Copilot(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("Github Copilot", urls, callbacks)
        self.related_user_data: dict[str, dict[str, Any]] = {}
        self._related_user_data_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale(), name="gh-copilot-cleanup")

    async def _cleanup_stale(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [k for k, ts in list(self._related_user_data_ts.items()) if now - ts > SESSION_TTL]
            for k in stale:
                self.related_user_data.pop(k, None)
                self._related_user_data_ts.pop(k, None)

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "githubcopilot.com/chat/completions" in flow.request.pretty_url:
            ctx.log.info(f"Request URL: {flow.request.pretty_url}")

            try:
                json_body: dict[str, Any] = flow.request.json()

                if 'messages' in json_body:
                    messages: list[dict[str, Any]] = json_body['messages']
                    for message in reversed(messages):
                        if 'role' in message and message['role'] == 'user':
                            if 'content' in message:
                                prompt: str = message['content']

                                if prompt:
                                    ctx.log.info(f"Prompt found: {prompt}")

                                    ip_address: str = flow.client_conn.address[0]

                                    login: str | None = self.related_user_data.get(ip_address, {}).get("login", None)
                                    if login:
                                        await self.conversation_callback(login, prompt)
                                    else:
                                        await self.anonymous_conversation_callback(prompt)

                                break
                            else:
                                ctx.log.error("User message content not found.")
                        else:
                            ctx.log.error("User role not found in the message.")

            except json.JSONDecodeError:
                ctx.log.info(f"Request body could not be decoded as JSON")


    async def on_response_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "GET" and "api.github.com/user" in flow.request.pretty_url:

            ip_address: str = flow.client_conn.address[0]
            if "application/json" in flow.response.headers.get("content-type", ""):
                try:
                    json_body: dict[str, Any] = json.loads(flow.response.get_text())
                    if 'login' in json_body:
                        user_login: str = json_body['login']
                        ctx.log.info(f"User login: {user_login}")

                        self.related_user_data[ip_address] = {"login": user_login}
                        self._related_user_data_ts[ip_address] = time.time()

                except json.JSONDecodeError:
                    print("Failed to decode JSON.")
