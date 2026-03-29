from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Callable

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site

SESSION_TTL: int = 3600  # 1 hour


class Claude(Site):

    def __init__(
        self,
        urls: list[str],
        account_login_callback: Callable[..., Any],
        account_check_callback: Callable[..., Any],
        conversation_callback: Callable[..., Any],
        attached_file_callback: Callable[..., Any],
        allow_anonymous_access: Callable[..., Any],
        anonymous_conversation_callback: Callable[..., Any],
        store_file_callback: Callable[..., Any],
    ) -> None:
        super().__init__(
            "Claude", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        # Maps session cookie value → email
        self.sessions: dict[str, str] = {}
        self._sessions_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_sessions(), name="claude-cleanup")

    async def _cleanup_stale_sessions(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [k for k, ts in list(self._sessions_ts.items()) if now - ts > SESSION_TTL]
            for k in stale:
                self.sessions.pop(k, None)
                self._sessions_ts.pop(k, None)

    def _get_session_key(self, flow: HTTPFlow) -> str | None:
        """Extract the sessionKey cookie value from the request."""
        cookies_header: str = flow.request.headers.get("Cookie", "")
        for part in cookies_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name.strip() == "sessionKey":
                return value.strip()
        return None

    def _extract_conversation_id(self, url: str) -> str | None:
        """Extract conversation UUID from a Claude API URL."""
        match = re.search(r"/chat_conversations/([^/?]+)", url)
        if match:
            return match.group(1)
        return None

    async def on_request_handle(self, flow: HTTPFlow) -> None:
        url: str = flow.request.pretty_url

        # Intercept POST completion to capture the user prompt and enforce access control
        if (
            flow.request.method == "POST"
            and "claude.ai/api/organizations/" in url
            and "/chat_conversations/" in url
            and url.endswith("/completion")
        ):
            try:
                req_body: dict[str, Any] = flow.request.json()
            except Exception as e:
                ctx.log.error(f"[Claude] Failed to parse completion request body: {e}")
                return

            prompt: str = req_body.get("prompt", "")
            if not prompt:
                return

            conversation_id: str | None = self._extract_conversation_id(url)
            session_key: str | None = self._get_session_key(flow)

            if session_key and session_key in self.sessions:
                email: str = self.sessions[session_key]
                self._sessions_ts[session_key] = time.time()  # refresh TTL

                if not await self.account_check_callback(email):
                    ctx.log.info(f"[Claude] Blocking unauthorized user: {email}")
                    flow.response = Response.make(
                        403,
                        b"Blocked by proxy",
                        {"Content-Type": "text/plain"},
                    )
                    return

                ctx.log.info(f"[Claude] Logging conversation for {email}")
                await self.conversation_callback(email, prompt, conversation_id)

            elif await self.allow_anonymous_access():
                ctx.log.info("[Claude] Logging anonymous conversation")
                await self.anonymous_conversation_callback(prompt, conversation_id)

            else:
                ctx.log.info("[Claude] No session found and anonymous access disabled — blocking")
                flow.response = Response.make(
                    403,
                    b"Blocked by proxy",
                    {"Content-Type": "text/plain"},
                )

    async def on_response_handle(self, flow: HTTPFlow) -> None:
        url: str = flow.request.pretty_url

        # Capture the user's email when the account profile endpoint is loaded
        if flow.request.method == "GET" and "claude.ai/api/account" in url:
            if not flow.response:
                return
            content_type: str = flow.response.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                return
            try:
                resp: dict[str, Any] = json.loads(flow.response.content.decode("utf-8"))
                email: str | None = resp.get("email")
                if email:
                    session_key: str | None = self._get_session_key(flow)
                    if session_key:
                        if session_key not in self.sessions:
                            ctx.log.info(f"[Claude] Mapped session to {email}")
                            if not await self.account_login_callback(email):
                                # User not allowed — let the login proceed but session won't be trusted
                                return
                        self.sessions[session_key] = email
                        self._sessions_ts[session_key] = time.time()
            except Exception as e:
                ctx.log.error(f"[Claude] Failed to parse account response: {e}")
