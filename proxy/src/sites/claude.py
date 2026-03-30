from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site, ProxyCallbacks

SESSION_TTL: int = 3600  # 1 hour
PENDING_TTL: int = 120   # 2 minutes — max wait for the tree GET after a completion POST


class Claude(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("Claude", urls, callbacks)
        # Maps session cookie value → email
        self.sessions: dict[str, str] = {}
        self._sessions_ts: dict[str, float] = {}
        # Maps conversation_id → assistant_message_uuid (populated on POST, consumed on GET)
        self._pending_responses: dict[str, str] = {}
        self._pending_responses_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_sessions(), name="claude-cleanup")

    async def _cleanup_stale_sessions(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale_sessions: list[str] = [
                k for k, ts in list(self._sessions_ts.items()) if now - ts > SESSION_TTL
            ]
            for k in stale_sessions:
                self.sessions.pop(k, None)
                self._sessions_ts.pop(k, None)

            stale_pending: list[str] = [
                k for k, ts in list(self._pending_responses_ts.items()) if now - ts > PENDING_TTL
            ]
            for k in stale_pending:
                self._pending_responses.pop(k, None)
                self._pending_responses_ts.pop(k, None)

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

            # Store the expected assistant message UUID so we can fetch the response later
            turn_uuids: dict[str, Any] = req_body.get("turn_message_uuids", {})
            assistant_uuid: str | None = turn_uuids.get("assistant_message_uuid")
            if conversation_id and assistant_uuid:
                self._pending_responses[conversation_id] = assistant_uuid
                self._pending_responses_ts[conversation_id] = time.time()

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
            return

        # Intercept the conversation tree GET to capture the LLM response text
        if (
            flow.request.method == "GET"
            and "claude.ai/api/organizations/" in url
            and "/chat_conversations/" in url
            and "tree=True" in url
        ):
            conversation_id: str | None = self._extract_conversation_id(url)
            if not conversation_id:
                return

            assistant_uuid: str | None = self._pending_responses.pop(conversation_id, None)
            self._pending_responses_ts.pop(conversation_id, None)
            if not assistant_uuid:
                return

            if not flow.response:
                return
            content_type = flow.response.headers.get("Content-Type", "")
            if "application/json" not in content_type.lower():
                return

            try:
                resp_body: dict[str, Any] = json.loads(flow.response.content.decode("utf-8"))
            except Exception as e:
                ctx.log.error(f"[Claude] Failed to parse tree response: {e}")
                return

            for msg in resp_body.get("chat_messages", []):
                if msg.get("uuid") == assistant_uuid and msg.get("sender") == "assistant":
                    response_text: str = "".join(
                        c.get("text", "")
                        for c in msg.get("content", [])
                        if c.get("type") == "text"
                    ).strip()
                    if response_text:
                        ctx.log.info(f"[Claude] Captured response for conversation {conversation_id}")
                        await self.update_response_callback(
                            conversation_id, assistant_uuid, response_text
                        )
                    break
