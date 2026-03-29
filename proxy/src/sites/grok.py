from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site, parse_multipart, decode_jwt

SESSION_TTL: int = 600  # 10 minutes


class Grok(Site):

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
            "Grok", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        self.users: dict[str, dict[str, str]] = {}
        self._users_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_users(), name="grok-cleanup")

    async def _cleanup_stale_users(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [k for k, ts in list(self._users_ts.items()) if now - ts > SESSION_TTL]
            for k in stale:
                self.users.pop(k, None)
                self._users_ts.pop(k, None)

    async def on_request_handle(self, flow: HTTPFlow) -> None:
        ctx.log.info(f"[Info] Handling request: {flow.request.method} {flow.request.pretty_url}")

        sso_cookie: str | None = flow.request.cookies.get("sso")
        session_id: str | None = None

        ctx.log.debug(f"[Debug] sso_cookie: {sso_cookie}")

        if sso_cookie:
            jwt_data: dict[str, Any] | None = decode_jwt(sso_cookie)
            ctx.log.debug(f"[Debug] jwt_data: {jwt_data}")

            if jwt_data:
                jwt_payload: dict[str, Any] = jwt_data['payload']
                ctx.log.debug(f"[Debug] jwt_payload: {jwt_payload}")

                if "session_id" in jwt_payload:
                    session_id = jwt_payload['session_id']
                    ctx.log.info(f"[Info] session_id extracted: {session_id}")

        if flow.request.method == "POST" and "grok.com/api/statsig/log_event" in flow.request.pretty_url:

            json_body: dict[str, Any] | None = None

            if flow.request.headers.get("content-type", "").startswith("text/plain"):
                try:
                    json_body = json.loads(flow.request.get_text())
                    ctx.log.debug(f"[Debug] statsig log_event json_body: {json_body}")
                except Exception as e:
                    ctx.log.warn(f"[Warn] Failed to decode text/plain as JSON: {e}")
                    return
            else:
                json_body = flow.request.json()
                ctx.log.debug(f"[Debug] statsig log_event json_body: {json_body}")

            if json_body:
                email: str | None = None
                for event in json_body.get('events', []):
                    user: dict[str, Any] = event.get('user', {})
                    email = user.get('email')
                    if email and session_id:
                        ctx.log.info(f"[Info] Extracted email from statsig log_event: {email}")
                        self.users[session_id] = {'email': email}
                        self._users_ts[session_id] = time.time()
                        ctx.log.info(f"[Info] Stored user: session_id={session_id}, email={email}")
                        break


        elif flow.request.method == "POST" and "grok.com/_data/v1/events" in flow.request.pretty_url:
            ctx.log.info("[Info] Processing events endpoint")

            json_body = flow.request.json()
            ctx.log.debug(f"[Debug] events json_body: {json_body}")

            events_email: str | None = json_body.get("viewer_context", {}).get("user_attributes", {}).get("email", None)
            ctx.log.info(f"[Info] Extracted email: {events_email}")

            if events_email and session_id:
                self.users[session_id] = {'email': events_email}
                ctx.log.info(f"[Info] Stored user: session_id={session_id}, email={events_email}")

        elif flow.request.method == "POST" and "grok.com/rest/app-chat/conversations" in flow.request.pretty_url:
            ctx.log.info("[Info] Processing conversations endpoint")

            json_body = flow.request.json()
            ctx.log.debug(f"[Debug] conversations json_body: {json_body}")

            conv_email: str | None = self.users.get(session_id, {}).get("email", None)
            ctx.log.info(f"[Info] Retrieved email for session: {conv_email}")

            if "message" in json_body:
                conversation: str = json_body['message']
                ctx.log.info(f"[Info] Extracted conversation: {conversation}")

                if conv_email:
                    if not await self.account_check_callback(conv_email):
                        ctx.log.warn(f"[Warn] Account check failed for email: {conv_email}")
                        flow.response = Response.make(401)
                        return
                    ctx.log.info(f"[Info] Account check passed for email: {conv_email}")
                    await self.conversation_callback(conv_email, conversation)
                else:
                    if not await self.allow_anonymous_access():
                        ctx.log.warn(f"[Warn] Anonymous access not allowed")
                        flow.response = Response.make(401)
                        return
                    ctx.log.info("[Info] Anonymous access allowed")
                    await self.anonymous_conversation_callback(conversation)
