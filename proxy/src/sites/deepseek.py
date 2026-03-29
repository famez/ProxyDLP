from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site, parse_multipart

SESSION_TTL: int = 600  # 10 minutes


class DeepSeek(Site):

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
            "DeepSeek", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        self.users: dict[str, str] = {}
        self._users_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_users(), name="deepseek-cleanup")

    async def _cleanup_stale_users(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [k for k, ts in list(self._users_ts.items()) if now - ts > SESSION_TTL]
            for k in stale:
                self.users.pop(k, None)
                self._users_ts.pop(k, None)

    async def on_request_handle(self, flow: HTTPFlow) -> None:

        if flow.request.method == "POST" and "deepseek.com/api/v0/chat/completion" in flow.request.pretty_url:

            auth_header: str | None = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                auth_header = auth_header[len("Bearer "):].strip()

            json_body: dict[str, Any] = flow.request.json()

            if "prompt" in json_body:
                conversation: str = json_body['prompt']

                if auth_header in self.users:
                    if not await self.account_check_callback(self.users[auth_header]):
                        flow.response = Response.make(401)
                        return

                    chat_session_id: str | None = json_body.get("chat_session_id")
                    await self.conversation_callback(self.users[auth_header], conversation, conversation_id=chat_session_id)


        elif flow.request.method == "POST" and "deepseek.com/api/v0/file/upload_file" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                auth_header = auth_header[len("Bearer "):].strip()

            content_type: str = flow.request.headers.get("content-type", "")

            if "multipart/form-data" in content_type:
                body: bytes = flow.request.raw_content
                uploaded_files: list[dict[str, Any]] = parse_multipart(content_type, body)

                for file in uploaded_files:
                    filepath: str = await self.store_file_callback(file['content'])

                    if auth_header in self.users:
                        await self.attached_file_callback(self.users[auth_header], file['filename'], filepath, file['content_type'])

        elif flow.request.method == "POST" and "chat.deepseek.com/api/v0/users/login" in flow.request.pretty_url:

            req_content_type: str = flow.request.headers.get("Content-Type", "")

            if not "application/json" in req_content_type.lower():
                return

            try:
                json_body = flow.request.json()

                if not 'email' in json_body:
                    return

                email: str = json_body['email']

                if not await self.account_login_callback(email):
                    flow.response = Response.make(401)
                    return

            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")


    async def on_response_handle(self, flow: HTTPFlow) -> None:

        if flow.request.method == "GET" and "deepseek.com/api/v0/users/current" in flow.request.pretty_url:

            auth_header: str | None = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                auth_header = auth_header[len("Bearer "):].strip()

            content_type: str = flow.response.headers.get("Content-Type", "")

            if "application/json" in content_type.lower():
                try:
                    content: dict[str, Any] = json.loads(flow.response.content.decode('utf-8'))

                    if "data" in content and "biz_data" in content['data'] and "email" in content['data']['biz_data']:
                        email: str = content['data']['biz_data']['email']

                        if not auth_header in self.users:
                            self.users[auth_header] = email
                            self._users_ts[auth_header] = time.time()

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")


        elif flow.request.method == "POST" and "chat.deepseek.com/api/v0/users/login" in flow.request.pretty_url:

            req_content_type: str = flow.request.headers.get("Content-Type", "")

            if not "application/json" in req_content_type.lower():
                return

            try:
                req_json: dict[str, Any] = flow.request.json()

                if not 'email' in req_json:
                    return

                email = req_json['email']

                resp_content_type: str = flow.response.headers.get("Content-Type", "")

                if not "application/json" in resp_content_type.lower():
                    return

                resp_json: dict[str, Any] = flow.response.json()

                if ('data' in resp_json and 'biz_data' in resp_json['data']
                        and 'user' in resp_json['data']['biz_data']
                        and 'token' in resp_json['data']['biz_data']['user']):
                    token: str = resp_json['data']['biz_data']['user']['token']
                    self.users[token] = email
                    self._users_ts[token] = time.time()

            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")
