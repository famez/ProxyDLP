from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site, parse_multipart

SESSION_TTL: int = 600  # 10 minutes


class BlackBox(Site):

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
            "BlackBox", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        self.sessions: dict[str, dict[str, Any]] = {}
        self.workspaces: dict[str, list[dict[str, Any]]] = {}
        self._sessions_ts: dict[str, float] = {}
        self._workspaces_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale(), name="blackbox-cleanup")

    async def _cleanup_stale(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            for ts_dict, data_dict in [
                (self._sessions_ts, self.sessions),
                (self._workspaces_ts, self.workspaces),
            ]:
                stale: list[str] = [k for k, ts in list(ts_dict.items()) if now - ts > SESSION_TTL]
                for k in stale:
                    data_dict.pop(k, None)
                    ts_dict.pop(k, None)

    async def on_request_handle(self, flow: HTTPFlow) -> None:

        if flow.request.method == "POST" and "blackbox.ai/api/chat" in flow.request.pretty_url:

            content_type: str = flow.request.headers.get("Content-Type", "")
            email: str | None = None

            if not "application/json" in content_type.lower():
                return

            try:
                json_body: dict[str, Any] = flow.request.json()

                session: Any = json_body.get('session')
                if isinstance(session, dict):
                    user: Any = session.get('user')
                    if isinstance(user, dict):
                        email = user.get('email')

                if not email:
                    if not await self.allow_anonymous_access():
                        flow.response = Response.make(401)
                        return
                else:
                    if not await self.account_check_callback(email):
                        flow.response = Response.make(401)
                        return

                if not "messages" in json_body:
                    return

                conversation_id: str | None = json_body.get("id", None)

                for message in reversed(json_body['messages']):
                    if 'role' in message and message['role'] == "user" and 'content' in message:
                        if email:
                            session_id: str = json_body['id']
                            results: list[str] = [item for item in self.sessions if session_id in item]

                            if results:
                                self.sessions[session_id]['email'] = email
                                ctx.log.info("Added session 1")
                            else:
                                self.sessions[session_id] = {'email': email}
                                ctx.log.info("Added session 2")
                            self._sessions_ts[session_id] = time.time()

                            await self.conversation_callback(
                                json_body['session']['user']['email'],
                                message['content'],
                                conversation_id=conversation_id,
                            )
                        else:
                            await self.anonymous_conversation_callback(message['content'], conversation_id=conversation_id)
                        break

            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        elif flow.request.method == "POST" and "blackbox.ai/api/workspace/link-to-chat" in flow.request.pretty_url:
            json_body = flow.request.json()
            ctx.log.info(f"json_body: {json.dumps(json_body, indent=2)}")

            session_id = json_body['chatId']
            workspace_id: str = json_body['workspaceIds'][0]

            ctx.log.info(f"session id: {session_id}, workspace_id: {workspace_id}")

            for session in self.sessions:
                ctx.log.info(f"Session: {str(session)}")

            if session_id in self.sessions:
                self.sessions[session_id]['workspace'] = json_body['workspaceIds'][0]
                ctx.log.info(f"Eeeeooo")

                linked_email: str | None = None
                if "email" in self.sessions[session_id]:
                    linked_email = self.sessions[session_id]['email']

                if workspace_id in self.workspaces:
                    self.sessions[session_id]['files'] = self.workspaces[workspace_id]
                    ctx.log.info("Session...")
                    ctx.log.info(str(self.sessions[session_id]))

                    for file in self.sessions[session_id]['files']:
                        await self.attached_file_callback(linked_email, file['filename'], file['filepath'], file['content_type'])


    async def on_response_handle(self, flow: HTTPFlow) -> None:

        if flow.request.method == "POST" and "https://www.blackbox.ai/api/workspace" == flow.request.pretty_url:

            workspace_id: str | None = None
            response_content_type: str = flow.response.headers.get("Content-Type", "")
            ctx.log.info("Eooooo one two three")

            if "application/json" in response_content_type.lower():
                try:
                    content: dict[str, Any] = flow.response.json()
                    ctx.log.info("Hellooo")

                    if "id" in content:
                        workspace_id = content["id"]
                        self.workspaces[workspace_id] = []
                        self._workspaces_ts[workspace_id] = time.time()

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

            req_content_type: str = flow.request.headers.get("content-type", "")

            if "multipart/form-data" in req_content_type:
                body: bytes = flow.request.raw_content
                uploaded_files: list[dict[str, Any]] = parse_multipart(req_content_type, body)

                for file in uploaded_files:
                    filepath: str = await self.store_file_callback(file['content'])
                    ctx.log.info(f"Saved file: {filepath}")

                    self.workspaces[workspace_id].append({
                        "filename": file['filename'],
                        "filepath": filepath,
                        "content_type": file['content_type'],
                    })
                    ctx.log.info("Adding workspace!!!")
