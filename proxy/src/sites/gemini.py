from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from typing import Any, Callable
from urllib.parse import parse_qs, unquote

import magic
from mitmproxy import ctx, http
from mitmproxy.http import Response

from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between

SESSION_TTL: int = 600  # 10 minutes


class Gemini(Site):

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
            "Google Gemini", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        self.related_user_data: dict[str, dict[str, Any]] = {}
        self.related_file_data: dict[str, dict[str, Any]] = {}
        self._user_data_ts: dict[str, float] = {}
        self._file_data_ts: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale(), name="gemini-cleanup")

    async def _cleanup_stale(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            for ts_dict, data_dict in [
                (self._user_data_ts, self.related_user_data),
                (self._file_data_ts, self.related_file_data),
            ]:
                stale: list[str] = [k for k, ts in list(ts_dict.items()) if now - ts > SESSION_TTL]
                for k in stale:
                    data_dict.pop(k, None)
                    ts_dict.pop(k, None)

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "gemini.google.com/_/BardChatUi/data/assistant.lamda" in flow.request.pretty_url:
            ctx.log.info("Conversation!!!")
            if "f.req=" in flow.request.text:
                form_data: dict[str, list[str]] = parse_qs(flow.request.text)
                f_req_raw: str = form_data.get("f.req", [""])[0]
                ctx.log.info(f"f_req_raw: {f_req_raw}")

                decoded: str = unquote(f_req_raw)
                try:
                    parsed: Any = json.loads(decoded)
                    parsed = parsed[1]
                    parsed = json.loads(parsed)

                    conversation: str = parsed[0][0]
                    ctx.log.info(f'Conversation: {conversation}')

                    sid_cookie: str | None = flow.request.cookies.get("SID")

                    email: str | None = self.related_user_data.get(sid_cookie, {}).get("email", None)
                    ctx.log.info(f"Email: {email}")

                    if email and email != "":
                        if not await self.account_check_callback(email):
                            flow.response = Response.make(403)
                            return

                        await self.conversation_callback(email, conversation)

                    else:
                        if not await self.allow_anonymous_access():
                            flow.response = Response.make(403)
                            return

                        await self.anonymous_conversation_callback(conversation)

                except Exception as e:
                    ctx.log.error(f"Could not parse JSON: {e}\nDecoded String:\n{decoded}")


        elif flow.request.method == "POST" and "push.clients6.google.com/upload/" in flow.request.pretty_url:

            sid_cookie = flow.request.cookies.get("SID")
            content_type: str = flow.request.headers.get("Content-Type", "")

            if "application/x-www-form-urlencoded" in content_type:

                if flow.request.method == "POST" and "push.clients6.google.com/upload/?upload_id" in flow.request.pretty_url:

                    filename: str | None = self.related_file_data.get(sid_cookie, {}).get("filename", None)

                    if not filename:
                        ctx.log.error("Something went wrong retrieving filename")
                        return

                    file_content: bytes = flow.request.raw_content

                    mime: magic.Magic = magic.Magic(mime=True)
                    detected_type: str = mime.from_buffer(file_content)

                    unique_id: str = uuid.uuid4().hex
                    filepath: str = await self.store_file_callback(file_content)

                    email = self.related_user_data.get(sid_cookie, {}).get("email", None)
                    await self.attached_file_callback(email, filename, filepath, detected_type)
                    ctx.log.info(f"Saved PUT upload to: {filepath}")

                else:
                    raw_content: bytes = flow.request.raw_content
                    raw_text: str = raw_content.decode('utf-8', errors='ignore')
                    ctx.log.info(f"raw_text: {raw_text}")

                    match = re.search(r"File name:\s*(.*)", raw_text)
                    if match:
                        found_filename: str = match.group(1)
                        ctx.log.info(f"filename: {found_filename}")
                        self.related_file_data[sid_cookie] = {'filename': found_filename}
                        self._file_data_ts[sid_cookie] = time.time()

    async def on_response_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "GET" and "gemini.google.com/app" in flow.request.pretty_url:

            sid_cookie: str | None = flow.request.cookies.get("SID")

            html: str = flow.response.get_text()

            match = re.search(
                r'aria-label=\"[^\"]*?\(([^)]+)\)\"\shref=\"https:\/\/accounts\.google\.com\/SignOutOptions[^\"]*\"',
                html,
                re.DOTALL
            )
            if match:
                email: str = match.group(1)
                ctx.log.info(f"Extracted email: {email}")

                self.related_user_data[sid_cookie] = {'email': email}
                self._user_data_ts[sid_cookie] = time.time()

            else:
                ctx.log.info("No email found in anchor content.")
