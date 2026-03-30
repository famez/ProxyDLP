from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from io import BytesIO
from typing import Any
from urllib.parse import urlparse, parse_qs

import magic
from mitmproxy import ctx, http
from mitmproxy.http import Response
from mitmproxy import websocket

from proxy import Site, ProxyCallbacks, EmailNotFoundException, decode_jwt, pad_b64

UPLOAD_TTL: int = 300  # seconds before a stale upload buffer is evicted

class Microsoft_Copilot(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("Microsoft Copilot", urls, callbacks)
        self.uploaded_files: dict[str, dict[str, Any]] = {}
        self._upload_timestamps: dict[str, float] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_uploads(), name="ms-copilot-cleanup")

    async def _cleanup_stale_uploads(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            async with self._lock:
                stale: list[str] = [email for email, ts in self._upload_timestamps.items() if now - ts > UPLOAD_TTL]
                for email in stale:
                    self.uploaded_files.pop(email, None)
                    self._upload_timestamps.pop(email, None)
                    ctx.log.info(f"Evicted stale upload buffer for: {email}")

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "PUT" and "sharepoint.com/personal" in flow.request.pretty_url and "uploadSession" in flow.request.pretty_url:
            ctx.log.info(f"Handling PUT request for SharePoint uploadSession: {flow.request.pretty_url}")

            tempauth: str | None = flow.request.query.get("tempauth")
            user_email: str | None = extract_email_from_tempauth(tempauth)

            if not user_email or not await self.account_check_callback(user_email):
                ctx.log.warn(f"User email invalid or not allowed: {user_email}")
                flow.response = Response.make(403, b"Blocked by proxy", {"Content-Type": "text/plain"})
                return

            content_type: str = flow.request.headers.get("Content-Type", "")
            ctx.log.debug(f"Content-Type of request: {content_type}")

            if "application/octet-stream" in content_type:
                content_range: str = flow.request.headers.get("Content-Range", "")
                ctx.log.debug(f"Content-Range of request: {content_range}")

                start: int = 0
                end: int = 0
                total: int = 0
                match = re.match(r"bytes (\d+)-(\d+)/(\d+)", content_range)
                if match:
                    start = int(match.group(1))
                    end = int(match.group(2))
                    total = int(match.group(3))

                async with self._lock:
                    entry: dict[str, Any] | None = self.uploaded_files.get(user_email)

                if entry is not None:
                    ctx.log.info(f"Handling in-memory upload for user: {user_email}")

                    async with self._lock:
                        buf: bytearray | None = entry.get('filecontent')
                        if start == 0 or buf is None:
                            buf = bytearray()
                            entry['filecontent'] = buf
                            ctx.log.debug(f"Initialized in-memory buffer for user {user_email}")

                        if start > len(buf):
                            buf.extend(b'\x00' * (start - len(buf)))

                        chunk: bytes = flow.request.raw_content
                        buf[start:start + len(chunk)] = chunk
                        ctx.log.info(f"In-memory chunk written for {user_email}: {start}-{end} (total {total}), buffer size now {len(buf)}")

                    if end + 1 == total:
                        async with self._lock:
                            buf_snapshot: bytes = bytes(buf)
                            filename: str = entry['filename']
                            self.uploaded_files.pop(user_email, None)
                            self._upload_timestamps.pop(user_email, None)

                        try:
                            mime: magic.Magic = magic.Magic(mime=True)
                            content_type_detected: str = mime.from_buffer(buf_snapshot)
                        except Exception as e:
                            ctx.log.warn(f"Failed to detect MIME type from buffer: {e}")
                            content_type_detected = "application/octet-stream"

                        filepath: str = await self.store_file_callback(buf_snapshot)
                        await self.attached_file_callback(user_email, filename, filepath, content_type_detected)
                        ctx.log.info(f"Completed in-memory upload and removed entry for user: {user_email}")
                else:
                    ctx.log.warn(f"No uploaded_files entry found for user: {user_email}")

    async def on_response_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:" in flow.request.pretty_url:

            req_content_type: str = flow.request.headers.get("Content-Type", "")
            req_content: dict[str, Any] = flow.request.json()
            filename: str | None = req_content.get("item", {}).get("name", None)
            ctx.log.info(f"File name: {filename}")

            resp_content_type: str = flow.response.headers.get("Content-Type", "")

            if "application/json" in resp_content_type.lower():
                try:
                    resp_content: dict[str, Any] = json.loads(flow.response.content.decode('utf-8'))
                    upload_url: str | None = resp_content.get('uploadUrl')

                    tempauth: str | None = None
                    if upload_url:
                        parsed_url = urlparse(upload_url)
                        query_params: dict[str, list[str]] = parse_qs(parsed_url.query)
                        tempauth = query_params.get("tempauth", [None])[0]

                    if tempauth:
                        email: str | None = extract_email_from_tempauth(tempauth)
                        ctx.log.info(f"Email: {email}")
                        async with self._lock:
                            self.uploaded_files[email] = {"filename": filename}
                            self._upload_timestamps[email] = time.time()

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")


    async def on_ws_from_client_to_server(
        self, flow: http.HTTPFlow, message: websocket.WebSocketMessage
    ) -> None:

        if flow.request.method == "GET" and "copilot.microsoft.com/c/api/chat" in flow.request.pretty_url:

            email: str | None = None
            auth_query_param: str = flow.request.query.get("accessToken", "")

            if auth_query_param == "":
                if not await self.allow_anonymous_access():
                    message.kill()
                    return
            else:
                try:
                    jwt_token: str = auth_query_param.strip()
                    jwt_data: dict[str, Any] | None = decode_jwt(jwt_token)

                    if jwt_data:
                        jwt_payload: dict[str, Any] = jwt_data['payload']

                        if "email" in jwt_payload:
                            email = jwt_payload['email']

                            if not await self.account_check_callback(email):
                                message.kill()
                                return

                except EmailNotFoundException as e:
                    ctx.log.error(f"Email not properly decoded: {e}")

            try:
                json_content: dict[str, Any] = json.loads(message.content.decode('utf-8'))

                if "event" in json_content and json_content['event'] == "send" and "content" in json_content:
                    messages: list[dict[str, Any]] = json_content['content']
                    for msg in messages:
                        if msg['type'] == 'text':
                            if email:
                                await self.conversation_callback(email, msg['text'])
                            else:
                                await self.anonymous_conversation_callback(msg['text'])

            except Exception as e:
                ctx.log.error(f"Failed to decode JSON from message.content: {e}")


        elif flow.request.method == "GET" and "substrate.office.com/m365Copilot/Chathub" in flow.request.pretty_url:

            auth_query_param = flow.request.query.get("access_token", "")
            conversationId: str | None = flow.request.query.get("ConversationId", None)

            try:
                ws_email: str = get_email_from_auth_header(auth_query_param)

                if await self.account_check_callback(ws_email):
                    ctx.log.info(f"Email address belongs to the organization")

                    message_contents: list[bytes] = message.content.split(b'\x1e')
                    message_contents = [part for part in message_contents if part]
                    json_messages: list[dict[str, Any]] = [json.loads(part.decode('utf-8')) for part in message_contents]

                    for json_content in json_messages:
                        if "arguments" in json_content:
                            for argument in json_content["arguments"]:
                                if "message" in argument and "text" in argument["message"]:
                                    conversation_text: str = argument["message"]["text"]
                                    await self.conversation_callback(ws_email, conversation_text, conversationId)

                    return

            except EmailNotFoundException as e:
                ctx.log.error(f"Email not properly decoded: {e}")

            ctx.log.info("JWT token checks failed!")
            message.kill()


def get_email_from_auth_header(auth_query_param: str) -> str:
    if auth_query_param:
        jwt_token: str = auth_query_param.strip()
        jwt_data: dict[str, Any] | None = decode_jwt(jwt_token)

        if jwt_data:
            jwt_payload: dict[str, Any] = jwt_data['payload']

            if "unique_name" in jwt_payload:
                email: str = jwt_payload["unique_name"]
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")


def decode_special_microsoft_token(token: str) -> dict[str, Any] | None:
    parts: list[str] = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header: dict[str, Any] = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())

        encoded_payload: str = parts[1].strip().split(".")[0]
        missing_padding: int = len(encoded_payload) % 4
        if missing_padding:
            encoded_payload += "=" * (4 - missing_padding)

        raw_payload: bytes = base64.urlsafe_b64decode(encoded_payload)
        payload_text: str = raw_payload.decode('latin1', errors='ignore')

        patterns: dict[str, str] = {
            "Emails": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "UUIDs": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            "IP addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Readable strings": r"[a-zA-Z0-9\.\-_\@\s]{4,}",
        }

        payload_strings: dict[str, list[str]] = {}
        for name, pattern in patterns.items():
            matches: list[str] = re.findall(pattern, payload_text)
            payload_strings[name] = list(set(matches))

        return {"header": header, "payload_strings": payload_strings}

    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None


def extract_email_from_tempauth(tempauth: str | None) -> str | None:
    ctx.log.debug(f"tempauth query param: {tempauth}")

    if tempauth and tempauth.startswith("v1."):
        tempauth = tempauth.removeprefix("v1.")
        ctx.log.debug(f"tempauth after removing prefix: {tempauth}")

        decoded: dict[str, Any] | None = decode_special_microsoft_token(tempauth)
        ctx.log.debug(f"Decoded tempauth token: {decoded}")

        if not decoded:
            ctx.log.error("Failed to decode tempauth token")
            return None

        if "app_displayname" in decoded['header']:
            ctx.log.debug(f"app_displayname in header: {decoded['header']['app_displayname']}")
        if (
            "app_displayname" in decoded['header']
            and decoded['header']["app_displayname"] == "M365ChatClient"
            and 'Emails' in decoded['payload_strings']
            and len(decoded['payload_strings']['Emails']) > 0
        ):
            emails: list[str] = decoded['payload_strings']['Emails']
            ctx.log.info(f"Emails extracted from payload: {emails}")

            for email in emails:
                if not 'live.comz' in email:
                    ctx.log.info(f"Email extracted from tempauth: {email}")
                    return email

    return None
