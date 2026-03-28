from __future__ import annotations

import json
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable

from mitmproxy import ctx
from mitmproxy.http import Response, HTTPFlow

from proxy import Site, parse_multipart

SESSION_TTL: int = 600  # 10 minutes


class Perplexity(Site):

    def __init__(
        self,
        urls: list[str],
        account_login_callback: Callable[..., bool],
        account_check_callback: Callable[..., bool],
        conversation_callback: Callable[..., None],
        attached_file_callback: Callable[..., None],
        allow_anonymous_access: Callable[..., bool],
        anonymous_conversation_callback: Callable[..., None],
        store_file_callback: Callable[..., str],
    ) -> None:
        super().__init__(
            "Perplexity", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )
        self.related_user_data: dict[str, dict[str, Any]] = {}
        self.file_data: dict[str, dict[str, Any]] = {}
        self._user_data_ts: dict[str, float] = {}
        self._file_data_ts: dict[str, float] = {}
        threading.Thread(target=self._cleanup_stale, daemon=True, name="perplexity-cleanup").start()

    def _cleanup_stale(self) -> None:
        while True:
            time.sleep(60)
            now: float = time.time()
            for ts_dict, data_dict in [
                (self._user_data_ts, self.related_user_data),
                (self._file_data_ts, self.file_data),
            ]:
                stale: list[str] = [k for k, ts in list(ts_dict.items()) if now - ts > SESSION_TTL]
                for k in stale:
                    data_dict.pop(k, None)
                    ts_dict.pop(k, None)

    def on_response_handle(self, flow: HTTPFlow) -> None:

        conversation_id: str | None = None

        if flow.request.method == "POST" and "perplexity.ai/rest/sse/perplexity_ask" in flow.request.pretty_url:

            if flow.response and flow.response.headers.get("Content-Type", "").startswith("text/event-stream"):
                try:
                    event_data: str = flow.response.text
                    for line in event_data.splitlines():
                        if line.startswith("data:"):
                            data: str = line[len("data:"):].strip()
                            if data and data != "[DONE]":
                                try:
                                    event: dict[str, Any] = json.loads(data)
                                    if "context_uuid" in event:
                                        conversation_id = event['context_uuid']
                                        break
                                except Exception as e:
                                    ctx.log.error(f"Failed to parse event data: {e}")
                except Exception as e:
                    ctx.log.error(f"Error parsing text/event-stream: {e}")

            try:
                json_body: dict[str, Any] = flow.request.json()
                ctx.log.info(f"[Debug] Parsed request JSON body: {json_body}")
            except Exception as e:
                ctx.log.error(f"[Error] Failed to parse request JSON: {e}")
                flow.response = Response.make(400, b"Invalid JSON")
                return

            conversation: str | None = json_body.get('query_str', None)
            ctx.log.info(f"[Debug] Extracted conversation: {conversation}")

            user_id: str | None = json_body.get('params', {}).get('user_nextauth_id', None)
            ctx.log.info(f"[Debug] Extracted user_id: {user_id}")

            email: str | None = self.related_user_data.get(user_id, {}).get("email", None)
            ctx.log.info(f"[Debug] Extracted email from related_user_data: {email}")

            if isinstance(conversation, str):
                if email:
                    ctx.log.info(f"[Debug] Email found, checking account...")
                    if not self.account_check_callback(email):
                        ctx.log.warn(f"[Warn] Account check failed for email: {email}")
                        flow.response = Response.make(401)
                        return
                    ctx.log.info(f"[Debug] Account check passed, invoking conversation_callback")
                    self.conversation_callback(email, conversation, conversation_id)
                else:
                    ctx.log.info(f"[Debug] No email found, checking anonymous access...")
                    if not self.allow_anonymous_access():
                        ctx.log.warn(f"[Warn] Anonymous access not allowed")
                        flow.response = Response.make(401)
                        return
                    ctx.log.info(f"[Debug] Anonymous access allowed, invoking anonymous_conversation_callback")
                    self.anonymous_conversation_callback(conversation, conversation_id)
            else:
                ctx.log.warn(f"[Warn] Conversation is not a string: {conversation}")


        elif flow.request.method == "GET" and "perplexity.ai/api/auth/session" in flow.request.pretty_url:

            content_type: str = flow.response.headers.get("Content-Type", "")
            pplx_session_id: str | None = flow.request.cookies.get("pplx.session-id")
            ctx.log.info(f"[Debug] pplx_session_id from cookies: {pplx_session_id}")

            if "application/json" in content_type.lower():
                try:
                    content: dict[str, Any] = json.loads(flow.response.content.decode('utf-8'))
                    ctx.log.info(f"[Debug] Parsed JSON content: {content}")

                    session_email: str = content['user']['email']
                    session_user_id: str = content['user']['id']
                    ctx.log.info(f"[Debug] Extracted email: {session_email}, user_id: {session_user_id}")

                    self.related_user_data[session_user_id] = {'email': session_email, "pplx_session_id": pplx_session_id}
                    self._user_data_ts[session_user_id] = time.time()
                    ctx.log.info(f"[Debug] Updated self.related_user_data: {self.related_user_data}")

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        elif flow.request.method == "POST" and "perplexity.ai/rest/uploads/create_upload_url" in flow.request.pretty_url:

            upload_session_id: str | None = flow.request.cookies.get("pplx.session-id")
            ctx.log.info(f"[Debug] pplx_session_id from cookies: {upload_session_id}")

            upload_content_type: str = flow.response.headers.get("Content-Type", "")
            ctx.log.info(f"[Debug] Content-Type: {upload_content_type}")

            if "application/json" in upload_content_type.lower():
                try:
                    upload_response: dict[str, Any] = json.loads(flow.response.content.decode('utf-8'))
                    ctx.log.info(f"[Debug] Parsed JSON content: {upload_response}")

                    tagging: str | None = upload_response.get('fields', {}).get('tagging', None)
                    ctx.log.info(f"[Debug] Extracted tagging: {tagging}")

                    if tagging:
                        file_uuid: str | None = get_file_uuid_from_tagging(tagging)
                        ctx.log.info(f"[Debug] Extracted file_uuid: {file_uuid}")

                        self.file_data[file_uuid] = {"pplx.session-id": upload_session_id}
                        self._file_data_ts[file_uuid] = time.time()
                        ctx.log.info(f"[Debug] Updated self.file_data: {self.file_data}")
                except Exception as e:
                    ctx.log.error(f"[Error] Failed to parse JSON or extract tagging: {e}")


        elif flow.request.method == "POST" and "ppl-ai-file-upload.s3.amazonaws.com" in flow.request.pretty_url:

            req_content_type: str = flow.request.headers.get("Content-Type", "")
            ctx.log.info(f"Updating file...")

            if "multipart/form-data" in req_content_type:
                ctx.log.info(f"Multipart form data")
                body: bytes = flow.request.raw_content
                uploaded_files: list[dict[str, Any]]
                form_fields: dict[str, str]
                uploaded_files, form_fields = parse_multipart(req_content_type, body, return_fields=True)

                s3_tagging: str | None = form_fields.get('tagging')
                ctx.log.info(f"Extracted tagging: {s3_tagging}")

                s3_file_uuid: str | None = get_file_uuid_from_tagging(s3_tagging)
                ctx.log.info(f"Extracted file_uuid: {s3_file_uuid}")

                s3_file_data: dict[str, Any] | None = self.file_data.get(s3_file_uuid, None)
                ctx.log.info(f"file_data for file_uuid {s3_file_uuid}: {s3_file_data}")

                if not s3_file_data:
                    ctx.log.warn(f"No file_data found for file_uuid {s3_file_uuid}. self.file_data: {self.file_data}")
                    return

                s3_pplx_session_id: str | None = s3_file_data.get("pplx.session-id") if s3_file_data else None
                ctx.log.info(f"pplx_session_id from file_data: {s3_pplx_session_id}")

                s3_email: str | None = None
                for user_info in self.related_user_data.values():
                    ctx.log.info(f"Checking user_info for pplx_session_id: {user_info}")
                    if user_info.get("pplx_session_id") == s3_pplx_session_id:
                        s3_email = user_info.get("email")
                        ctx.log.info(f"Matched email: {s3_email}")
                        break

                for file in uploaded_files:
                    filepath: str = self.store_file_callback(file['content'])
                    self.attached_file_callback(s3_email, file['filename'], filepath, file['content_type'])


def get_file_uuid_from_tagging(tagging: str | None) -> str | None:
    if tagging is None:
        return None
    wrapped: str = f"<root>{tagging}</root>"
    root: ET.Element = ET.fromstring(wrapped)

    for tag in root.findall(".//Tag"):
        key: ET.Element | None = tag.find("Key")
        value: ET.Element | None = tag.find("Value")
        if key is not None and key.text == "file_uuid":
            return value.text if value is not None else None
    return None
