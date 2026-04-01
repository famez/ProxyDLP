from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from mitmproxy import ctx, http
from mitmproxy.http import Response

from proxy import Site, ProxyCallbacks, EmailNotFoundException, decode_jwt, extract_substring_between

FILE_ID_TTL: int = 300  # seconds before an unused file_id entry is evicted

class ChatGPT(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("ChatGPT", urls, callbacks)
        self.files: dict[str, dict[str, Any]] = {}
        self.file_ids: dict[str, dict[str, Any]] = {}
        self._file_id_timestamps: dict[str, float] = {}

    async def start_background_tasks(self) -> None:
        asyncio.create_task(self._cleanup_stale_file_ids(), name="chatgpt-cleanup")

    async def _cleanup_stale_file_ids(self) -> None:
        while True:
            await asyncio.sleep(60)
            now: float = time.time()
            stale: list[str] = [fid for fid, ts in list(self._file_id_timestamps.items()) if now - ts > FILE_ID_TTL]
            for fid in stale:
                self.file_ids.pop(fid, None)
                self._file_id_timestamps.pop(fid, None)
                ctx.log.info(f"Evicted stale file_id entry: {fid}")

    async def on_response_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "auth.openai.com/api/accounts/authorize/continue" in flow.request.pretty_url:
            ctx.log.info("Performing authentication!")
            json_body: dict[str, Any] = flow.request.json()

            if 'connection' in json_body and not await self.allow_anonymous_access():
                #Don't allow delegated authentication
                ctx.log.info("Blocking delegated authentication!")
                response_data: dict[str, Any] = {
                    "continue_url": "https://chatgpt.com",
                    "method": "GET",
                }
                flow.response = Response.make(
                    200,
                    json.dumps(response_data).encode("utf-8"),
                    {"Content-Type": "application/json"}
                )
                return

            if 'username' in json_body and json_body['username']['kind'] == "email":
                email: str = json_body['username']["value"]
                ctx.log.info(f"Using email {email}")

                if not await self.account_login_callback(email):
                    response_data = {
                        "continue_url": "https://chatgpt.com",
                        "method": "GET",
                    }
                    flow.response = Response.make(
                        200,
                        json.dumps(response_data).encode("utf-8"),
                        {"Content-Type": "application/json"}
                    )

                return

        if flow.request.method == "POST" and flow.request.pretty_url == "https://chatgpt.com/backend-api/files":
            #Get the file reference
            try:
                auth_header: str | None = flow.request.headers.get("Authorization")
                email = get_email_from_auth_header(auth_header)

                json_body = flow.request.json()
                file_name: str = json_body['file_name']
                self.files[email] = {"file_name": file_name}

            except EmailNotFoundException as e:
                ctx.log.error(f"Email not found on URL: {e}")


        if flow.request.method == "POST" and "chatgpt.com/backend-api/files/process_upload_stream" in flow.request.pretty_url:
            #Get the file reference
            try:
                auth_header = flow.request.headers.get("Authorization")
                email = get_email_from_auth_header(auth_header)

                json_body = flow.request.json()
                file_id: str = json_body['file_id']

                self.files[email]['filepath'] = self.file_ids[file_id]['filepath']
                self.files[email]['content_type'] = self.file_ids[file_id]['content_type']

                await self.attached_file_callback(email, self.files[email]['file_name'], self.files[email]['filepath'], self.files[email]['content_type'])

                # Free state — no longer needed after callback
                self.files.pop(email, None)
                self.file_ids.pop(file_id, None)
                self._file_id_timestamps.pop(file_id, None)

            except EmailNotFoundException as e:
                ctx.log.error(f"Email not found on URL: {e}")


        if flow.request.method == "POST" and (
            "chatgpt.com/backend-anon/conversation" in flow.request.pretty_url
            or "chatgpt.com/backend-anon/f/conversation" in flow.request.pretty_url
        ):
            if not await self.allow_anonymous_access():
                ctx.log.info(f"Anonymous conversations are not allowed")
                flow.response = Response.make(
                    403,
                    b"Blocked by proxy",
                    {"Content-Type": "text/plain"}
                )
                return

            json_body = flow.request.json()
            conversation_text: str = json_body["messages"][0]["content"]["parts"][0]

            if flow.response and flow.response.headers.get("Content-Type", "").startswith("text/event-stream"):
                try:
                    event_data: str = flow.response.text
                    for line in event_data.splitlines():
                        if line.startswith("data:"):
                            data: str = line[len("data:"):].strip()
                            if data and data != "[DONE]":
                                try:
                                    event: dict[str, Any] = json.loads(data)
                                    if "conversation_id" in event:
                                        conversation_id: str = event['conversation_id']
                                        await self.anonymous_conversation_callback(conversation_text, conversation_id)
                                        break
                                except Exception as e:
                                    ctx.log.error(f"Failed to parse event data: {e}")
                except Exception as e:
                    ctx.log.error(f"Error parsing text/event-stream: {e}")


        if flow.request.method == "POST" and (
            flow.request.pretty_url == "https://chatgpt.com/backend-api/conversation"
            or flow.request.pretty_url == "https://chatgpt.com/backend-api/f/conversation"
        ):
            ctx.log.info(f"Authenticated conversation...")

            auth_header = flow.request.headers.get("Authorization")
            try:
                email = get_email_from_auth_header(auth_header)

                if await self.account_check_callback(email):
                    ctx.log.info(f"Email address belongs to the organization")

                    json_body = flow.request.json()
                    conversation_text = json_body["messages"][0]["content"]["parts"][0]

                    if isinstance(conversation_text, str):
                        if flow.response and flow.response.headers.get("Content-Type", "").startswith("text/event-stream"):
                            try:
                                event_data = flow.response.text
                                parsed = parse_assistant_response(event_data)
                                conversation_id = None
                                for line in event_data.splitlines():
                                    if line.startswith("data:"):
                                        data = line[len("data:"):].strip()
                                        if data and data != "[DONE]":
                                            try:
                                                event = json.loads(data)
                                                if "conversation_id" in event:
                                                    conversation_id = event['conversation_id']
                                                    break
                                            except Exception as e:
                                                ctx.log.error(f"Failed to parse event data: {e}")
                                if conversation_id:
                                    await self.conversation_callback(email, conversation_text, conversation_id)
                                    if parsed:
                                        assistant_uuid, response_text = parsed
                                        await self.update_response_callback(conversation_id, assistant_uuid, response_text)
                            except Exception as e:
                                ctx.log.error(f"Error parsing text/event-stream: {e}")

                    return

            except EmailNotFoundException as e:
                ctx.log.error("Email not properly decoded!")

            ctx.log.info("JWT token checks failed!")
            flow.response = Response.make(
                403,
                b"Blocked by proxy",
                {"Content-Type": "text/plain"}
            )

        #File being uploaded to ChatGPT.
        if flow.request.method == "PUT" and "oaiusercontent.com/file" in flow.request.pretty_url:
            content: bytes | None = flow.request.content

            if content:
                unique_id: str = uuid.uuid4().hex
                filename: str = f"{unique_id}"
                content_type: str = flow.request.headers.get("Content-Type", "unknown")
                filepath: str = await self.store_file_callback(content)
                ctx.log.info(f"Saved PUT upload to: {filepath}")

                file_id = extract_substring_between(flow.request.pretty_url, "oaiusercontent.com/", "?")
                self.file_ids[file_id] = {"filepath": filepath, "content_type": content_type}
                self._file_id_timestamps[file_id] = time.time()


def _apply_delta_patch(obj: Any, path: str, op: str, value: Any) -> Any:
    """Apply a single JSON-patch-like operation to obj at path."""
    if not path or path == "/":
        if op == "replace":
            return value
        return obj

    parts = [p for p in path.split("/") if p]
    target = obj
    for part in parts[:-1]:
        if isinstance(target, dict):
            target = target.setdefault(part, {})
        elif isinstance(target, list):
            target = target[int(part)]
        else:
            return obj

    key = parts[-1]
    if isinstance(target, dict):
        if op == "append":
            existing = target.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.update(value)
            else:
                target[key] = (existing or "") + value
        elif op in ("replace", "add"):
            target[key] = value
    elif isinstance(target, list):
        idx = int(key)
        if op == "append":
            existing = target[idx]
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.update(value)
            else:
                target[idx] = existing + value
        elif op in ("replace", "add"):
            target[idx] = value

    return obj


def parse_assistant_response(event_data: str) -> tuple[str, str] | None:
    """Parse a ChatGPT delta-encoded eventstream and return (assistant_uuid, response_text), or None."""
    channels: dict[int, Any] = {}
    current_channel: int = 0

    for line in event_data.splitlines():
        if not line.startswith("data:"):
            continue
        raw = line[len("data:"):].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            delta: Any = json.loads(raw)
        except Exception:
            continue

        if not isinstance(delta, dict):
            ctx.log.debug(f"[parse_assistant_response] Skipping non-dict delta: {type(delta)}")
            continue

        o: str | None = delta.get("o")
        p: str = delta.get("p", "")
        v: Any = delta.get("v")
        c: int = delta.get("c", current_channel)

        # Initialize or replace an entire channel object
        if o == "add" and p == "" and isinstance(v, dict):
            ctx.log.debug(f"[parse_assistant_response] Channel {c} init (add), role={v.get('message', {}).get('author', {}).get('role')}")
            channels[c] = v
            current_channel = c
            continue

        if o is None and isinstance(v, dict) and "message" in v:
            # Full object assignment for a channel
            ctx.log.debug(f"[parse_assistant_response] Channel {c} set, role={v.get('message', {}).get('author', {}).get('role')}")
            channels[c] = v
            current_channel = c
            continue

        # Patch operations (list of patches or single patch on current channel)
        patches: list[dict[str, Any]] = []
        if o == "patch" and isinstance(v, list):
            patches = v
            c = current_channel
        elif o is None and isinstance(v, list):
            patches = v
            c = current_channel
        elif o in ("append", "replace") and p:
            patches = [{"p": p, "o": o, "v": v}]
            c = current_channel

        if patches:
            if c not in channels:
                ctx.log.debug(f"[parse_assistant_response] Patches for unknown channel {c}, known={list(channels.keys())}")
            else:
                for patch in patches:
                    try:
                        _apply_delta_patch(channels[c], patch.get("p", ""), patch.get("o", ""), patch.get("v"))
                    except Exception as e:
                        ctx.log.error(f"[parse_assistant_response] Patch error on channel {c}, patch={patch}: {e}")

    ctx.log.debug(f"[parse_assistant_response] Channels after parsing: {list(channels.keys())}")
    for ch_idx, ch_obj in channels.items():
        msg = ch_obj.get("message", {}) if isinstance(ch_obj, dict) else {}
        author = msg.get("author", {})
        role = author.get("role")
        parts = msg.get("content", {}).get("parts", [])
        ctx.log.debug(f"[parse_assistant_response] Channel {ch_idx}: role={role}, parts={parts}")
        if role == "assistant":
            if parts and isinstance(parts[0], str):
                assistant_uuid: str = msg.get("id", "")
                ctx.log.info(f"[parse_assistant_response] Extracted response (uuid={assistant_uuid}): {parts[0][:100]!r}")
                return assistant_uuid, parts[0]
            else:
                ctx.log.debug(f"[parse_assistant_response] Assistant channel {ch_idx} has no valid parts")

    ctx.log.debug("[parse_assistant_response] No assistant response found")
    return None


def get_email_from_auth_header(auth_header: str | None) -> str:
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token: str = auth_header[len("Bearer "):].strip()

        jwt_data: dict[str, Any] | None = decode_jwt(jwt_token)

        if jwt_data:
            jwt_payload: dict[str, Any] = jwt_data['payload']

            if "https://api.openai.com/profile" in jwt_payload and 'email' in jwt_payload["https://api.openai.com/profile"]:
                email: str = jwt_payload["https://api.openai.com/profile"]['email']
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")
