from __future__ import annotations

import json
import base64
import re
from typing import Any, Callable
from mitmproxy import ctx, http, websocket


class Proxy:
    def __init__(
        self,
        account_login_callback: Callable[..., bool],
        account_check_callback: Callable[..., bool],
        conversation_callback: Callable[..., None],
        attached_file_callback: Callable[..., None],
        allow_anonymous_access: Callable[..., bool],
        anonymous_conversation_callback: Callable[..., None],
        store_file_callback: Callable[..., str],
    ) -> None:
        self.sites: list[Site] = []
        self.account_login_callback = account_login_callback
        self.account_check_callback = account_check_callback
        self.conversation_callback = conversation_callback
        self.attached_file_callback = attached_file_callback
        self.allow_anonymous_access = allow_anonymous_access
        self.anonymous_conversation_callback = anonymous_conversation_callback
        self.store_file_callback = store_file_callback

    def register_site(self, cls: type[Site], urls: list[str]) -> None:
        site = cls(
            urls,
            self.account_login_callback,
            self.account_check_callback,
            self.conversation_callback,
            self.attached_file_callback,
            self.allow_anonymous_access,
            self.anonymous_conversation_callback,
            self.store_file_callback,
        )
        self.sites.append(site)

    def route_request(self, flow: http.HTTPFlow) -> bool:
        routed: bool = False
        url: str = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_request(flow)
                        routed = True
        return routed

    def route_response(self, flow: http.HTTPFlow) -> bool:
        routed: bool = False
        url: str = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_response(flow)
                        routed = True
        return routed

    def route_ws_from_client_to_server(
        self, flow: http.HTTPFlow, message: websocket.WebSocketMessage
    ) -> bool:
        url: str = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_ws_from_client_to_server(flow, message)
                        return True
        return False

    def get_sites(self) -> list[Site]:
        return self.sites

    def get_site(self, name: str) -> Site | None:
        return next((x for x in self.sites if x.get_name() == name), None)


class EmailNotFoundException(Exception):
    def __init__(self, field: str, message: str) -> None:
        self.field: str = field
        self.message: str = message
        super().__init__(f"Validation error on '{field}': {message}")


class Site:
    def __init__(
        self,
        name: str,
        urls: list[str],
        account_login_callback: Callable[..., bool],
        account_check_callback: Callable[..., bool],
        conversation_callback: Callable[..., None],
        attached_file_callback: Callable[..., None],
        allow_anonymous_access: Callable[..., bool],
        anonymous_conversation_callback: Callable[..., None],
        store_file_callback: Callable[..., str],
    ) -> None:
        self.name: str = name
        self.urls: list[str] = urls
        self.source_ip: str = ""     #To keep track of the source IP address.
        self.on_account_login_callback = account_login_callback
        self.on_account_check_callback = account_check_callback
        self.on_conversation_callback = conversation_callback
        self.on_attached_file_callback = attached_file_callback
        self.on_allow_anonymous_access = allow_anonymous_access
        self.on_anonymous_conversation_callback = anonymous_conversation_callback
        self.on_store_file_callback = store_file_callback

        self.enabled: bool = False

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def isEnabled(self) -> bool:
        return self.enabled

    def get_urls(self) -> list[str]:
        return self.urls

    def get_name(self) -> str:
        return self.name

    def handle_request(self, flow: http.HTTPFlow) -> None:
        # Prefer the real client IP stored by main.py from X-Forwarded-For (HAProxy injects it).
        # Falls back to the raw TCP source when running without a load balancer.
        self.source_ip = flow.metadata.get("_real_source_ip", flow.client_conn.address[0])
        self.on_request_handle(flow)

    def handle_response(self, flow: http.HTTPFlow) -> None:
        self.source_ip = flow.metadata.get("_real_source_ip", flow.client_conn.address[0])
        self.on_response_handle(flow)

    def handle_ws_from_client_to_server(
        self, flow: http.HTTPFlow, message: websocket.WebSocketMessage
    ) -> None:
        # This method is called when a WebSocket message is sent from the client to the server
        self.source_ip = flow.metadata.get("_real_source_ip", flow.client_conn.address[0])
        self.on_ws_from_client_to_server(flow, message)

    def on_request_handle(self, flow: http.HTTPFlow) -> None:
        pass        #To be implement by child

    def on_response_handle(self, flow: http.HTTPFlow) -> None:
        pass        #To be implement by child

    def on_ws_from_client_to_server(
        self, flow: http.HTTPFlow, message: websocket.WebSocketMessage
    ) -> None:
        pass        #To be implement by child

    def account_login_callback(self, email: str) -> bool:
        return self.on_account_login_callback(self, email, self.source_ip)

    def account_check_callback(self, email: str) -> bool:
        return self.on_account_check_callback(self, email, self.source_ip)

    def conversation_callback(
        self, email: str, conversation_text: str, conversation_id: str | None = None
    ) -> None:
        return self.on_conversation_callback(self, email, conversation_text, self.source_ip, conversation_id)

    def attached_file_callback(
        self, email: str | None, file_name: str, filepath: str, content_type: str
    ) -> None:
        return self.on_attached_file_callback(self, email, file_name, filepath, content_type, self.source_ip)

    def allow_anonymous_access(self) -> bool:
        return self.on_allow_anonymous_access(self)

    def anonymous_conversation_callback(
        self, conversation_text: str, conversation_id: str | None = None
    ) -> None:
        return self.on_anonymous_conversation_callback(self, conversation_text, self.source_ip, conversation_id)

    def store_file_callback(self, file_content: bytes) -> str:
        return self.on_store_file_callback(self, file_content)


# Helper functions

def pad_b64(segment: str) -> str:
    return segment + '=' * (-len(segment) % 4)

def decode_jwt(token: str) -> dict[str, Any] | None:
    parts: list[str] = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header: dict[str, Any] = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())
        payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])).decode())
        return {"header": header, "payload": payload}
    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None


def extract_substring_between(s: str, start: str, end: str) -> str:
    # Find the index of the start substring
    idx1: int = s.find(start)

    # Find the index of the end substring, starting after the start substring
    idx2: int = s.find(end, idx1 + len(start))

    # Check if both delimiters are found and extract the substring between them
    if idx1 != -1 and idx2 != -1:
        res: str = s[idx1 + len(start):idx2]
        return res

    return ""


def parse_multipart(
    content_type_header: str,
    body_bytes: bytes,
    return_fields: bool = False,
) -> list[dict[str, Any]] | tuple[list[dict[str, Any]], dict[str, str]]:
    # Extract boundary from Content-Type header
    match = re.search(r'boundary=(.*)', content_type_header)
    if not match:
        return [], {}

    boundary: str = match.group(1)
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary_bytes: bytes = boundary.encode()

    delimiter: bytes = b'--' + boundary_bytes
    parts: list[bytes] = body_bytes.split(delimiter)[1:-1]  # Skip preamble and epilogue
    files: list[dict[str, Any]] = []
    fields: dict[str, str] = {}

    for part in parts:
        part = part.strip(b'\r\n')
        headers_body = part.split(b'\r\n\r\n', 1)
        if len(headers_body) != 2:
            continue

        headers_raw, body = headers_body
        headers_text: str = headers_raw.decode(errors='ignore')
        body = body.rstrip(b'\r\n')

        # Check if it's a file
        filename_match = re.search(r'filename="([^"]+)"', headers_text)
        content_type_match = re.search(r'Content-Type:\s*([^\r\n;]+)', headers_text, re.IGNORECASE)
        name_match = re.search(r'name="([^"]+)"', headers_text)

        if filename_match:
            filename: str = filename_match.group(1)
            content_type: str = content_type_match.group(1) if content_type_match else "application/octet-stream"

            files.append({
                "filename": filename,
                "content": body,
                "content_type": content_type
            })
        elif name_match:
            # Treat as a normal form field
            name: str = name_match.group(1)
            try:
                value: str = body.decode(errors='ignore')
            except Exception:
                value = body
            fields[name] = value

    if return_fields:
        return files, fields
    return files
