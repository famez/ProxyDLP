from __future__ import annotations

from typing import Any, Callable
from urllib.parse import parse_qs

from mitmproxy import http

from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between


class DeepL(Site):

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
            "DeepL", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback,
        )

    def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "dict.deepl.com" in flow.request.pretty_url:
            content: str = flow.request.get_text()
            parsed: dict[str, list[str]] = parse_qs(content)
            conversation: str | None = parsed.get("query", [None])[0]

            self.anonymous_conversation_callback(conversation)
