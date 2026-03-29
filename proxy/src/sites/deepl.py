from __future__ import annotations

from typing import Any, Callable
from urllib.parse import parse_qs

from mitmproxy import http

from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between


class DeepL(Site):

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
        update_response_callback: Callable[..., Any],
    ) -> None:
        super().__init__(
            "DeepL", urls, account_login_callback, account_check_callback,
            conversation_callback, attached_file_callback,
            allow_anonymous_access, anonymous_conversation_callback, store_file_callback, update_response_callback,
        )

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "dict.deepl.com" in flow.request.pretty_url:
            content: str = flow.request.get_text()
            parsed: dict[str, list[str]] = parse_qs(content)
            conversation: str | None = parsed.get("query", [None])[0]

            await self.anonymous_conversation_callback(conversation)
