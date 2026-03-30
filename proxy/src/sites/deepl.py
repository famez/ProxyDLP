from __future__ import annotations

from urllib.parse import parse_qs

from mitmproxy import http

from proxy import Site, ProxyCallbacks, EmailNotFoundException, decode_jwt, extract_substring_between


class DeepL(Site):

    def __init__(self, urls: list[str], callbacks: ProxyCallbacks) -> None:
        super().__init__("DeepL", urls, callbacks)

    async def on_request_handle(self, flow: http.HTTPFlow) -> None:

        if flow.request.method == "POST" and "dict.deepl.com" in flow.request.pretty_url:
            content: str = flow.request.get_text()
            parsed: dict[str, list[str]] = parse_qs(content)
            conversation: str | None = parsed.get("query", [None])[0]

            await self.anonymous_conversation_callback(conversation)
