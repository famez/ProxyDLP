from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import os
import uuid
from urllib.parse import parse_qs


class DeepL(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback, exclude_urls):
        super().__init__("DeepL", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback, exclude_urls)
        
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "dict.deepl.com" in flow.request.pretty_url:
            #ctx.log.info("DeepL data")
            
            content = flow.request.get_text()

            parsed = parse_qs(content)
            conversation = parsed.get("query", [None])[0]

            #ctx.log.info(f"Extracted query value: {query_value}")

            self.anonymous_conversation_callback(conversation)