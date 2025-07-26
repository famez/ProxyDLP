from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response
import urllib.parse

import json
import os
import uuid


class Gemini(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Google Gemini", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "gemini.google.com/_/BardChatUi/data/assistant.lamda" in flow.request.pretty_url:
            ctx.log.info("Conversation!!!")
            if "f.req=" in flow.request.text:
                form_data = urllib.parse.parse_qs(flow.request.text)
                f_req_raw = form_data.get("f.req", [""])[0]
                ctx.log.info(f"f_req_raw: {f_req_raw}")

                # URL decode
                decoded = urllib.parse.unquote(f_req_raw)
                # Optional: attempt to parse as JSON if possible
                try:

                    parsed = json.loads(decoded)
                    parsed = parsed[1]
                    parsed = json.loads(parsed)

                    conversation = parsed[0][0]

                    ctx.log.info(f'Anonymous conversation: {conversation}')

                    self.anonymous_conversation_callback(conversation)

                except Exception as e:
                    ctx.log.error(f"Could not parse JSON: {e}\nDecoded String:\n{decoded}")

            