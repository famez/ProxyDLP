from proxy import Site
from mitmproxy import ctx
from mitmproxy.http import Response

import json

import os
import uuid


class BlackBox(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__("BlackBox", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        
    
    def on_request_handle(self, flow):

        if flow.request.method == "POST" and "blackbox.ai/api/chat" in flow.request.pretty_url:
            cookie_value = flow.request.cookies.get("__Secure-authjs.session-token")
            if cookie_value:
                ctx.log.info(f"Found session token: {cookie_value}")
                with open("/tmp/session_token.txt", "w") as f:
                    f.write(cookie_value)
            else:
                ctx.log.info("Session token not found in cookies.")

                

        
    









            