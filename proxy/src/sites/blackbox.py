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
            
            content_type = flow.request.headers.get("Content-Type", "")

            if not "application/json" in content_type.lower():

                return
            
            try:

                #Decode json from body
                json_body = flow.request.json()

                if not 'session' in json_body or not 'user' in json_body['session'] or not 'email' in json_body['session']['user']:
                    return
                
                if not self.account_check_callback(json_body['session']['user']['email']):
                    flow.response = Response.make(
                        401
                    )
                    return

                if not "messages" in json_body:
                    return
                
                for message in reversed(json_body['messages']): 
                    if 'role' in message and message['role'] == "user" and 'content' in message:
                        self.conversation_callback(json_body['session']['user']['email'], message['content'])
                        break

            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        
    









            