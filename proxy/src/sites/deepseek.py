from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import os
import uuid


class DeepSeek(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__("DeepSeek", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        self.users = {}
    
    def on_request_handle(self, flow):

        
        if flow.request.method == "POST" and "deepseek.com/api/v0/chat/completion" in flow.request.pretty_url:
            

            auth_header = flow.request.headers.get("Authorization")

            #Decode json from body
            json_body = flow.request.json()

            #Extract conversation
            if "prompt" in json_body:

                conversation = json_body['prompt']
                #ctx.log.info(f"Conversation: {conversation}")

                if auth_header in self.users:
                    #ctx.log.info(f"Registering conversation: {conversation}")
                    self.conversation_callback(self.users[auth_header], conversation)


    def on_response_handle(self, flow):

        if flow.request.method == "GET" and "deepseek.com/api/v0/users/current" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")

            content_type = flow.response.headers.get("Content-Type", "")

            if "application/json" in content_type.lower():

                try:

                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))

                    if "data" in content and "biz_data" in content['data'] and "email" in content['data']['biz_data']:
                        email = content['data']['biz_data']['email']
                        self.users[auth_header] = email
                        #ctx.log.info(f"Email added to the users dict")

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")