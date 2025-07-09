from proxy import Site
from mitmproxy import ctx
from mitmproxy.http import Response

import json

import os
import uuid


class BlackBox(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("BlackBox", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        
    
    def on_request_handle(self, flow):

        if flow.request.method == "POST" and "blackbox.ai/api/chat" in flow.request.pretty_url:
            
            content_type = flow.request.headers.get("Content-Type", "")

            email = None

            if not "application/json" in content_type.lower():

                return
            
            try:

                #Decode json from body
                json_body = flow.request.json()

                session = json_body.get('session')
                if isinstance(session, dict):
                    user = session.get('user')
                    if isinstance(user, dict):
                        email = user.get('email')


                #Check if anonymous chats are allowed or chats with proper account domains are allowed.
                if not email:
                    if not self.allow_anonymous_access():
                        flow.response = Response.make(
                            401
                        )
                        return
                else:
                    if not self.account_check_callback(email):
                        flow.response = Response.make(
                            401
                        )
                        return
                    

                if not "messages" in json_body:
                    return
                
                
                for message in reversed(json_body['messages']): 
                    if 'role' in message and message['role'] == "user" and 'content' in message:
                        if email:
                            self.conversation_callback(json_body['session']['user']['email'], message['content'])
                        else:
                            self.anonymous_conversation_callback(message['content'])
                        break



            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        
    









            