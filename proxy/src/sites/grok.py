from proxy import Site, parse_multipart
from mitmproxy import ctx
from mitmproxy.http import Response

import json
import os
import uuid


class Grok(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Grok", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        self.users = {}
    
    def on_request_handle(self, flow):

        
        if flow.request.method == "POST" and "grok.com/rest/app-chat/conversations" in flow.request.pretty_url:
            

            #Decode json from body
            json_body = flow.request.json()

            #Extract conversation
            if "message" in json_body:

                conversation = json_body['message']

                self.anonymous_conversation_callback(conversation)

