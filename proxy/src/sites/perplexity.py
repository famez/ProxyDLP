from proxy import Site
from mitmproxy import ctx

import json


class Perplexity(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Perplexity", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        
        self.related_user_data = {}
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "perplexity.ai/rest/sse/perplexity_ask" in flow.request.pretty_url:
           
            json_body = flow.request.json()
            conversation = json_body.get('query_str', None)

            user_id = json_body['params']['user_nextauth_id']

            email = self.related_user_data.get(user_id, {}).get("email", None)

            if isinstance(conversation, str):
                if email:
                    self.conversation_callback(email, conversation)
                else:
                    self.anonymous_conversation_callback(conversation)

    def on_response_handle(self, flow):

        if flow.request.method == "GET" and "perplexity.ai/api/auth/session" in flow.request.pretty_url:

            content_type = flow.response.headers.get("Content-Type", "")
            
            if "application/json" in content_type.lower():

                try:

                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))

                    email = content['user']['email']
                    user_id = content['user']['id']

                    self.related_user_data[user_id] = {'email': email}

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")