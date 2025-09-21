from proxy import Site
from mitmproxy import ctx

import json


class Perplexity(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Perplexity", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        
        self.related_user_data = {}
    
    def on_response_handle(self, flow):

        conversation_id = None
            
        if flow.request.method == "POST" and "perplexity.ai/rest/sse/perplexity_ask" in flow.request.pretty_url:
           
            # If the response is a text/event-stream, parse and log the events
            if flow.response and flow.response.headers.get("Content-Type", "").startswith("text/event-stream"):
                try:
                    event_data = flow.response.text
                    for line in event_data.splitlines():
                        if line.startswith("data:"):
                            data = line[len("data:"):].strip()
                            if data and data != "[DONE]":
                                try:
                                    event = json.loads(data)

                                    if "context_uuid" in event:
                                        
                                        conversation_id = event['context_uuid']
                                        break

                                except Exception as e:
                                    ctx.log.error(f"Failed to parse event data: {e}")
                except Exception as e:
                    ctx.log.error(f"Error parsing text/event-stream: {e}")


            json_body = flow.request.json()
            conversation = json_body.get('query_str', None)

            user_id = json_body['params']['user_nextauth_id']

            email = self.related_user_data.get(user_id, {}).get("email", None)

            if isinstance(conversation, str):
                if email:
                    self.conversation_callback(email, conversation, conversation_id)
                else:
                    self.anonymous_conversation_callback(conversation, conversation_id)


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