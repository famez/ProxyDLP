from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response


class Perplexity(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Perplexity", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "perplexity.ai/rest/sse/perplexity_ask" in flow.request.pretty_url:
           
            json_body = flow.request.json()
            conversation = json_body.get('query_str', None)

            if isinstance(conversation, str):
                self.anonymous_conversation_callback(conversation)
