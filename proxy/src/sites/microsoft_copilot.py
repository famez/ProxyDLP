from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import os
import uuid


class Microsoft_Copilot(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__("Microsoft Copilot", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        
    def on_request_handle(self, flow):
        pass

    def on_ws_from_client_to_server(self, flow, message):
        if flow.request.method == "GET" and "substrate.office.com/m365Copilot/Chathub" in flow.request.pretty_url:
            #ctx.log.info(f"\n[WS Message from Client to Server]")
            #ctx.log.info(f"URL: {flow.request.pretty_url}")
            #ctx.log.info(f"Message: {message.content}")

            auth_query_param = flow.request.query.get("access_token", "")
            #ctx.log.info(f"auth_header: {auth_header}")

            try :
                email = get_email_from_auth_header(auth_query_param)

                if self.account_check_callback(email):
                    ctx.log.info(f"Email address belongs to the organization")

                    message_contents = message.content.split(b'\x1e')

                    message_contents = [part for part in message_contents if part]

                                            

                    json_messages = [json.loads(part.decode('utf-8')) for part in message_contents]

                    for json_content in json_messages:
                        #ctx.log.info(f"JSON Content: {json.dumps(json_content, indent=2)}")
                    
                        if "arguments" in json_content:
                            for argument in json_content["arguments"]:
                                if "message" in argument and "text" in argument["message"]:
                                    conversation_text = argument["message"]["text"]
                                    #ctx.log.info(f'Conversation: {conversation_text}')
                                    self.conversation_callback(email, conversation_text)

                    return
                
            except EmailNotFoundException as e:
                ctx.log.error(f"Email not properly decoded: {e}")

            ctx.log.info("JWT token checks failed!")
            # Prevent the message from being sent to the server
            message.kill()
            # Optionally, you can send a close frame to the client
            #flow.websocket.close(403, reason="Blocked by proxy")

def get_email_from_auth_header(auth_query_param):
    
    if auth_query_param:
            
        jwt_token = auth_query_param.strip()
        #ctx.log.info(f"JWT Token extracted: {jwt_token}")

        jwt_data = decode_jwt(jwt_token)

        if jwt_data:
            #ctx.log.info(f"JWT Header: {json.dumps(jwt_data['header'], indent=2)}")
            #ctx.log.info(f"JWT Payload: {json.dumps(jwt_data['payload'], indent=2)}")

            jwt_payload = jwt_data['payload']

            #Let's check only the email address from the JWT token, 
            #as the rest of fields are already validated by Copilot to 
            #perform the request (correctly signed, not expired, etc).

            if "unique_name" in jwt_payload:

                email = jwt_payload["unique_name"]
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")

