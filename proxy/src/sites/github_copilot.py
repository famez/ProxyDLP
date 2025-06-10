from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response
import xml.etree.ElementTree as ET

import json
import os
import uuid


class Github_Copilot(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__("Github Copilot", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        self.related_user_data = {}
        
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "githubcopilot.com/chat/completions" in flow.request.pretty_url:
            ctx.log.info(f"Request URL: {flow.request.pretty_url}")

            body = flow.request.get_text()
            try:
                json_body = json.loads(body)

                if 'messages' in json_body:
                    messages = json_body['messages']
                    for message in reversed(messages):
                        if 'role' in message and message['role'] == 'user':
                            if 'content' in message:
                                user_message = message['content']
                                #ctx.log.info(f"User message: {user_message}")
                                user_message = f"<root>{user_message}</root>"
                                root = ET.fromstring(user_message)

                                prompt = root.find('prompt').text if root.find('prompt') is not None else None

                                if prompt:
                                    #ctx.log.info(f"Prompt found: {prompt}")

                                    ip_address = flow.client_conn.address[0]

                                    login = self.related_user_data.get(ip_address, {}).get("login", None)
                                    if login:
                                        self.conversation_callback(login, prompt)
  
                                break
                            else:
                                ctx.log.error("User message content not found.")
                        else:
                            ctx.log.error("User role not found in the message.")

            except json.JSONDecodeError:
                ctx.log.info(f"Request body (raw): {body}")
            # Save json_body to a file
            with open("/tmp/copilot_json_body.json", "w") as f:
                json.dump(json_body, f, indent=2)

    def on_response_handle(self, flow):

        if flow.request.method == "GET" and "api.github.com/user" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")
            #token = auth_header[len("Bearer "):].strip()

            ip_address = flow.client_conn.address[0]
            if "application/json" in flow.response.headers.get("content-type", ""):
                    try:
                        # Decode the response content as JSON
                        json_body = json.loads(flow.response.get_text())
                        # Log or process the JSON data
                        if 'login' in json_body:
                            user_login = json_body['login']
                            ctx.log.info(f"User login: {user_login}")
                            
                            self.related_user_data[ip_address] = {
                                "login": user_login,
                            }
                            
                    except json.JSONDecodeError:
                        print("Failed to decode JSON.")


            


                

