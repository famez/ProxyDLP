from proxy import Site, parse_multipart
from mitmproxy import ctx
from mitmproxy.http import Response

import json

import os
import uuid


class DeepSeek(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("DeepSeek", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        self.users = {}
    
    def on_request_handle(self, flow):

        
        if flow.request.method == "POST" and "deepseek.com/api/v0/chat/completion" in flow.request.pretty_url:
            

            auth_header = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
            
                auth_header = auth_header[len("Bearer "):].strip()

            #Decode json from body
            json_body = flow.request.json()

            #Extract conversation
            if "prompt" in json_body:

                conversation = json_body['prompt']

                if auth_header in self.users:


                    if not self.account_check_callback(self.users[auth_header]):
                            
                        # Return JSON response
                        flow.response = Response.make(
                            401
                        )

                        return
                    
                    chat_session_id = None

                    if "chat_session_id" in json_body:
                        chat_session_id = json_body["chat_session_id"]

                    self.conversation_callback(self.users[auth_header], conversation, conversation_id = chat_session_id)


        elif flow.request.method == "POST" and "deepseek.com/api/v0/file/upload_file" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
            
                auth_header = auth_header[len("Bearer "):].strip()

            content_type = flow.request.headers.get("content-type", "")

            if "multipart/form-data" in content_type:

                body = flow.request.raw_content

                uploaded_files = parse_multipart(content_type, body)

                for file in uploaded_files:
                    unique_id = uuid.uuid4().hex
                    safe_filename = f"{unique_id}"
                    filepath = os.path.join("/uploads", safe_filename)

                    ctx.log.info(f"Saving uploaded file to {filepath}")
                    with open(filepath, "wb") as f:
                        f.write(file['content'])
                    ctx.log.info(f"Saved file: {filepath}")

                    if auth_header in self.users:
                        self.attached_file_callback(self.users[auth_header], file['filename'], filepath, file['content_type'])

        elif flow.request.method == "POST" and "chat.deepseek.com/api/v0/users/login" in flow.request.pretty_url:

            content_type = flow.request.headers.get("Content-Type", "")

            if not "application/json" in content_type.lower():

                return
            
            try:

                #Decode json from body
                json_body = flow.request.json()

                if not 'email' in json_body:
                    return
                
                email = json_body['email']

                #Send login event
                if not self.account_login_callback(email):
                    # Return JSON response
                    flow.response = Response.make(
                        401
                    )

                    return
                
            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")
                


    def on_response_handle(self, flow):

        if flow.request.method == "GET" and "deepseek.com/api/v0/users/current" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
            
                auth_header = auth_header[len("Bearer "):].strip()

            content_type = flow.response.headers.get("Content-Type", "")

            if "application/json" in content_type.lower():

                try:

                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))

                    if "data" in content and "biz_data" in content['data'] and "email" in content['data']['biz_data']:
                        email = content['data']['biz_data']['email']

                        #Only associate auth_header token with email if it was not before associated (during login)
                        if not auth_header in self.users:
                            self.users[auth_header] = email
                        #ctx.log.info(f"Email added to the users dict")

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")


        elif flow.request.method == "POST" and "chat.deepseek.com/api/v0/users/login" in flow.request.pretty_url:

            content_type = flow.request.headers.get("Content-Type", "")


            if not "application/json" in content_type.lower():
                return
            
            try:
                #Decode json from body
                json_body = flow.request.json()

                if not 'email' in json_body:
                    return
                
                email = json_body['email']
            
                content_type = flow.response.headers.get("Content-Type", "")

                if not "application/json" in content_type.lower():
                    return
                
                #Decode json from body
                json_body = flow.response.json()

                if 'data' in json_body and 'biz_data' in json_body['data'] and 'user' in json_body['data']['biz_data'] and 'token' in json_body['data']['biz_data']['user']:
                    token = json_body['data']['biz_data']['user']['token']

                    #Get full email account when using the local login.
                    self.users[token] = email

            except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

                











            