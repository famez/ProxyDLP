from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import os
import uuid


class ChatGPT(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__("ChatGPT", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        self.files = {}
        self.file_ids = {}
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "auth.openai.com/api/accounts/authorize/continue" in flow.request.pretty_url:
            ctx.log.info("Performing authentication!")
            json_body = flow.request.json()

            if 'connection' in json_body:
                #Don't allow delegated authentication
                ctx.log.info("Blocking delegated authentication!")
                # Define the JSON structure you want to return
                response_data = {
                    "continue_url": "https://chatgpt.com",
                    "method": "GET",
                }

                # Return JSON response
                flow.response = Response.make(
                    200,
                    json.dumps(response_data).encode("utf-8"),  # Must be bytes
                    {"Content-Type": "application/json"}
                )
                return
        
            if 'username' in json_body and json_body['username']['kind'] == "email":

                email = json_body['username']["value"]
                ctx.log.info(f"Using email {email}")

                #Check whether the email address belongs to the organization or not
                if not self.account_login_callback(email):
                    response_data = {
                        "continue_url": "https://chatgpt.com",
                        "method": "GET",
                    }

                    # Return JSON response
                    flow.response = Response.make(
                        200,
                        json.dumps(response_data).encode("utf-8"),  # Must be bytes
                        {"Content-Type": "application/json"}
                    )


                return

        if flow.request.method == "POST" and flow.request.pretty_url == "https://chatgpt.com/backend-api/files":

            #Get the file reference
            try:
                auth_header = flow.request.headers.get("Authorization")
                email = get_email_from_auth_header(auth_header)

                #Decode json from body
                json_body = flow.request.json()

                file_name = json_body['file_name']

                self.files[email] = { "file_name" : file_name }

            except EmailNotFoundException as e:
                ctx.log.error(f"Email not found on URL: {e}")
                

        if flow.request.method == "POST" and "chatgpt.com/backend-api/files/process_upload_stream" in flow.request.pretty_url:
            
            
            #Get the file reference
            try:
                auth_header = flow.request.headers.get("Authorization")
                email = get_email_from_auth_header(auth_header)

                #Decode json from body
                json_body = flow.request.json()

                file_id = json_body['file_id']

                self.files[email]['filepath'] = self.file_ids[file_id]['filepath']
                self.files[email]['content_type'] = self.file_ids[file_id]['content_type']

                self.attached_file_callback(email, self.files[email]['file_name'], self.files[email]['filepath'], self.files[email]['content_type'])


            except EmailNotFoundException as e:
                ctx.log.error(f"Email not found on URL: {e}")


        if flow.request.method == "POST" and "chatgpt.com/backend-anon/conversation" in flow.request.pretty_url:
            # Return JSON response

            ctx.log.info(f"Anonymous conversations are not allowed")
            flow.response = Response.make(
                403,
                b"Blocked by proxy",  # Body
                {"Content-Type": "text/plain"}  # Headers
            )
            return        
        
        if flow.request.method == "POST" and (flow.request.pretty_url == "https://chatgpt.com/backend-api/conversation"
                                            or flow.request.pretty_url == "https://chatgpt.com/backend-api/f/conversation"):
            
            ctx.log.info(f"Authenticated conversation...")

            #Obtain JWT token to double check that the session is still authorized
            auth_header = flow.request.headers.get("Authorization")
            try:
                email = get_email_from_auth_header(auth_header)

                if self.account_check_callback(email):
                    ctx.log.info(f"Email address belongs to the organization")

                    #Get the text sent to the conversation
                    json_body = flow.request.json()
                    conversation_text = json_body["messages"][0]["content"]["parts"][0]

                    self.conversation_callback(email, conversation_text)

                    return
                
            except EmailNotFoundException as e:
                ctx.log.error("Email not properly decoded!")

            ctx.log.info("JWT token checks failed!")
            flow.response = Response.make(
                403,
                b"Blocked by proxy",  # Body
                {"Content-Type": "text/plain"}  # Headers
            )


        #File being uploaded to ChatGPT.
        if flow.request.method == "PUT" and "oaiusercontent.com/file" in flow.request.pretty_url:

            content = flow.request.content

            if content:
                # Generate a filename from UUID

                unique_id = uuid.uuid4().hex

                filename = f"{unique_id}"

                content_type = flow.request.headers.get("Content-Type", "unknown")

                filepath = os.path.join("/uploads", filename)

                with open(filepath, "wb") as f:
                    f.write(content)

                ctx.log.info(f"Saved PUT upload to: {filepath}")


                #Get file id

                file_id = extract_substring_between(flow.request.pretty_url, "oaiusercontent.com/", "?")

                #ctx.log.info(f"File id: {file_id}")

                self.file_ids[file_id] = { "filepath" : filepath, "content_type" : content_type }



def get_email_from_auth_header(auth_header):
    
    if auth_header and auth_header.startswith("Bearer "):
            
        jwt_token = auth_header[len("Bearer "):].strip()
        #ctx.log.info(f"JWT Token extracted: {jwt_token}")

        jwt_data = decode_jwt(jwt_token)

        if jwt_data:
            #ctx.log.info(f"JWT Header: {json.dumps(jwt_data['header'], indent=2)}")
            #ctx.log.info(f"JWT Payload: {json.dumps(jwt_data['payload'], indent=2)}")

            jwt_payload = jwt_data['payload']

            #Let's check only the email address from the JWT token, 
            #as the rest of fields are already validated by Chatgpt to 
            #perform the request (correctly signed, not expired, etc).

            if "https://api.openai.com/profile" in jwt_payload and 'email' in jwt_payload["https://api.openai.com/profile"]:

                email = jwt_payload["https://api.openai.com/profile"]['email']
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")

