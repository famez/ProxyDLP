from proxy import Site
from mitmproxy import ctx

import json
import re

import os
import uuid

def parse_multipart(content_type, body_bytes):
    # Extract boundary from Content-Type
    match = re.search(r'boundary=(.*)', content_type)
    if not match:
        return []

    boundary = match.group(1)
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]

    boundary = boundary.encode()
    delimiter = b'--' + boundary
    parts = body_bytes.split(delimiter)[1:-1]  # Skip preamble and epilogue
    files = []

    for part in parts:
        part = part.strip(b'\r\n')
        headers_body = part.split(b'\r\n\r\n', 1)
        if len(headers_body) != 2:
            continue

        headers_raw, body = headers_body
        headers_text = headers_raw.decode(errors='ignore')

        if 'filename="' in headers_text:
            filename_match = re.search(r'filename="([^"]+)"', headers_text)
            if not filename_match:
                continue
            filename = filename_match.group(1)
            files.append((filename, body.strip()))

    return files



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


        elif flow.request.method == "POST" and "deepseek.com/api/v0/file/upload_file" in flow.request.pretty_url:

            auth_header = flow.request.headers.get("Authorization")

            content_type = flow.request.headers.get("content-type", "")

            if "multipart/form-data" in content_type:

                body = flow.request.raw_content

                uploaded_files = parse_multipart(content_type, body)

                for filename, content in uploaded_files:
                    unique_id = uuid.uuid4().hex
                    safe_filename = f"{unique_id}"
                    filepath = os.path.join("/uploads", safe_filename)

                    ctx.log.info(f"Saving uploaded file to {filepath}")
                    with open(filepath, "wb") as f:
                        f.write(content)
                    ctx.log.info(f"Saved file: {filepath}")


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

            