from proxy import Site, EmailNotFoundException, decode_jwt, extract_substring_between
from mitmproxy import http, ctx
from mitmproxy.http import Response
from urllib.parse import parse_qs, unquote

import json
import os
import uuid
import re
import magic


class Gemini(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Google Gemini", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        
        self.related_user_data = {}
        self.related_file_data = {}
    
    def on_request_handle(self, flow):
            
        if flow.request.method == "POST" and "gemini.google.com/_/BardChatUi/data/assistant.lamda" in flow.request.pretty_url:
            ctx.log.info("Conversation!!!")
            if "f.req=" in flow.request.text:
                form_data = parse_qs(flow.request.text)
                f_req_raw = form_data.get("f.req", [""])[0]
                ctx.log.info(f"f_req_raw: {f_req_raw}")

                # URL decode
                decoded = unquote(f_req_raw)
                # Optional: attempt to parse as JSON if possible
                try:

                    parsed = json.loads(decoded)
                    parsed = parsed[1]
                    parsed = json.loads(parsed)

                    conversation = parsed[0][0]

                    ctx.log.info(f'Conversation: {conversation}')

                    sid_cookie = flow.request.cookies.get("SID")
                    #ctx.log.info(f"SID cookie value: {sid_cookie}")

                    email = self.related_user_data.get(sid_cookie, {}).get("email", None)
                    ctx.log.info(f"Email: {email}")


                    if email and email != "":

                        if not self.account_check_callback(email):
                            #Don't allow not permitted domains
                            flow.response = Response.make(403)
                            return

                        self.conversation_callback(email, conversation)

                    else:
                        if not self.allow_anonymous_access():
                            #Don't allow anonymous conversations
                            flow.response = Response.make(403)
                            return
                        
                        self.anonymous_conversation_callback(conversation)

                except Exception as e:
                    ctx.log.error(f"Could not parse JSON: {e}\nDecoded String:\n{decoded}")

        
        elif flow.request.method == "POST" and "push.clients6.google.com/upload/" in flow.request.pretty_url:


            sid_cookie = flow.request.cookies.get("SID")
            content_type = flow.request.headers.get("Content-Type", "")

            if "application/x-www-form-urlencoded" in content_type:

                if flow.request.method == "POST" and "push.clients6.google.com/upload/?upload_id" in flow.request.pretty_url:
                    
                    filename = self.related_file_data.get(sid_cookie, {}).get("filename", None)

                    if not filename:
                        ctx.log.error("Something went wrong retrieving filename")
                        return

                    pdf_bytes = flow.request.raw_content

                    #Need to determine ourselves the content type...
                    # Create a Magic object with mime detection enabled
                    mime = magic.Magic(mime=True)

                    # Get MIME type from file content
                    content_type = mime.from_buffer(pdf_bytes)
        
                    unique_id = uuid.uuid4().hex

                    filepath = os.path.join("/uploads", f"{unique_id}")

                    with open(filepath, "wb") as f:
                        f.write(pdf_bytes)

                    email = self.related_user_data.get(sid_cookie, {}).get("email", None)

                    self.attached_file_callback(email, filename, filepath, content_type)

                    ctx.log.info(f"Saved PUT upload to: {filepath}")

                else:

                        # Get the raw content bytes and decode to string
                        raw_content = flow.request.raw_content
                        raw_text = raw_content.decode('utf-8', errors='ignore')

                        ctx.log.info(f"raw_text: {raw_text}")

                        match = re.search(r"File name:\s*(.*)", raw_text)

                        if match:
                            filename = match.group(1)
                            ctx.log.info(f"filename: {filename}")
                            self.related_file_data[sid_cookie] = {'filename': filename}

    def on_response_handle(self, flow):

        if flow.request.method == "GET" and "gemini.google.com/app" in flow.request.pretty_url:

            sid_cookie = flow.request.cookies.get("SID")
            #ctx.log.info(f"SID cookie value: {sid_cookie}")

            html = flow.response.get_text()
            #ctx.log.info(f"HTML response body:\n{html}")

            # Look for the anchor tag with the specific href pattern
            match = re.search(
                r'aria-label=\"[^\"]*?\(([^)]+)\)\"\shref=\"https:\/\/accounts\.google\.com\/SignOutOptions[^\"]*\"',
                html,
                re.DOTALL
            )
            if match:

                email = match.group(1)
                ctx.log.info(f"Extracted email: {email}")

                self.related_user_data[sid_cookie] = {'email': email}
                    
            else:

                ctx.log.info("No email found in anchor content.")