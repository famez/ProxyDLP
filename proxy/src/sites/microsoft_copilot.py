from proxy import Site, EmailNotFoundException, decode_jwt, pad_b64
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import base64
import uuid
import re
import os
import gzip
from io import BytesIO
from urllib.parse import urlparse, parse_qs
import magic


class Microsoft_Copilot(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback, store_file_callback):
        super().__init__("Microsoft Copilot", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback, store_file_callback)
        self.uploaded_files = {}
        
    def on_request_handle(self, flow):
        
        if flow.request.method == "PUT" and "sharepoint.com/personal" in flow.request.pretty_url and "uploadSession" in flow.request.pretty_url:
            ctx.log.info(f"Handling PUT request for SharePoint uploadSession: {flow.request.pretty_url}")

            tempauth = flow.request.query.get("tempauth")
            user_email = extract_email_from_tempauth(tempauth)
            

            if not user_email or not self.account_check_callback(user_email):
                ctx.log.warn(f"User email invalid or not allowed: {user_email}")
                flow.response = Response.make(
                    403,
                    b"Blocked by proxy",  # Body
                    {"Content-Type": "text/plain"}  # Headers
                )
                return

            content_type = flow.request.headers.get("Content-Type", "")
            ctx.log.debug(f"Content-Type of request: {content_type}")

            if "application/octet-stream" in content_type:

                content_range = flow.request.headers.get("Content-Range", "")
                ctx.log.debug(f"Content-Range of request: {content_range}")

                # Parse Content-Range header
                match = re.match(r"bytes (\d+)-(\d+)/(\d+)", content_range)
                if match:
                    start = int(match.group(1))
                    end = int(match.group(2))
                    total = int(match.group(3))

                if user_email in self.uploaded_files:
                    ctx.log.info(f"Handling in-memory upload for user: {user_email}")


                    # Initialize or get existing bytearray buffer
                    buf = self.uploaded_files[user_email].get('filecontent')
                    if start == 0 or buf is None:
                        buf = bytearray()
                        self.uploaded_files[user_email]['filecontent'] = buf
                        ctx.log.debug(f"Initialized in-memory buffer for user {user_email}")

                    # Ensure buffer length matches start (pad with zeros if needed)
                    if start > len(buf):
                        buf.extend(b'\x00' * (start - len(buf)))

                    # Write/overwrite the chunk into the buffer
                    chunk = flow.request.raw_content
                    buf[start:start + len(chunk)] = chunk
                    ctx.log.info(f"In-memory chunk written for {user_email}: {start}-{end} (total {total}), buffer size now {len(buf)}")

                    # If upload complete, detect mime type and invoke callback with in-memory content
                    if end + 1 == total:
                        try:
                            mime = magic.Magic(mime=True)
                            content_type_detected = mime.from_buffer(bytes(buf))
                        except Exception as e:
                            ctx.log.warn(f"Failed to detect MIME type from buffer: {e}")
                            content_type_detected = "application/octet-stream"

                        filepath = self.store_file_callback(bytes(buf))

                        # Call attached_file_callback with file content instead of a filepath
                        self.attached_file_callback(user_email, self.uploaded_files[user_email]['filename'], filepath, content_type_detected)

                        # Optionally remove the entry to free memory
                        del self.uploaded_files[user_email]
                        ctx.log.info(f"Completed in-memory upload and removed entry for user: {user_email}")
                else:
                    ctx.log.warn(f"No uploaded_files entry found for user: {user_email}")

    def on_response_handle(self, flow):

        if flow.request.method == "POST" and "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:" in flow.request.pretty_url:
            
            content_type = flow.request.headers.get("Content-Type", "")

            content = flow.request.json()

            filename = content.get("item", {}).get("name", None)

            ctx.log.info(f"File name: {filename}")
            
            content_type = flow.response.headers.get("Content-Type", "")

            if "application/json" in content_type.lower():

                try:

                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))

                    upload_url = content.get('uploadUrl')

                    if upload_url:
                        parsed_url = urlparse(upload_url)
                        query_params = parse_qs(parsed_url.query)
                        tempauth = query_params.get("tempauth", [None])[0]
                    else:
                        tempauth = None

                    if tempauth:
                        email = extract_email_from_tempauth(tempauth)

                        ctx.log.info(f"Email: {email}")
                        self.uploaded_files[email] = {"filename": filename}

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")
          

    def on_ws_from_client_to_server(self, flow, message):

        if flow.request.method == "GET" and "copilot.microsoft.com/c/api/chat" in flow.request.pretty_url:

            email = None

            auth_query_param = flow.request.query.get("accessToken", "")

            if auth_query_param == "":

                #Anonymous conversation
                if not self.allow_anonymous_access():
                    # Prevent the message from being sent to the server
                    message.kill()
                    return
                
            else:

                try :

                    jwt_token = auth_query_param.strip()

                    jwt_data = decode_jwt(jwt_token)

                    if jwt_data:

                        jwt_payload = jwt_data['payload']

                        if "email" in jwt_payload:
                            email = jwt_payload['email']

                            if not self.account_check_callback(email):
                                # Prevent the message from being sent to the server
                                message.kill()
                                return

                except EmailNotFoundException as e:
                    ctx.log.error(f"Email not properly decoded: {e}")

            try:
                json_content = json.loads(message.content.decode('utf-8'))
                
                if "event" in json_content and json_content['event'] == "send" and "content" in json_content:
                    messages = json_content['content']
                    for message in messages:
                        if message['type'] == 'text':
                            if email:
                                self.conversation_callback(email, message['text'])
                            else:
                                self.anonymous_conversation_callback(message['text'])

            except Exception as e:
                ctx.log.error(f"Failed to decode JSON from message.content: {e}")

            

        elif flow.request.method == "GET" and "substrate.office.com/m365Copilot/Chathub" in flow.request.pretty_url:

            auth_query_param = flow.request.query.get("access_token", "")
            conversationId = flow.request.query.get("ConversationId", None)

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
                                    self.conversation_callback(email, conversation_text, conversationId)

                    return
                
            except EmailNotFoundException as e:
                ctx.log.error(f"Email not properly decoded: {e}")

            ctx.log.info("JWT token checks failed!")
            # Prevent the message from being sent to the server
            message.kill()

def get_email_from_auth_header(auth_query_param):
    
    if auth_query_param:
            
        jwt_token = auth_query_param.strip()
        #ctx.log.info(f"JWT Token extracted: {jwt_token}")

        jwt_data = decode_jwt(jwt_token)

        if jwt_data:

            jwt_payload = jwt_data['payload']

            #Let's check only the email address from the JWT token, 
            #as the rest of fields are already validated by Copilot to 
            #perform the request (correctly signed, not expired, etc).

            if "unique_name" in jwt_payload:

                email = jwt_payload["unique_name"]
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")

def decode_special_microsoft_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())

        encoded_payload = parts[1].strip().split(".")[0]

        missing_padding = len(encoded_payload) % 4
        if missing_padding:
            encoded_payload += "=" * (4 - missing_padding)

        raw_payload = base64.urlsafe_b64decode(encoded_payload)

        payload_text = raw_payload.decode('latin1', errors='ignore')  # latin1 avoids decode errors

        patterns = {
            "Emails": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "UUIDs": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            "IP addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Readable strings": r"[a-zA-Z0-9\.\-_\@\s]{4,}",
        }

        payload_strings = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, payload_text)
            payload_strings[name] = list(set(matches))  # remove duplicates

        return {"header": header, "payload_strings": payload_strings}
    
    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None


def extract_email_from_tempauth(tempauth):

    ctx.log.debug(f"tempauth query param: {tempauth}")

    if tempauth and tempauth.startswith("v1."):
        tempauth = tempauth.removeprefix("v1.")
        ctx.log.debug(f"tempauth after removing prefix: {tempauth}")

        decoded = decode_special_microsoft_token(tempauth)
        ctx.log.debug(f"Decoded tempauth token: {decoded}")

        if not decoded:
            ctx.log.error("Failed to decode tempauth token")
            return

        if "app_displayname" in decoded['header']:
            ctx.log.debug(f"app_displayname in header: {decoded['header']['app_displayname']}")
        if "app_displayname" in decoded['header'] and decoded['header']["app_displayname"] == "M365ChatClient" and 'Emails' in decoded['payload_strings'] and len(decoded['payload_strings']['Emails']) > 0:
            emails = decoded['payload_strings']['Emails']
            ctx.log.info(f"Emails extracted from payload: {emails}")

            for email in emails:
                if not 'live.comz' in email:
                    ctx.log.info(f"Email extracted from tempauth: {email}")
                    return email

    return None