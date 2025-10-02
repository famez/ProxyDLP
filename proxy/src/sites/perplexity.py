from proxy import Site, parse_multipart
from mitmproxy import ctx
from mitmproxy.http import Response
import xml.etree.ElementTree as ET


import json
import os
import uuid


class Perplexity(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback, exclude_urls):
        super().__init__("Perplexity", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback, exclude_urls)
        
        self.related_user_data = {}
        self.file_data = {}
    
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


            try:
                json_body = flow.request.json()
                ctx.log.info(f"[Debug] Parsed request JSON body: {json_body}")
            except Exception as e:
                ctx.log.error(f"[Error] Failed to parse request JSON: {e}")
                flow.response = Response.make(
                    400, b"Invalid JSON"
                )
                return

            conversation = json_body.get('query_str', None)
            ctx.log.info(f"[Debug] Extracted conversation: {conversation}")

            user_id = json_body.get('params', {}).get('user_nextauth_id', None)
            ctx.log.info(f"[Debug] Extracted user_id: {user_id}")

            email = self.related_user_data.get(user_id, {}).get("email", None)
            ctx.log.info(f"[Debug] Extracted email from related_user_data: {email}")

            if isinstance(conversation, str):
                if email:
                    ctx.log.info(f"[Debug] Email found, checking account...")
                    if not self.account_check_callback(email):
                        ctx.log.warn(f"[Warn] Account check failed for email: {email}")
                        flow.response = Response.make(
                            401
                        )
                        return
                    ctx.log.info(f"[Debug] Account check passed, invoking conversation_callback")
                    self.conversation_callback(email, conversation, conversation_id)
                else:
                    ctx.log.info(f"[Debug] No email found, checking anonymous access...")
                    if not self.allow_anonymous_access():
                        ctx.log.warn(f"[Warn] Anonymous access not allowed")
                        flow.response = Response.make(
                            401
                        )
                        return
                    ctx.log.info(f"[Debug] Anonymous access allowed, invoking anonymous_conversation_callback")
                    self.anonymous_conversation_callback(conversation, conversation_id)
            else:
                ctx.log.warn(f"[Warn] Conversation is not a string: {conversation}")


        elif flow.request.method == "GET" and "perplexity.ai/api/auth/session" in flow.request.pretty_url:

            content_type = flow.response.headers.get("Content-Type", "")

            pplx_session_id = flow.request.cookies.get("pplx.session-id")
            ctx.log.info(f"[Debug] pplx_session_id from cookies: {pplx_session_id}")
            
            if "application/json" in content_type.lower():

                try:
                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))
                    ctx.log.info(f"[Debug] Parsed JSON content: {content}")

                    email = content['user']['email']
                    user_id = content['user']['id']
                    ctx.log.info(f"[Debug] Extracted email: {email}, user_id: {user_id}")

                    self.related_user_data[user_id] = {'email': email, "pplx_session_id": pplx_session_id}
                    ctx.log.info(f"[Debug] Updated self.related_user_data: {self.related_user_data}")

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        elif flow.request.method == "POST" and "perplexity.ai/rest/uploads/create_upload_url" in flow.request.pretty_url:
            
            pplx_session_id = flow.request.cookies.get("pplx.session-id")
            ctx.log.info(f"[Debug] pplx_session_id from cookies: {pplx_session_id}")

            content_type = flow.response.headers.get("Content-Type", "")
            ctx.log.info(f"[Debug] Content-Type: {content_type}")

            if "application/json" in content_type.lower():
                try:
                    content = json.loads(flow.response.content.decode('utf-8'))
                    ctx.log.info(f"[Debug] Parsed JSON content: {content}")

                    tagging = content.get('fields', {}).get('tagging', None)
                    ctx.log.info(f"[Debug] Extracted tagging: {tagging}")

                    if tagging:
                        file_uuid = get_file_uuid_from_tagging(tagging)
                        ctx.log.info(f"[Debug] Extracted file_uuid: {file_uuid}")

                        self.file_data[file_uuid] = {"pplx.session-id": pplx_session_id}
                        ctx.log.info(f"[Debug] Updated self.file_data: {self.file_data}")
                except Exception as e:
                    ctx.log.error(f"[Error] Failed to parse JSON or extract tagging: {e}")

        
        elif flow.request.method == "POST" and "ppl-ai-file-upload.s3.amazonaws.com" in flow.request.pretty_url:

            content_type = flow.request.headers.get("Content-Type", "")

            ctx.log.info(f"Updating file...")
            if "multipart/form-data" in content_type:

                ctx.log.info(f"Multipart form data")
                body = flow.request.raw_content
                uploaded_files, fields = parse_multipart(content_type, body, return_fields=True)

                tagging = fields.get('tagging')
                ctx.log.info(f"Extracted tagging: {tagging}")

                file_uuid = get_file_uuid_from_tagging(tagging)
                ctx.log.info(f"Extracted file_uuid: {file_uuid}")

                file_data = self.file_data.get(file_uuid, None)
                ctx.log.info(f"file_data for file_uuid {file_uuid}: {file_data}")

                if not file_data:
                    ctx.log.warn(f"No file_data found for file_uuid {file_uuid}. self.file_data: {self.file_data}")
                    return
                
                # Get pplx_session_id from file_data
                pplx_session_id = file_data.get("pplx.session-id") if file_data else None
                ctx.log.info(f"pplx_session_id from file_data: {pplx_session_id}")

                # Find email by pplx_session_id from self.related_user_data
                email = None
                for user_info in self.related_user_data.values():
                    ctx.log.info(f"Checking user_info for pplx_session_id: {user_info}")
                    if user_info.get("pplx_session_id") == pplx_session_id:
                        email = user_info.get("email")
                        ctx.log.info(f"Matched email: {email}")
                        break

                for file in uploaded_files:
                    unique_id = uuid.uuid4().hex
                    safe_filename = f"{unique_id}"
                    filepath = os.path.join("/uploads", safe_filename)

                    ctx.log.info(f"Saving uploaded file to {filepath}")
                    with open(filepath, "wb") as f:
                        f.write(file['content'])
                    ctx.log.info(f"Saved file: {filepath}")

                    self.attached_file_callback(email, file['filename'], filepath, file['content_type'])    #Send file attached event 


def get_file_uuid_from_tagging(tagging):

    tagging = f"<root>{tagging}</root>"
    root = ET.fromstring(tagging)
    file_uuid = None

    for tag in root.findall(".//Tag"):
        key = tag.find("Key")
        value = tag.find("Value")
        if key is not None and key.text == "file_uuid":
            file_uuid = value.text if value is not None else None
            return file_uuid
