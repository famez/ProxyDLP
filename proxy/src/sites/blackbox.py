from proxy import Site, parse_multipart
from mitmproxy import ctx
from mitmproxy.http import Response

import json

import os
import uuid


class BlackBox(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("BlackBox", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)

        self.sessions = {}
        self.workspaces = {}
            
    def on_request_handle(self, flow):

        if flow.request.method == "POST" and "blackbox.ai/api/chat" in flow.request.pretty_url:
            
            content_type = flow.request.headers.get("Content-Type", "")

            email = None

            if not "application/json" in content_type.lower():

                return
            
            try:

                #Decode json from body
                json_body = flow.request.json()

                session = json_body.get('session')
                if isinstance(session, dict):
                    user = session.get('user')
                    if isinstance(user, dict):
                        email = user.get('email')


                #Check if anonymous chats are allowed or chats with proper account domains are allowed.
                if not email:
                    if not self.allow_anonymous_access():
                        flow.response = Response.make(
                            401
                        )
                        return
                else:
                    if not self.account_check_callback(email):
                        flow.response = Response.make(
                            401
                        )
                        return
                    

                if not "messages" in json_body:
                    return
                
                
                for message in reversed(json_body['messages']): 
                    if 'role' in message and message['role'] == "user" and 'content' in message:
                        if email:
                            session_id = json_body['id']

                            results = [item for item in self.sessions if session_id in item]

                            if results:
                                self.sessions[session_id]['email'] = email
                                ctx.log.info("Added session 1")
                            else:
                                self.sessions[session_id] = {'email': email}        #Keep track of email from conversation id.
                                ctx.log.info("Added session 2")

                            self.conversation_callback(json_body['session']['user']['email'], message['content'])
                        else:
                            self.anonymous_conversation_callback(message['content'])
                        break


            except Exception as e:
                ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")

        elif flow.request.method == "POST" and "blackbox.ai/api/workspace/link-to-chat" in flow.request.pretty_url:
            json_body = flow.request.json()

            ctx.log.info(f"json_body: {json.dumps(json_body, indent=2)}")

            session_id = json_body['chatId']
            workspace_id = json_body['workspaceIds'][0]

            ctx.log.info(f"session id: {session_id}, workspace_id: {workspace_id}")

            for session in self.sessions:
                ctx.log.info(f"Session: {str(session)}")
            

            if session_id in self.sessions:
                self.sessions[session_id]['workspace'] = json_body['workspaceIds'][0]
                ctx.log.info(f"Eeeeooo")

                email = None

                if "email" in self.sessions[session_id]:
                    email = self.sessions[session_id]['email']

                if workspace_id in self.workspaces:
                    self.sessions[session_id]['files'] = self.workspaces[workspace_id]
                    ctx.log.info("Session...")
                    ctx.log.info(str(self.sessions[session_id]))

                    for file in self.sessions[session_id]['files']:

                        self.attached_file_callback(email, file['filename'], file['filepath'], file['content_type'])    #Send file attached event 



    def on_response_handle(self, flow):

        if flow.request.method == "POST" and "https://www.blackbox.ai/api/workspace" == flow.request.pretty_url:

            workspace_id = None

            response_content_type = flow.response.headers.get("Content-Type", "")

            ctx.log.info("Eooooo one two three")

            if "application/json" in response_content_type.lower():

                try:

                    # Try to parse as JSON
                    content = flow.response.json()

                    ctx.log.info("Hellooo")

                    if "id" in content:
                        workspace_id = content["id"]
                        self.workspaces[workspace_id] = []

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")
            
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

                    self.workspaces[workspace_id].append({"filename": file['filename'], "filepath": filepath, "content_type": 
                                                          file['content_type']})

                    ctx.log.info("Adding workspace!!!")

                    #self.attached_file_callback(None, file['filename'], filepath, file['content_type'])
                    