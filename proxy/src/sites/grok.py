from proxy import Site, parse_multipart, decode_jwt
from mitmproxy import ctx
from mitmproxy.http import Response

import json
import os
import uuid


class Grok(Site):

    def __init__(self, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        super().__init__("Grok", urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                         allow_anonymous_access, anonymous_conversation_callback)
        self.users = {}
    
    def on_request_handle(self, flow):
        ctx.log.info(f"[Info] Handling request: {flow.request.method} {flow.request.pretty_url}")

        sso_cookie = flow.request.cookies.get("sso")
        session_id = None

        ctx.log.debug(f"[Debug] sso_cookie: {sso_cookie}")

        if sso_cookie:
            jwt_data = decode_jwt(sso_cookie)
            ctx.log.debug(f"[Debug] jwt_data: {jwt_data}")

            if jwt_data:
                jwt_payload = jwt_data['payload']
                ctx.log.debug(f"[Debug] jwt_payload: {jwt_payload}")

                if "session_id" in jwt_payload:
                    session_id = jwt_payload['session_id']
                    ctx.log.info(f"[Info] session_id extracted: {session_id}")

        if flow.request.method == "POST" and "grok.com/api/statsig/log_event" in flow.request.pretty_url:

            json_body = None

            if flow.request.headers.get("content-type", "").startswith("text/plain"):
                try:
                    json_body = json.loads(flow.request.get_text())
                    ctx.log.debug(f"[Debug] statsig log_event json_body: {json_body}")
                except Exception as e:
                    ctx.log.warn(f"[Warn] Failed to decode text/plain as JSON: {e}")
                    return
            else:
                json_body = flow.request.json()
                ctx.log.debug(f"[Debug] statsig log_event json_body: {json_body}")

            if json_body:
                # Extract the first email occurrence from json_body['events']
                email = None
                for event in json_body.get('events', []):
                    user = event.get('user', {})
                    email = user.get('email')
                    if email and session_id:
                        ctx.log.info(f"[Info] Extracted email from statsig log_event: {email}")
                        self.users[session_id] = {'email': email}
                        ctx.log.info(f"[Info] Stored user: session_id={session_id}, email={email}")
                        break


        elif flow.request.method == "POST" and "grok.com/_data/v1/events" in flow.request.pretty_url:
            ctx.log.info("[Info] Processing events endpoint")

            # Decode json from body
            json_body = flow.request.json()
            ctx.log.debug(f"[Debug] events json_body: {json_body}")

            email = json_body.get("viewer_context", {}).get("user_attributes", {}).get("email", None)
            ctx.log.info(f"[Info] Extracted email: {email}")

            if email and session_id:
                self.users[session_id] = {'email': email}
                ctx.log.info(f"[Info] Stored user: session_id={session_id}, email={email}")

        elif flow.request.method == "POST" and "grok.com/rest/app-chat/conversations" in flow.request.pretty_url:
            ctx.log.info("[Info] Processing conversations endpoint")

            # Decode json from body
            json_body = flow.request.json()
            ctx.log.debug(f"[Debug] conversations json_body: {json_body}")

            email = self.users.get(session_id, {}).get("email", None)
            ctx.log.info(f"[Info] Retrieved email for session: {email}")

            # Extract conversation
            if "message" in json_body:
                conversation = json_body['message']
                ctx.log.info(f"[Info] Extracted conversation: {conversation}")

                if email:
                    if not self.account_check_callback(email):
                        ctx.log.warn(f"[Warn] Account check failed for email: {email}")
                        flow.response = Response.make(
                            401
                        )
                        return
                    ctx.log.info(f"[Info] Account check passed for email: {email}")
                    self.conversation_callback(email, conversation)
                else:
                    if not self.allow_anonymous_access():
                        ctx.log.warn(f"[Warn] Anonymous access not allowed")
                        flow.response = Response.make(
                            401
                        )
                        return
                    ctx.log.info("[Info] Anonymous access allowed")
                    self.anonymous_conversation_callback(conversation)