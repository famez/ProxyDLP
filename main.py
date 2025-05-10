# modify_headers.py
from mitmproxy import http, ctx
from mitmproxy.http import Response
import json
import re
import base64

allowed_domain = "gmail.com"

email_regex = r'^[a-zA-Z0-9._%+-]+@' + allowed_domain + '$'


def request(flow: http.HTTPFlow) -> None:
    # Example: Add a custom header to requests to example.com
    #print("Requested URL:", flow.request.pretty_url)
    #ctx.log.info("test")
    
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
            if not re.match(email_regex, email):
                ctx.log.info(f"Email address does not belong to an organization")
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

    if flow.request.method == "POST" and "chatgpt.com/backend-anon/conversation" in flow.request.pretty_url:
        # Return JSON response

        ctx.log.info(f"Anonymous conversations are not allowed")
        flow.response = Response.make(
            403,
            b"Blocked by proxy",  # Body
            {"Content-Type": "text/plain"}  # Headers
        )
        return        
    
    if flow.request.method == "POST" and ("chatgpt.com/backend-api/f/conversation" in flow.request.pretty_url 
                                          or "chatgpt.com/backend-api/conversation" in flow.request.pretty_url):
        ctx.log.info(f"Authenticated conversation...")

        #Obtain JWT token to double check that the session is still authorized
        auth_header = flow.request.headers.get("Authorization")
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

                    if re.match(email_regex, email):
                        ctx.log.info(f"Email address belongs to the organization")
                        return

            ctx.log.info("JWT token checks failed!")
            flow.response = Response.make(
                403,
                b"Blocked by proxy",  # Body
                {"Content-Type": "text/plain"}  # Headers
            )
            

       
def response(flow: http.HTTPFlow) -> None:
    # Add a custom header to every HTTP response
    return
    flow.response.headers["X-Injected-By"] = "mitmproxy"

def decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())
        payload = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])).decode())
        return {"header": header, "payload": payload}
    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None

def pad_b64(segment: str) -> str:
    return segment + '=' * (-len(segment) % 4)
