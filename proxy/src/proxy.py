from mitmproxy import http, ctx
from mitmproxy.http import Response
import json
import re
import base64
import os
from datetime import datetime, timezone
from pymongo import MongoClient
import uuid
import time

import grpc
import monitor_pb2
import monitor_pb2_grpc


from mitm_term import launch_ws_term

launch_ws_term()


db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["proxyGPT"]["events"]

class EmailNotFoundException(Exception):
    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"Validation error on '{field}': {message}")

files = {}

file_ids = {}


allowed_domain = "gmail.com"      #Change by your org domain, such as contoso.com

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

            else:
                ctx.log.info(f"Corporative user {email} logged in")

                #Register event into the database.
                event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Logged in", "detail" : ""}
                events_collection.insert_one(event)

                return

    if flow.request.method == "POST" and flow.request.pretty_url == "https://chatgpt.com/backend-api/files":

        #Get the file reference
        try:
            auth_header = flow.request.headers.get("Authorization")
            email = get_email_from_auth_header(auth_header)

            #Decode json from body
            json_body = flow.request.json()

            file_name = json_body['file_name']

            files[email] = { "file_name" : file_name }

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

            files[email]['filepath'] = file_ids[file_id]['filepath']
            files[email]['content_type'] = file_ids[file_id]['content_type']

            ctx.log.info(f"File:")

            for key, value in files[email].items():
                ctx.log.info(f"{key}: {value}")


            #ctx.log.info(f"Leaked data from file: {result}")

            event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Attached file", "filename" : files[email]['file_name'], "filepath" : files[email]['filepath'], 
                     "content_type": files[email]['content_type']}
            
            result = events_collection.insert_one(event)
            
            mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

            ctx.log.info("Sent event to monitor...")

            response = stub.EventAdded(mon_message)

            ctx.log.info(f"Response: {response}")

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

            if re.match(email_regex, email):
                ctx.log.info(f"Email address belongs to the organization")

                #Get the text sent to the conversation

                json_body = flow.request.json()
                conversation_text = json_body["messages"][0]["content"]["parts"][0]

                #ctx.log.info(f"Conversation sent: {conversation_text}")

                event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Conversation", "content": conversation_text}

                result = events_collection.insert_one(event)

                mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

                ctx.log.info("Sent event to monitor...")

                response = stub.EventAdded(mon_message)

                ctx.log.info(f"Response: {response}")

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
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if content:
            # Generate a filename from UUID

            unique_id = uuid.uuid4().hex

            filename = f"{unique_id}"

            content_type = flow.request.headers.get("Content-Type", "unknown")
            if content_type == "application/pdf":
                filename += ".pdf"
            elif content_type == "application/vnd.ms-excel" or content_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
                filename += ".xlsx"
            elif content_type == "application/msword" or content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                filename += ".docx"
            elif content_type == "image/jpeg":
                filename += ".jpg"
            elif content_type == "image/png":
                filename += ".png"
            elif content_type == "image/gif":
                filename += ".gif"
            elif content_type == "image/bmp":
                filename += ".bmp"
            elif content_type == "image/webp":
                filename += ".webp"
            elif content_type == "image/svg+xml":
                filename += ".svg"
            elif content_type == "image/tiff":
                filename += ".tiff"
            elif content_type == "image/vnd.microsoft.icon":
                filename += ".ico"

            filepath = os.path.join("/uploads", filename)

            with open(filepath, "wb") as f:
                f.write(content)

            ctx.log.info(f"Saved PUT upload to: {filepath}")


            #Get file id

            file_id = extract_substring_between(flow.request.pretty_url, "oaiusercontent.com/", "?")

            #ctx.log.info(f"File id: {file_id}")

            file_ids[file_id] = { "filepath" : filepath, "content_type" : content_type }

           

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



def extract_substring_between(s, start, end):
    
    # Find the index of the start substring
    idx1 = s.find(start)

    # Find the index of the end substring, starting after the start substring
    idx2 = s.find(end, idx1 + len(start))

    # Check if both delimiters are found and extract the substring between them
    if idx1 != -1 and idx2 != -1:
        res = s[idx1 + len(start):idx2]
        return res  # Output: world
    
    return ""


time.sleep(2)  # Wait for server to be ready
channel = grpc.insecure_channel('monitor:50051')
stub = monitor_pb2_grpc.MonitorStub(channel)