import json
import base64
from mitmproxy import ctx
import re

class Proxy:
    def __init__(self, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        self.sites = []
        self.account_login_callback = account_login_callback
        self.account_check_callback = account_check_callback
        self.conversation_callback = conversation_callback
        self.attached_file_callback = attached_file_callback
        self.allow_anonymous_access = allow_anonymous_access
        self.anonymous_conversation_callback = anonymous_conversation_callback


    def register_site(self, cls, urls):
        site = cls(urls, self.account_login_callback, self.account_check_callback, self.conversation_callback, self.attached_file_callback,
                   self.allow_anonymous_access, self.anonymous_conversation_callback)
        self.sites.append(site)

    def route_request(self, flow):
        routed = False
        url = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_request(flow)
                        routed = True

        return routed

    def route_response(self, flow):
        routed = False
        url = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_response(flow)
                        routed = True
                        
        return routed

                    
    def route_ws_from_client_to_server(self, flow, message):
        url = flow.request.pretty_url
        for site in self.sites:
            if site.isEnabled():
                for site_url in site.get_urls():
                    if site_url in url:
                        site.handle_ws_from_client_to_server(flow, message)
                        return True
        return False
                
    def get_sites(self):
        return self.sites
    
    def get_site(self, name: str):
        # Find the first matching object
        return next((x for x in self.sites if x.get_name() == name), None)
    

class EmailNotFoundException(Exception):
    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"Validation error on '{field}': {message}")

class Site:
    def __init__(self, name, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
                 allow_anonymous_access, anonymous_conversation_callback):
        self.name = name
        self.urls = urls
        self.source_ip = ""     #To keep track of the source IP address.
        self.on_account_login_callback = account_login_callback
        self.on_account_check_callback = account_check_callback
        self.on_conversation_callback = conversation_callback
        self.on_attached_file_callback = attached_file_callback
        self.on_allow_anonymous_access = allow_anonymous_access
        self.on_anonymous_conversation_callback = anonymous_conversation_callback

        self.enabled = False

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def isEnabled(self):
        return self.enabled

    def get_urls(self):
        return self.urls
    
    def get_name(self):
        return self.name

    def handle_request(self, flow):
        self.source_ip = flow.client_conn.address[0]
        self.on_request_handle(flow)

    def handle_response(self, flow):
        self.source_ip = flow.client_conn.address[0]
        self.on_response_handle(flow)
        
    def handle_ws_from_client_to_server(self, flow, message):
        # This method is called when a WebSocket message is sent from the client to the server
        self.source_ip = flow.client_conn.address[0]
        self.on_ws_from_client_to_server(flow, message)


    def on_request_handle(self, flow):
        pass        #To be implement by child

    def on_response_handle(self, flow):
        pass        #To be implement by child

    
    def on_ws_from_client_to_server(self, flow, message):
        pass        #To be implement by child

    def account_login_callback(self, email):
        return self.on_account_login_callback(self, email, self.source_ip)

    def account_check_callback(self, email):
        return self.on_account_check_callback(self, email, self.source_ip)

    def conversation_callback(self, email, conversation_text, conversation_id = None):
        return self.on_conversation_callback(self, email, conversation_text, self.source_ip, conversation_id)

    def attached_file_callback(self, email, file_name, filepath, content_type):
        return self.on_attached_file_callback(self, email, file_name, filepath, content_type, self.source_ip)
    
    def allow_anonymous_access(self):
        return self.on_allow_anonymous_access(self)
    
    def anonymous_conversation_callback(self, conversation_text, conversation_id = None):
        return self.on_anonymous_conversation_callback(self, conversation_text, self.source_ip, conversation_id)


#Helper functions

def pad_b64(segment: str) -> str:
    return segment + '=' * (-len(segment) % 4)

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


import re

def parse_multipart(content_type_header, body_bytes, return_fields=False):
    # Extract boundary from Content-Type header
    match = re.search(r'boundary=(.*)', content_type_header)
    if not match:
        return [], {}

    boundary = match.group(1)
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary = boundary.encode()

    delimiter = b'--' + boundary
    parts = body_bytes.split(delimiter)[1:-1]  # Skip preamble and epilogue
    files = []
    fields = {}

    for part in parts:
        part = part.strip(b'\r\n')
        headers_body = part.split(b'\r\n\r\n', 1)
        if len(headers_body) != 2:
            continue

        headers_raw, body = headers_body
        headers_text = headers_raw.decode(errors='ignore')
        body = body.rstrip(b'\r\n')

        # Check if it's a file
        filename_match = re.search(r'filename="([^"]+)"', headers_text)
        content_type_match = re.search(r'Content-Type:\s*([^\r\n;]+)', headers_text, re.IGNORECASE)
        name_match = re.search(r'name="([^"]+)"', headers_text)

        if filename_match:
            filename = filename_match.group(1)
            content_type = content_type_match.group(1) if content_type_match else "application/octet-stream"

            files.append({
                "filename": filename,
                "content": body,
                "content_type": content_type
            })
        elif name_match:
            # Treat as a normal form field
            name = name_match.group(1)
            try:
                value = body.decode(errors='ignore')
            except Exception:
                value = body
            fields[name] = value

    if return_fields:
        return files, fields
    return files

