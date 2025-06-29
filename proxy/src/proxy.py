from mitmproxy import ctx

class Proxy:
    def __init__(self, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        self.sites = []
        self.account_login_callback = account_login_callback
        self.account_check_callback = account_check_callback
        self.conversation_callback = conversation_callback
        self.attached_file_callback = attached_file_callback

    def register_site(self, cls, urls):
        site = cls(urls, self.account_login_callback, self.account_check_callback, self.conversation_callback, self.attached_file_callback)
        self.sites.append(site)

    def route_request(self, flow):
        url = flow.request.pretty_url
        for site in self.sites:
            for site_url in site.get_urls():
                if site_url in url:
                    site.handle_request(flow)

    def route_response(self, flow):
        url = flow.request.pretty_url
        for site in self.sites:
            for site_url in site.get_urls():
                if site_url in url:
                    site.handle_response(flow)

                    
    def route_ws_from_client_to_server(self, flow, message):
        url = flow.request.pretty_url
        for site in self.sites:
            for site_url in site.get_urls():
                if site_url in url:
                    site.handle_ws_from_client_to_server(flow, message)
                    return
                
    def get_sites(self):
        return self.sites
    

class EmailNotFoundException(Exception):
    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"Validation error on '{field}': {message}")

class Site:
    def __init__(self, name, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        self.name = name
        self.urls = urls
        self.on_account_login_callback = account_login_callback
        self.on_account_check_callback = account_check_callback
        self.on_conversation_callback = conversation_callback
        self.on_attached_file_callback = attached_file_callback

    def get_urls(self):
        return self.urls
    
    def get_name(self):
        return self.name

    def handle_request(self, flow):
        self.on_request_handle(flow)

    def handle_response(self, flow):
        self.on_response_handle(flow)
        
    def handle_ws_from_client_to_server(self, flow, message):
        # This method is called when a WebSocket message is sent from the client to the server
        self.on_ws_from_client_to_server(flow, message)


    def on_request_handle(self, flow):
        pass        #To be implement by child

    def on_response_handle(self, flow):
        pass        #To be implement by child

    
    def on_ws_from_client_to_server(self, flow, message):
        pass        #To be implement by child

    def account_login_callback(self, email):
        return self.on_account_login_callback(self, email)

    def account_check_callback(self, email):
        return self.on_account_check_callback(self, email)

    def conversation_callback(self, email, conversation_text):
        return self.on_conversation_callback(self, email, conversation_text)

    def attached_file_callback(self, email, file_name, filepath, content_type):
        return self.on_attached_file_callback(self, email, file_name, filepath, content_type)

