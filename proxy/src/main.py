from mitmproxy import http, ctx, websocket
from mitmproxy.http import Response

import re
import os
from datetime import datetime, timezone
from pymongo import MongoClient
import psutil

from bson.objectid import ObjectId

import grpc
import monitor_pb2
import monitor_pb2_grpc
import proxy_pb2
import proxy_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from concurrent import futures
import time

from proxy import Proxy
from sites.chatgpt import ChatGPT
from sites.github_copilot import Github_Copilot
from sites.microsoft_copilot import Microsoft_Copilot
from sites.deepseek import DeepSeek
from sites.blackbox import BlackBox
from sites.gemini import Gemini
from sites.deepl import DeepL


from mitm_term import launch_ws_term

launch_ws_term()

last_check = time.time()
last_request_count = 0


db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["ProxyDLP"]["events"]
domains_collection = db_client["ProxyDLP"]["domains"]
sites_collection = db_client["ProxyDLP"]["sites"]
domain_settings_collection = db_client["ProxyDLP"]["domain-settings"]
site_settings_collection = db_client["ProxyDLP"]["site-settings"]
agents_collection = db_client["ProxyDLP"]["agents"]


site_settings = site_settings_collection.find_one()
rejectSiteTraffic = (site_settings and "rejectTraffic" in site_settings and site_settings['rejectTraffic'])


def find_agent_by_source_ip(ip):
    # Search for the document with the given IP
    agent = agents_collection.find_one({'ip': ip})

    # Return the GUID if document exists
    if agent:
        return agent.get('guid')
    return None

#Anonymous access is allowed if no account check is enabled to authorize several account domains
def allow_anonymous_access(site):
    #Check domain check skip
    domain_settings = domain_settings_collection.find_one()
    if  domain_settings and "allow_anonymous" in domain_settings and domain_settings['allow_anonymous']:
        return True
    
    return False

#Anonymous conversations
def anonymous_conversation_callback(site, content, source_ip, conversation_id):

    #Workaround for DeepL to avoid receiving several successive events in few seconds
    if site.get_name() == "DeepL":

        latest_event = events_collection.find_one(
            {"site": "DeepL"},
            sort=[("timestamp", -1)]
        )

        latest_timestamp = latest_event.get("timestamp")

        if latest_timestamp:
            if isinstance(latest_timestamp, str):
                latest_timestamp = datetime.fromisoformat(latest_timestamp)

            # Ensure latest_timestamp is timezone-aware (UTC)
            if latest_timestamp.tzinfo is None:
                latest_timestamp = latest_timestamp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            #If the event was sent less than 10 seconds ago and the new event content contains the latest one, update the last event content to the current one.
            if (now - latest_timestamp).total_seconds() < 10 and latest_event.get("content") in content:
                events_collection.update_one({"_id": latest_event["_id"]}, {"$set": {"content": content, "timestamp": now}})

                #Retrigger monitor analysis
                mon_message = monitor_pb2.EventID(id=str(latest_event["_id"]))
                ctx.log.info("Sent event to monitor...")
                response = stub.EventAdded(mon_message)
                ctx.log.info(f"Response: {response}")
                return
            
                

    event = {"timestamp": datetime.now(timezone.utc), "rational": "Conversation", "content": content, "site": site.get_name(), "source_ip": source_ip}
    
    if conversation_id:
        event['conversation_id'] = conversation_id

    agent_id = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))
    ctx.log.info("Sent event to monitor...")
    response = stub.EventAdded(mon_message)
    ctx.log.info(f"Response: {response}")

def account_login_callback(site, email, source_ip):

    #Check domain check skip
    domain_settings = domain_settings_collection.find_one()
    if not domain_settings or not "check_domain" in domain_settings or not domain_settings['check_domain']:
        return True        

    for domain in domains_collection.find():

        email_regex = r'^[a-zA-Z0-9._%+-]+@' + domain['content'] + '$'

        if re.match(email_regex, email):
            ctx.log.info(f"Corporative user {email} logged in")
            #Register event into the database.
            event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Logged in", "site": site.get_name(), "source_ip": source_ip}
            events_collection.insert_one(event)
            return True

    ctx.log.info(f"Email address does not belong to an organization")
    return False


def account_check_callback(site, email, source_ip):

    #Check domain check skip
    domain_settings = domain_settings_collection.find_one()
    if not domain_settings or not "check_domain" in domain_settings or not domain_settings['check_domain']:
        return True 
    
    for domain in domains_collection.find():
        email_regex = r'^[a-zA-Z0-9._%+\-*]+@' + domain['content'] + r'$'
        if re.match(email_regex, email):
            return True
    return False


def conversation_callback(site, email, content, source_ip, conversation_id):

    event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Conversation", "content": content, "site": site.get_name(), "source_ip": source_ip}

    if conversation_id:
        event['conversation_id'] = conversation_id

    agent_id = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))
    ctx.log.info("Sent event to monitor...")
    response = stub.EventAdded(mon_message)
    ctx.log.info(f"Response: {response}")

def attached_file_callback(site, email, filename, filepath, content_type, source_ip):

    if email:

        event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Attached file", "filename" : filename, "filepath" : filepath, 
                            "content_type": content_type, "site": site.get_name(), "source_ip": source_ip}
        
    else:
        event = {"timestamp": datetime.now(timezone.utc), "rational": "Attached file", "filename" : filename, "filepath" : filepath, 
                            "content_type": content_type, "site": site.get_name(), "source_ip": source_ip}

    agent_id = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)
    
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

    ctx.log.info("Sent event to monitor...")

    response = stub.EventAdded(mon_message)

    ctx.log.info(f"Response: {response}")


proxy = Proxy(account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
              allow_anonymous_access, anonymous_conversation_callback)


proxy.register_site(ChatGPT, ["openai.com", "chatgpt.com", "oaiusercontent.com"])
proxy.register_site(Microsoft_Copilot, ["substrate.office.com/m365Copilot/Chathub", "sharepoint.com/personal", "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:",
                                        "copilot.microsoft.com"])
proxy.register_site(Github_Copilot, ["githubcopilot.com", "api.github.com/user"])
proxy.register_site(DeepSeek, ["deepseek.com"])
proxy.register_site(BlackBox, ["blackbox.ai"])
proxy.register_site(Gemini, ["gemini.google.com", "push.clients6.google.com/upload"])
proxy.register_site(DeepL, ["deepl.com"])


#Add sites to the database for being checked later on the web interface.
for site in proxy.get_sites():
    #ctx.log.info(f"Registering site {site.get_name()} with urls {site.get_urls()}")
    
    try:
        result = sites_collection.insert_one({
            "name": site.get_name(),        #Name is unique ID, so once it is added the first time, this will "fail"
            "urls": site.get_urls(),
            "enabled": False                #Let's default to disable all the sites.
        })
    except Exception as e:
        #ctx.log.error(f"Failed to register site {site.get_name()}: {e}")
        pass


#When initializing, let's check which sites are enabled and which are disabled.
sites = proxy.get_sites()

# Get the list of site names
site_names = [site.get_name() for site in sites]

# Query the DB for matching names
db_sites = sites_collection.find({"name": {"$in": site_names}})

# Create a mapping { name: enabled }
enabled_map = {doc["name"]: doc.get("enabled", False) for doc in db_sites}

# Update Site objects
for site in sites:
    if site.get_name() in enabled_map:
        if enabled_map[site.get_name()]:
            site.enable()
        else:
            site.disable()


channel = grpc.insecure_channel('monitor:50051')
stub = monitor_pb2_grpc.MonitorStub(channel)


def request(flow: http.HTTPFlow) -> None:
    if not proxy.route_request(flow) and rejectSiteTraffic:
        flow.response = Response.make(403)


def response(flow: http.HTTPFlow) -> None:
    if not proxy.route_response(flow) and rejectSiteTraffic:
        flow.response = Response.make(403)


class WSHandler:
    def websocket_message(self, flow):
        # This is called when a WebSocket message is received or sent.
        message = flow.websocket.messages[-1]
        if message.from_client:
            #ctx.log.info(f"Client -> Server: {message.content}")
            #ctx.log.info(f"Request URL: {flow.request.pretty_url}")
            if not proxy.route_ws_from_client_to_server(flow, message) and rejectSiteTraffic:
                # Prevent the message from being sent to the server
                message.kill()

class Monitor:
    def __init__(self):
        self.active_flows = set()
        self.request_count = 0
        self.dropped_flows = 0
        self.peak_connections = 0

    def client_connected(self, client_conn):
        """Called when a new TCP connection starts."""
        ctx.log.info("tcp_start")
        self.active_flows.add(client_conn.id)
        self.request_count += 1
        if len(self.active_flows) > self.peak_connections:
            self.peak_connections = len(self.active_flows)

    def client_disconnected(self, client_conn):
        """Called when a TCP connection ends."""
        ctx.log.info("tcp_end")
        self.active_flows.discard(client_conn.id)

    def request(self, flow):
        """Called when a HTTP/HTTPS request is processed."""
        self.request_count += 1

    def error(self, flow, msg):
        """Called when a flow encounters an error (dropped/malformed)."""
        self.dropped_flows += 1
        ctx.log.warn(f"Flow error: {msg}")

monitor = Monitor()


addons = [WSHandler(), monitor]


class ProxyServicer(proxy_pb2_grpc.ProxyServicer):

    def SiteRejectEnabled(self, request, context):
        global rejectSiteTraffic
        ctx.log.info(f"Received SiteRejectedEnabled: {request.enabled}")
        rejectSiteTraffic = request.enabled

        return proxy_pb2.ProxyReply(result=0)       #Everything ok :)
    
    def SiteMonitoringToggled(self, request, context):

        ctx.log.info(f"Received SiteMonitoringToggled: {request.id}, {request.enabled}")

        db_site = sites_collection.find_one({"_id": ObjectId(request.id)})

        site = proxy.get_site(db_site['name'])

        if request.enabled:
            site.enable()
        else:
            site.disable()

        return proxy_pb2.ProxyReply(result=0)       #Everything ok :)
    

    def GetMitmStats(self, request, context):

        """Called every second by mitmproxy."""
        global last_check, last_request_count, mem, rps
        now = time.time()
        elapsed = now - last_check
        pid = os.getpid()
        process = psutil.Process(pid)
        mem = process.memory_info().rss / (1024 * 1024)  # MB
        rps = (monitor.request_count - last_request_count) / elapsed
        
        last_request_count = monitor.request_count
        last_check = now


        return proxy_pb2.MitmStats(active_connections = len(monitor.active_flows), peak_connections = monitor.peak_connections, rps = rps, 
                                    mem = mem, dropped_flows = monitor.dropped_flows)


# Initialize gRPC server
server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
proxy_pb2_grpc.add_ProxyServicer_to_server(ProxyServicer(), server)

#For health check to ensure proper start up of the containers
# Add health service
health_servicer = health.HealthServicer()
health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
health_servicer.set('', health_pb2.HealthCheckResponse.SERVING)

server.add_insecure_port("[::]:50051")
server.start()
print("Server running on port 50051...")