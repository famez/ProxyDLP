from mitmproxy import http, ctx, websocket
from mitmproxy.http import Response

import re
import os
from datetime import datetime, timezone
from pymongo import MongoClient

import grpc
import monitor_pb2
import monitor_pb2_grpc
import proxy_pb2
import proxy_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from concurrent import futures

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


db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["ProxyDLP"]["events"]
domains_collection = db_client["ProxyDLP"]["domains"]
sites_collection = db_client["ProxyDLP"]["sites"]
domain_settings_collection = db_client["ProxyDLP"]["domain-settings"]
site_settings_collection = db_client["ProxyDLP"]["site-settings"]


site_settings = site_settings_collection.find_one()
rejectSiteTraffic = (site_settings and "rejectTraffic" in site_settings and site_settings['rejectTraffic'])


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
                
    result = events_collection.insert_one(event)
    
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

    ctx.log.info("Sent event to monitor...")

    response = stub.EventAdded(mon_message)

    ctx.log.info(f"Response: {response}")


proxy = Proxy(account_login_callback, account_check_callback, conversation_callback, attached_file_callback,
              allow_anonymous_access, anonymous_conversation_callback)


proxy.register_site(ChatGPT, ["openai.com", "chatgpt.com", "oaiusercontent.com"])
proxy.register_site(Microsoft_Copilot, ["substrate.office.com/m365Copilot/Chathub", "sharepoint.com/personal", "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:",
                                        "copilot.microsoft.com/c/api/chat"])
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
            "name": site.get_name(),
            "urls": site.get_urls()
        })
    except Exception as e:
        #ctx.log.error(f"Failed to register site {site.get_name()}: {e}")
        pass


channel = grpc.insecure_channel('monitor:50051')
stub = monitor_pb2_grpc.MonitorStub(channel)


def request(flow: http.HTTPFlow) -> None:
    if not proxy.route_request(flow) and rejectSiteTraffic:
        flow.response = Response.make(403)


def response(flow: http.HTTPFlow) -> None:
    proxy.route_response(flow)


class WSHandler:
    def websocket_message(self, flow):
        # This is called when a WebSocket message is received or sent.
        message = flow.websocket.messages[-1]
        if message.from_client:
            #ctx.log.info(f"Client -> Server: {message.content}")
            #ctx.log.info(f"Request URL: {flow.request.pretty_url}")
            proxy.route_ws_from_client_to_server(flow, message)
        

addons = [WSHandler()]


class ProxyServicer(proxy_pb2_grpc.ProxyServicer):

    def SiteRejectEnabled(self, request, context):
        global rejectSiteTraffic
        ctx.log.info(f"Received SiteRejectedEnabled: {request.enabled}")
        rejectSiteTraffic = request.enabled

        return proxy_pb2.ProxyReply(result=0)       #Everything ok :)


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