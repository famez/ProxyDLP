from __future__ import annotations

import hashlib
import os
import re
import threading
import time as _time
import uuid
from concurrent import futures
from datetime import datetime, timezone
from typing import Any

import grpc
import psutil
from bson.objectid import ObjectId
from mitmproxy import ctx, http, websocket
from mitmproxy.http import Response
from pymongo import MongoClient
from pymongo.collection import Collection

import monitor_pb2
import monitor_pb2_grpc
import proxy_pb2
import proxy_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from proxy import Proxy
from sites.chatgpt import ChatGPT
from sites.github_copilot import Github_Copilot
from sites.microsoft_copilot import Microsoft_Copilot
from sites.deepseek import DeepSeek
from sites.blackbox import BlackBox
from sites.gemini import Gemini
from sites.deepl import DeepL
from sites.perplexity import Perplexity
from sites.grok import Grok

from mitm_term import launch_ws_term

launch_ws_term()

last_check: float = _time.time()
last_request_count: int = 0


db_client: MongoClient = MongoClient(os.getenv("MONGO_URI"))
events_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["events"]
domains_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["domains"]
sites_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["sites"]
domain_settings_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["domain-settings"]
site_settings_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["site-settings"]
agents_collection: Collection[dict[str, Any]] = db_client["ProxyDLP"]["agents"]


site_settings: dict[str, Any] | None = site_settings_collection.find_one()
rejectSiteTraffic: bool = bool(site_settings and "rejectTraffic" in site_settings and site_settings['rejectTraffic'])

def sha256_hash_file(filename: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash in chunks (good for large files)
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def find_agent_by_source_ip(ip: str) -> str | None:
    # Search for the document with the given IP
    agent: dict[str, Any] | None = agents_collection.find_one({'ip': ip})

    # Return the GUID if document exists
    if agent:
        return agent.get('guid')
    return None

#Anonymous access is allowed if no account check is enabled to authorize several account domains
def allow_anonymous_access(site: Any) -> bool:
    #Check domain check skip
    domain_settings: dict[str, Any] | None = domain_settings_collection.find_one()
    if domain_settings and "allow_anonymous" in domain_settings and domain_settings['allow_anonymous']:
        return True

    return False

#Anonymous conversations
def anonymous_conversation_callback(
    site: Any, content: str, source_ip: str, conversation_id: str | None
) -> None:
    #Workaround for DeepL to avoid receiving several successive events in few seconds
    if site.get_name() == "DeepL":

        latest_event: dict[str, Any] | None = events_collection.find_one(
            {"site": "DeepL"},
            sort=[("timestamp", -1)]
        )

        latest_timestamp: datetime | str | None = latest_event.get("timestamp")

        if latest_timestamp:
            if isinstance(latest_timestamp, str):
                latest_timestamp = datetime.fromisoformat(latest_timestamp)

            # Ensure latest_timestamp is timezone-aware (UTC)
            if latest_timestamp.tzinfo is None:
                latest_timestamp = latest_timestamp.replace(tzinfo=timezone.utc)
            now: datetime = datetime.now(timezone.utc)

            #If the event was sent less than 10 seconds ago and the new event content contains the latest one, update the last event content to the current one.
            if (now - latest_timestamp).total_seconds() < 10 and latest_event.get("content") in content:
                events_collection.update_one({"_id": latest_event["_id"]}, {"$set": {"content": content, "timestamp": now}})

                #Retrigger monitor analysis
                mon_message = monitor_pb2.EventID(id=str(latest_event["_id"]))
                ctx.log.info("Sent event to monitor...")
                response = stub.EventAdded(mon_message)
                ctx.log.info(f"Response: {response}")
                return


    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc),
        "rational": "Conversation",
        "content": content,
        "site": site.get_name(),
        "source_ip": source_ip,
    }

    if conversation_id:
        event['conversation_id'] = conversation_id

    agent_id: str | None = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))
    ctx.log.info("Sent event to monitor...")
    response = stub.EventAdded(mon_message)
    ctx.log.info(f"Response: {response}")

def account_login_callback(site: Any, email: str, source_ip: str) -> bool:
    #Check domain check skip
    domain_settings: dict[str, Any] | None = domain_settings_collection.find_one()
    if not domain_settings or not "check_domain" in domain_settings or not domain_settings['check_domain']:
        return True

    for domain in domains_collection.find():
        email_regex: str = r'^[a-zA-Z0-9._%+-]+@' + domain['content'] + '$'

        if re.match(email_regex, email):
            ctx.log.info(f"Corporative user {email} logged in")
            #Register event into the database.
            event: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc),
                "user": email,
                "rational": "Logged in",
                "site": site.get_name(),
                "source_ip": source_ip,
            }
            events_collection.insert_one(event)
            return True

    ctx.log.info(f"Email address does not belong to an organization")
    return False


def account_check_callback(site: Any, email: str, source_ip: str) -> bool:
    #Check domain check skip
    domain_settings: dict[str, Any] | None = domain_settings_collection.find_one()
    if not domain_settings or not "check_domain" in domain_settings or not domain_settings['check_domain']:
        return True

    for domain in domains_collection.find():
        email_regex: str = r'^[a-zA-Z0-9._%+\-*]+@' + domain['content'] + r'$'
        if re.match(email_regex, email):
            return True
    return False


def conversation_callback(
    site: Any, email: str, content: str, source_ip: str, conversation_id: str | None
) -> None:
    event: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc),
        "user": email,
        "rational": "Conversation",
        "content": content,
        "site": site.get_name(),
        "source_ip": source_ip,
    }

    if conversation_id:
        event['conversation_id'] = conversation_id

    agent_id: str | None = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))
    ctx.log.info("Sent event to monitor...")
    response = stub.EventAdded(mon_message)
    ctx.log.info(f"Response: {response}")

def store_file_callback(site: Any, file_content: bytes) -> str:
    # Compute SHA-256 hash of the file content
    file_hash: str = hashlib.sha256(file_content).hexdigest()

    # Check if a document with the same hash exists
    existing_doc: dict[str, Any] | None = events_collection.find_one({"hash": file_hash, "rational": "Attached file"})

    #If it is the same file, just reuse the path of an already uploaded file.
    if existing_doc:
        return existing_doc["filepath"]

    unique_id: str = uuid.uuid4().hex
    safe_filename: str = f"{unique_id}"
    filepath: str = os.path.join("/uploads", safe_filename)

    ctx.log.info(f"Saving uploaded file to {filepath}")
    with open(filepath, "wb") as f:
        f.write(file_content)

    return filepath


def attached_file_callback(
    site: Any,
    email: str | None,
    filename: str,
    filepath: str,
    content_type: str,
    source_ip: str,
) -> None:
    file_hash: str = sha256_hash_file(filepath)

    event: dict[str, Any]
    if email:
        event = {
            "timestamp": datetime.now(timezone.utc),
            "user": email,
            "rational": "Attached file",
            "filename": filename,
            "filepath": filepath,
            "content_type": content_type,
            "site": site.get_name(),
            "source_ip": source_ip,
            "hash": file_hash,
        }
    else:
        event = {
            "timestamp": datetime.now(timezone.utc),
            "rational": "Attached file",
            "filename": filename,
            "filepath": filepath,
            "content_type": content_type,
            "site": site.get_name(),
            "source_ip": source_ip,
            "hash": file_hash,
        }

    agent_id: str | None = find_agent_by_source_ip(source_ip)
    if agent_id:
        event['agent_id'] = agent_id

    result = events_collection.insert_one(event)

    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

    ctx.log.info("Sent event to monitor...")

    response = stub.EventAdded(mon_message)

    ctx.log.info(f"Response: {response}")


proxy: Proxy = Proxy(
    account_login_callback,
    account_check_callback,
    conversation_callback,
    attached_file_callback,
    allow_anonymous_access,
    anonymous_conversation_callback,
    store_file_callback,
)


proxy.register_site(ChatGPT, ["openai.com", "chatgpt.com", "oaiusercontent.com"])
proxy.register_site(Microsoft_Copilot, ["substrate.office.com", "sharepoint.com", "graph.microsoft.com",
                                        "copilot.microsoft.com"])
proxy.register_site(Github_Copilot, ["githubcopilot.com", "api.github.com"])
proxy.register_site(DeepSeek, ["deepseek.com"])
proxy.register_site(BlackBox, ["blackbox.ai"])
proxy.register_site(Gemini, ["gemini.google.com", "push.clients6.google.com"])
proxy.register_site(DeepL, ["deepl.com"])
proxy.register_site(Perplexity, ["perplexity.ai", "ppl-ai-file-upload.s3.amazonaws.com"])
proxy.register_site(Grok, ["grok.com"])


#Add sites to the database for being checked later on the web interface.
for site in proxy.get_sites():
    try:
        result = sites_collection.insert_one({
            "name": site.get_name(),        #Name is unique ID, so once it is added the first time, this will "fail"
            "urls": site.get_urls(),
            "enabled": False                #Let's default to disable all the sites.
        })
    except Exception as e:
        pass


#When initializing, let's check which sites are enabled and which are disabled.
sites = proxy.get_sites()

# Get the list of site names
site_names: list[str] = [site.get_name() for site in sites]

# Query the DB for matching names
db_sites = sites_collection.find({"name": {"$in": site_names}})

# Create a mapping { name: enabled }
enabled_map: dict[str, bool] = {doc["name"]: doc.get("enabled", False) for doc in db_sites}

# Update Site objects
for site in sites:
    if site.get_name() in enabled_map:
        if enabled_map[site.get_name()]:
            site.enable()
        else:
            site.disable()


def _config_poller(check_interval: int = 5) -> None:
    """
    Poll MongoDB every few seconds so that all proxy replicas stay in sync
    with site-enabled flags and the global rejectTraffic setting — without
    needing gRPC broadcasts from the web console.
    """
    while True:
        _time.sleep(check_interval)
        try:
            global rejectSiteTraffic
            cfg: dict[str, Any] | None = site_settings_collection.find_one()
            rejectSiteTraffic = bool(cfg and cfg.get('rejectTraffic'))

            _site_names: list[str] = [s.get_name() for s in proxy.get_sites()]
            _db_sites = sites_collection.find({"name": {"$in": _site_names}})
            _enabled_map: dict[str, bool] = {doc["name"]: doc.get("enabled", False) for doc in _db_sites}
            for s in proxy.get_sites():
                if s.get_name() in _enabled_map:
                    if _enabled_map[s.get_name()]:
                        s.enable()
                    else:
                        s.disable()
        except Exception as e:
            print(f"[config-poller] Error syncing config from MongoDB: {e}")

threading.Thread(target=_config_poller, name="config-poller", daemon=True).start()

# Soft memory limit: exit cleanly before the container OOM-kills us.
# Docker's restart: always will respawn a fresh replica automatically.
_MEMORY_SOFT_LIMIT_MB: int = 400  # ~78% of the 512 MB container limit

def _memory_watchdog(check_interval: int = 30) -> None:
    process: psutil.Process = psutil.Process(os.getpid())
    while True:
        _time.sleep(check_interval)
        mem_mb: float = process.memory_info().rss / (1024 * 1024)
        if mem_mb > _MEMORY_SOFT_LIMIT_MB:
            print(f"[memory-watchdog] RSS {mem_mb:.1f} MB exceeds soft limit {_MEMORY_SOFT_LIMIT_MB} MB — exiting for clean restart.")
            os._exit(0)

threading.Thread(target=_memory_watchdog, name="memory-watchdog", daemon=True).start()

# Maps client_conn.id -> real source IP extracted from X-Forwarded-For (injected by HAProxy).
# Populated in http_connect (for CONNECT tunnels) and in request (for plain HTTP).
_real_source_ips: dict[str, str] = {}

channel: grpc.Channel = grpc.insecure_channel('monitor:50051')
stub: monitor_pb2_grpc.MonitorStub = monitor_pb2_grpc.MonitorStub(channel)


def http_connect(flow: http.HTTPFlow) -> None:
    """Capture the real client IP from X-Forwarded-For on CONNECT requests (injected by HAProxy)."""
    xff: str = flow.request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if xff:
        _real_source_ips[flow.client_conn.id] = xff


def request(flow: http.HTTPFlow) -> None:
    # Stamp the real source IP into flow metadata so Site handlers can read it.
    real_ip: str | None = _real_source_ips.get(flow.client_conn.id)
    if real_ip:
        flow.metadata["_real_source_ip"] = real_ip
    else:
        # Plain HTTP (non-CONNECT) — HAProxy still injects XFF here.
        xff: str = flow.request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if xff:
            _real_source_ips[flow.client_conn.id] = xff
            flow.metadata["_real_source_ip"] = xff

    if not proxy.route_request(flow) and rejectSiteTraffic:
        flow.response = Response.make(403)


def response(flow: http.HTTPFlow) -> None:
    if not proxy.route_response(flow) and rejectSiteTraffic:
        flow.response = Response.make(403)


class WSHandler:
    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # This is called when a WebSocket message is received or sent.
        message: websocket.WebSocketMessage = flow.websocket.messages[-1]
        if message.from_client:
            if not proxy.route_ws_from_client_to_server(flow, message) and rejectSiteTraffic:
                # Prevent the message from being sent to the server
                message.kill()

class Monitor:
    def __init__(self) -> None:
        self.active_flows: set[str] = set()
        self.request_count: int = 0
        self.dropped_flows: int = 0
        self.peak_connections: int = 0

    def client_connected(self, client_conn: Any) -> None:
        """Called when a new TCP connection starts."""
        self.active_flows.add(client_conn.id)
        self.request_count += 1
        if len(self.active_flows) > self.peak_connections:
            self.peak_connections = len(self.active_flows)

    def client_disconnected(self, client_conn: Any) -> None:
        """Called when a TCP connection ends."""
        self.active_flows.discard(client_conn.id)
        _real_source_ips.pop(client_conn.id, None)

    def request(self, flow: http.HTTPFlow) -> None:
        """Called when a HTTP/HTTPS request is processed."""
        self.request_count += 1

    def error(self, flow: http.HTTPFlow, msg: str) -> None:
        """Called when a flow encounters an error (dropped/malformed)."""
        self.dropped_flows += 1

monitor: Monitor = Monitor()


addons = [WSHandler(), monitor]


class ProxyServicer(proxy_pb2_grpc.ProxyServicer):

    def SiteRejectEnabled(self, request: Any, context: grpc.ServicerContext) -> Any:
        global rejectSiteTraffic
        ctx.log.info(f"Received SiteRejectedEnabled: {request.enabled}")
        rejectSiteTraffic = request.enabled

        return proxy_pb2.ProxyReply(result=0)       #Everything ok :)

    def SiteMonitoringToggled(self, request: Any, context: grpc.ServicerContext) -> Any:
        ctx.log.info(f"Received SiteMonitoringToggled: {request.id}, {request.enabled}")

        db_site: dict[str, Any] | None = sites_collection.find_one({"_id": ObjectId(request.id)})

        site = proxy.get_site(db_site['name'])

        if request.enabled:
            site.enable()
        else:
            site.disable()

        return proxy_pb2.ProxyReply(result=0)       #Everything ok :)


    def GetMitmStats(self, request: Any, context: grpc.ServicerContext) -> Any:
        """Called every second by mitmproxy."""
        global last_check, last_request_count
        now: float = _time.time()
        elapsed: float = now - last_check
        pid: int = os.getpid()
        process: psutil.Process = psutil.Process(pid)
        mem: float = process.memory_info().rss / (1024 * 1024)  # MB
        rps: float = (monitor.request_count - last_request_count) / elapsed

        last_request_count = monitor.request_count
        last_check = now

        return proxy_pb2.MitmStats(
            active_connections=len(monitor.active_flows),
            peak_connections=monitor.peak_connections,
            rps=rps,
            mem=mem,
            dropped_flows=monitor.dropped_flows,
        )


# Initialize gRPC server
server: grpc.Server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
proxy_pb2_grpc.add_ProxyServicer_to_server(ProxyServicer(), server)

#For health check to ensure proper start up of the containers
# Add health service
health_servicer: health.HealthServicer = health.HealthServicer()
health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
health_servicer.set('', health_pb2.HealthCheckResponse.SERVING)

server.add_insecure_port("[::]:50051")
server.start()
print("Server running on port 50051...")


def _midnight_watcher(check_interval: int = 10) -> None:
    """
    Check local time periodically and force flows cleanup every 24 hours.
    """
    while True:
        now: datetime = datetime.now()
        ctx.log.info(f"Checking time: Hour: {now.hour}, minute: {now.minute}.")
        if now.hour == 14 and now.minute == 3:
            ctx.log.info("Midnight reached (local time). Forcing process exit to allow restart.")
            # small grace period for logs to flush
            ctx.master.view.clear()
        _time.sleep(check_interval)

# Start the watcher as a daemon thread
_thread: threading.Thread = threading.Thread(target=_midnight_watcher, name="midnight-watcher", daemon=True)
_thread.start()
