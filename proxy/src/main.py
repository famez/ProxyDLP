from mitmproxy import http, ctx
from mitmproxy.http import Response
import re
import os
from datetime import datetime, timezone
from pymongo import MongoClient

import grpc
import monitor_pb2
import monitor_pb2_grpc

from proxy import Proxy
from chatgpt import ChatGPT


from mitm_term import launch_ws_term

launch_ws_term()


db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["proxyGPT"]["events"]
domains_collection = db_client["proxyGPT"]["domains"]

class EmailNotFoundException(Exception):
    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"Validation error on '{field}': {message}")
    

def account_login_callback(email):

    for domain in domains_collection.find():

        email_regex = r'^[a-zA-Z0-9._%+-]+@' + domain['content'] + '$'

        if re.match(email_regex, email):
            ctx.log.info(f"Corporative user {email} logged in")
            #Register event into the database.
            event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Logged in", "detail" : ""}
            events_collection.insert_one(event)
            return True

    ctx.log.info(f"Email address does not belong to an organization")
    return False



def account_check_callback(email):
    for domain in domains_collection.find():
        email_regex = r'^[a-zA-Z0-9._%+-]+@' + domain['content'] + '$'
        if re.match(email_regex, email):
            return True
    return False


def conversation_callback(email, content):

    event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Conversation", "content": content}
    result = events_collection.insert_one(event)
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))
    ctx.log.info("Sent event to monitor...")
    response = stub.EventAdded(mon_message)
    ctx.log.info(f"Response: {response}")

def attached_file_callback(email, filename, filepath, content_type):

    event = {"timestamp": datetime.now(timezone.utc), "user": email, "rational": "Attached file", "filename" : filename, "filepath" : filepath, 
                        "content_type": content_type}
                
    result = events_collection.insert_one(event)
    
    mon_message = monitor_pb2.EventID(id=str(result.inserted_id))

    ctx.log.info("Sent event to monitor...")

    response = stub.EventAdded(mon_message)

    ctx.log.info(f"Response: {response}")


proxy = Proxy(account_login_callback, account_check_callback, conversation_callback, attached_file_callback)


proxy.register_site(ChatGPT, ["openai.com", "chatgpt.com", "oaiusercontent.com"])


channel = grpc.insecure_channel('monitor:50051')
stub = monitor_pb2_grpc.MonitorStub(channel)


def request(flow: http.HTTPFlow) -> None:
    proxy.route_request(flow)