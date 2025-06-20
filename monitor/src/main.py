import re
import os
import pymupdf
from openpyxl import load_workbook
from docx import Document
from PIL import Image
import pytesseract
import io
import zipfile
from sentence_transformers import SentenceTransformer, util
#import spacy
from pymongo import MongoClient, ReturnDocument
from bson.objectid import ObjectId
import numpy as np
import grpc
from concurrent import futures
import monitor_pb2
import monitor_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
import faiss
import yara
from readerwriterlock import rwlock

INDEX_PATH = '/var/faiss/faiss_index.index'

background_executor = futures.ThreadPoolExecutor(max_workers=15)

db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["proxyGPT"]["events"]
regex_collection = db_client["proxyGPT"]["regex_rules"]
topics_collection = db_client["proxyGPT"]["topic_rules"]
counter_collection = db_client["proxyGPT"]["faiss_id_counters"]
yara_rules_collection = db_client["proxyGPT"]["yara_rules"]

#nlp = spacy.load("en_core_web_sm")

# Global shared resources and RWLocks
regex_rules = {}
regex_rw_lock = rwlock.RWLockFair()

faiss_index = None
faiss_rw_lock = rwlock.RWLockFair()

yara_rules_compiled = None
yara_rw_lock = rwlock.RWLockFair()

embeddings_model = SentenceTransformer('all-MiniLM-L6-v2')


def load_regex_rules():
    global regex_rules
    with regex_rw_lock.gen_wlock():
        rules = {}
        for doc in regex_collection.find():
            for regex_name, regex_value in doc.items():
                if regex_name != "_id":
                    rules[regex_name] = re.compile(regex_value)
        regex_rules = rules

def load_yara_rules():
    global yara_rules_compiled
    rule_sources = {}
    for doc in yara_rules_collection.find():
        try:
            rule_sources[doc['name']] = doc['content']
        except KeyError:
            print(f"Invalid YARA rule doc: {doc}")

    yara_rules_compiled = yara.compile(sources=rule_sources)
    with yara_rw_lock.gen_wlock():
        yara_rules_compiled.save("/tmp/yara_rules.yara")

def load_faiss_index():
    global faiss_index
    with faiss_rw_lock.gen_wlock():
        if os.path.exists(INDEX_PATH):
            faiss_index = faiss.read_index(INDEX_PATH)
        else:
            dim = 384  # Embedding size
            flat = faiss.IndexFlatIP(dim)
            faiss_index = faiss.IndexIDMap2(flat)


def match_regex(text):
    matches = {}
    with regex_rw_lock.gen_rlock():
        for name, pattern in regex_rules.items():
            for match in pattern.finditer(text):
                matches[match.group()] = name
    return matches

def match_yara(text):
    leaks = []

    # Acquire read lock
    with yara_rw_lock.gen_rlock():
        compiled_copy = yara.load("/tmp/yara_rules.yara")

    # Now perform the match
    matches = compiled_copy.match(data=text)
    for match in matches:
        matched_strings = []
        for string_match in match.strings:
            identifier = string_match.identifier
            for instance in string_match.instances:
                matched_strings.append({
                    "offset": instance.offset,
                    "identifier": identifier,
                    "data": instance.matched_data.decode(errors="ignore")
                })
        leaks.append({
            "name": match.rule,
            "matched_strings": matched_strings,
            "tags": match.tags,
            "meta": match.meta
        })
    return leaks


def search_faiss(embedding_vector):
    with faiss_rw_lock.gen_rlock():
        scores, indices = faiss_index.search(embedding_vector.reshape(1, -1), 10)
    return scores, indices

def reload_all_rules():
    load_regex_rules()
    load_yara_rules()
    load_faiss_index()

def get_next_faiss_id():
    counter = counter_collection.find_one_and_update(
        {"_id": "faiss_id_counter"},
        {"$inc": {"last_id": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER
    )
    return counter["last_id"]

def validate_yara_rule_string(rule_str):
    try:
        yara.compile(source=rule_str)
        print("YARA rule is valid.")
        return True
    except yara.SyntaxError as e:
        print(f"Syntax error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def chunk_text(text, chunk_size=500, overlap=50):
    """Split text into chunks of `chunk_size` with optional `overlap`."""
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size - overlap):
        chunk = ' '.join(words[i:i + chunk_size])
        chunks.append(chunk)
    return chunks


def analyze_topic_leak(text):

    leaked_topics = []
    chunk_embeddings = obtain_embeddings_from_text(text)
    
    # Let's check if the is similarity with the faiss index
    embedding_vectors = np.array([emb['embedding'] for emb in chunk_embeddings], dtype='float32')
    for embedding in embedding_vectors:
        #faiss_index.hnsw.efSearch = 16  # Query time accuracy/speed tradeoff, default is 16
        scores, indices = search_faiss(embedding)  # This will use the global faiss_index
        for score, idx in zip(scores[0], indices[0]):
            if score >= 0.3:        #Cosine similarity threshold higher or equals to 0.3
                print(f"Found similar embedding with score {score} at index {idx}")

                doc = topics_collection.find_one(
                    {"faiss_indexes.faiss_id": int(idx)},
                    {"faiss_indexes.$": 1, "name": 1}  # Only project the matched index with the chunk
                )

                if doc:
                    print("Matched Document ID:", doc["_id"])
                    leaked_topics.append({"name": doc['name'], "faiss_id": int(idx), "score": float(score)})

                else:
                    print("No matching document found.")

    return leaked_topics

    
def obtain_embeddings_from_text(text):
    chunks = chunk_text(text)
    embeddings = embeddings_model.encode(chunks, normalize_embeddings=True)

    linked_data = [{"chunk": chunk, "embedding": embedding.tolist()} for chunk, embedding in zip(chunks, embeddings)]

    return linked_data



def analyze_text(text):
    leak = {}
    leak['regex'] = analyze_text_regex(text)
    leak['topic'] = analyze_topic_leak(text)
    leak['yara'] = analyze_text_yara(text)

    return leak

def analyze_text_regex(text):

    return match_regex(text)
        


def analyze_text_yara(text):

    return match_yara(text)


def decode_file(filepath, content_type):

    text = ""
    if content_type == "application/pdf":
        with pymupdf.open(filepath) as doc:  # open document
            text = chr(12).join([page.get_text() for page in doc])

            #Extract images and apply OCR
            for page_num in range(len(doc)):
                page = doc[page_num]
                image_list = page.get_images(full=True)
                print(f"[+] Found {len(image_list)} images on page {page_num}")

                for img_index, img in enumerate(image_list):
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image = Image.open(io.BytesIO(image_bytes))
                    text += pytesseract.image_to_string(image)
                                    
    elif content_type == "application/vnd.ms-excel" or content_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        workbook = load_workbook(filename=filepath)
        text_data = []
    
        for sheet in workbook.sheetnames:
            ws = workbook[sheet]
            for row in ws.iter_rows(values_only=True):
                row_text = ' '.join([str(cell) for cell in row if cell is not None])
                text_data.append(row_text)
        
        text = '\n'.join(text_data)

    elif content_type == "application/msword" or content_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        doc = Document(filepath)
        text = [para.text for para in doc.paragraphs if para.text.strip()]
        text = '\n'.join(text)

        extract_images_from_docx(filepath)


    elif content_type == "image/jpeg" or content_type == "image/png" or content_type == "image/gif" or content_type == "image/bmp" or content_type == "image/webp" or content_type == "image/svg+xml" or content_type == "image/tiff" or content_type == "image/vnd.microsoft.icon":
        
        image = Image.open(filepath)
        text = pytesseract.image_to_string(image)

    elif content_type == "text/plain":
        with open(filepath, 'r') as file:
            text = file.read()
    
    return text


def analyze_file(filepath, content_type):
    text = decode_file(filepath, content_type)
    return text, analyze_text(text)



def extract_images_from_docx(docx_path, output_folder="extracted_images"):
    with zipfile.ZipFile(docx_path, 'r') as docx_zip:
        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)

        # Loop through files in the ZIP and extract images
        for file in docx_zip.namelist():
            if file.startswith("word/media/"):
                filename = os.path.basename(file)
                if filename:  # skip folders
                    target_path = os.path.join(output_folder, filename)
                    with open(target_path, "wb") as img_file:
                        img_file.write(docx_zip.read(file))
                    print(f"Saved image: {target_path}")


def on_event_added(event_id):
    try:
        print(f"Started on_event_added for Event ID: {event_id}")
        event = events_collection.find_one({'_id': ObjectId(event_id)})

        print(f"Event obtained")
    
        leak = {}
        result = {}

        if event['rational'] == "Conversation":
            print(f"Conversation, analysing: {event['content']}")
            leak = analyze_text(event['content'])
            print(f"Done: {leak}")


            result = events_collection.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": {"leak": leak}}
            )

        elif event['rational'] == "Attached file":
            text, leak = analyze_file(event['filepath'], event['content_type'])

            result = events_collection.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": {"leak": leak}}
            )


        if result.modified_count > 0:
            print("Document updated successfully.")
        else:
            print("No changes made or document not found.")


        print(f"Finished long task for Event ID: {event_id}")

    except Exception as e:
        # Handle the exception
        print(f"An error occurred: {e}")


def on_topic_rule_added(topic_rule_id):
    try:

        print(f"Started on_topic_rule_added for Topic Rule ID: {topic_rule_id}")
        topic_rule = topics_collection.find_one({'_id': ObjectId(topic_rule_id)})

        print(f"Topic Rule obtained: {topic_rule}")

        chunks = chunk_text(topic_rule['pattern'])
        embeddings = embeddings_model.encode(chunks, normalize_embeddings=True)
        faiss_indexes = [get_next_faiss_id() for chunk in chunks]

        # Prepare data
        ids = np.array(faiss_indexes, dtype='int64')

        # Add embeddings to FAISS index with write lock
        with faiss_rw_lock.gen_wlock():
            faiss_index.add_with_ids(embeddings, ids)
            # Save the FAISS index to disk
            faiss.write_index(faiss_index, INDEX_PATH)

        topics_collection.update_one(
            {'_id': ObjectId(topic_rule_id)},  # Filter to find the document
            {'$set': {'faiss_indexes': faiss_indexes}}  # Field to add or update
        )

        #print(f"Topic Rule encoded: {encoded}")

    except Exception as e:
        # Handle the exception
        print(f"An error occurred: {e}")


def remove_topic_rule(topic_rule_id, delete_only_indexes=False):
    print(f"Received Topic Rule ID: {topic_rule_id}")

    topic_rule = topics_collection.find_one({'_id': ObjectId(topic_rule_id)})

    ids = np.array(topic_rule['faiss_indexes'], dtype='int64')
    selector = faiss.IDSelectorBatch(ids)
    with faiss_rw_lock.gen_wlock():
        faiss_index.remove_ids(selector)
        # Save the FAISS index to disk
        faiss.write_index(faiss_index, INDEX_PATH)

    if delete_only_indexes:
        topics_collection.update_one(
            {'_id': ObjectId(topic_rule_id)},
            {'$unset': {'faiss_indexes': ""}}
        )
    else:
        topics_collection.delete_one({'_id': ObjectId(topic_rule_id)})

    
    

class MonitorServicer(monitor_pb2_grpc.MonitorServicer):

    def EventAdded(self, request, context):
        print(f"Received Event ID: {request.id}")
        background_executor.submit(on_event_added, request.id)
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)
    
    def TopicRuleAdded(self, request, context):
        print(f"Received Topic Rule ID: {request.id}")
        background_executor.submit(on_topic_rule_added, request.id)
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)
    
    def TopicRuleRemoved(self, request, context):
        remove_topic_rule(request.id, delete_only_indexes=False)
        
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)
    
    def TopicRuleEdited(self, request, context):
        remove_topic_rule(request.id, delete_only_indexes=True)
        background_executor.submit(on_topic_rule_added, request.id)
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)
    
    #We have this callback to check if the Yara rule is valid before saving it to the database
    def YaraRuleAdded(self, yara_rule, context):
        print(f"Received Yara rule name: {yara_rule.name}")

        if not validate_yara_rule_string(yara_rule.content):
            print(f"Invalid Yara rule: {yara_rule.name}")
            return monitor_pb2.MonitorReply(result=1)
        
        try:
            # Save the Yara rule to the database
            yara_rules_collection.insert_one({
                "name": yara_rule.name,
                "content": yara_rule.content
            })

            load_yara_rules()  # Reload Yara rules after adding a new one
        except Exception as e:
            print(f"Error saving Yara rule: {e}")
            return monitor_pb2.MonitorReply(result=2)
        
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)
    
    def YaraRuleEdited(self, yara_rule_edit_request, context):
        print(f"Received Yara rule name: {yara_rule_edit_request.rule.name}")
        print(f"Received Yara rule id: {yara_rule_edit_request.id.id}")

        if not validate_yara_rule_string(yara_rule_edit_request.rule.content):
            print(f"Invalid Yara rule: {yara_rule_edit_request.rule.name}")
            return monitor_pb2.MonitorReply(result=1)
        
        try:
            # Save the Yara rule to the database
            yara_rules_collection.update_one( 
                {'_id': ObjectId(yara_rule_edit_request.id.id)},  # Filter to find the document
                {'$set': 
                    {  
                        "name": yara_rule_edit_request.rule.name,
                        "content": yara_rule_edit_request.rule.content
                    }
                }  # Field to add or update
            )

            load_yara_rules()  # Reload Yara rules after adding a new one
        except Exception as e:
            print(f"Error saving Yara rule: {e}")
            return monitor_pb2.MonitorReply(result=2)
        
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)

    def YaraRuleDeleted(self, yara_rule, context):
        load_yara_rules()  # Reload Yara rules after removing it
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)

    def RegexRuleAdded(self, regex_rule, context):
        load_regex_rules()
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)

    def RegexRuleRemoved(self, regex_rule, context):
        load_regex_rules()
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)

    def RegexRuleEdited(self, regex_rule, context):
        load_regex_rules()
        return monitor_pb2.MonitorReply(result=0)       #Everything ok :)


def main():

    reload_all_rules()  # Load all rules at startup

    # Initialize gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    monitor_pb2_grpc.add_MonitorServicer_to_server(MonitorServicer(), server)

    #For health check to ensure proper start up of the containers
    # Add health service
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    health_servicer.set('', health_pb2.HealthCheckResponse.SERVING)

    server.add_insecure_port("[::]:50051")
    server.start()
    print("Server running on port 50051...")
    server.wait_for_termination() 

if __name__ == "__main__":
    main()