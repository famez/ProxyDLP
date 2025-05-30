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
import spacy
from pymongo import MongoClient
from bson.objectid import ObjectId

import grpc
from concurrent import futures
import threading
import time
import monitor_pb2
import monitor_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

background_executor = futures.ThreadPoolExecutor(max_workers=15)

db_client = MongoClient(os.getenv("MONGO_URI"))
events_collection = db_client["proxyGPT"]["events"]
regex_collection = db_client["proxyGPT"]["regex_rules"]
cos_sim_collection = db_client["proxyGPT"]["cos_sim_rules"]


nlp = spacy.load("en_core_web_sm")

embeddings_model = SentenceTransformer('all-MiniLM-L6-v2')

target_label_embeddings = {}

for target_labels in cos_sim_collection.find():
    for key, label in target_labels.items():
        if key != "_id":
        #print(f"key: {key}, label: {label}")
            target_label_embeddings[key] = embeddings_model.encode(label, convert_to_tensor=True)

def analyze_text_ner(text):
    doc = nlp(text)
    return {ent.text: ent.label_ for ent in doc.ents}
        
    
def analyze_text_cosine_similarity(text):
    similarities = {}
    feature_embedding = embeddings_model.encode(text, convert_to_tensor=True)
    for key, label_embedding in target_label_embeddings.items():
        similarity = util.cos_sim(feature_embedding, label_embedding).item()
        similarities[key] = similarity

    return similarities


def analyze_text(text):
    retVal = {}
    retVal['regex'] = analyze_text_regex(text)
    retVal['ner'] = analyze_text_ner(text)
    retVal['cos_sim'] = analyze_text_cosine_similarity(text)
    return retVal

def analyze_text_regex(text):

    regexes = {}
    for doc in regex_collection.find():
        for regex_name, regex_value in doc.items():
            if regex_name != "_id":
                compiled_regex = re.compile(regex_value)
                for line in text.splitlines():
                    match = re.search(compiled_regex, line)
                    if match:
                        regexes[match.group()] = regex_name
        
    return regexes

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

        print(f"Event obtained: {event}")
    
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
                {"$set": {"leak": leak, "content": text}}
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
        topic_rule = cos_sim_collection.find_one({'_id': ObjectId(topic_rule_id)})

        print(f"Topic Rule obtained: {topic_rule}")
    
        encoded = embeddings_model.encode(topic_rule['pattern'], convert_to_tensor=True)

        cos_sim_collection.update_one(
            {'_id': ObjectId(topic_rule_id)},  # Filter to find the document
            {'$set': {'embeddings': encoded.tolist()}}  # Field to add or update
        )

        #print(f"Topic Rule encoded: {encoded}")

    except Exception as e:
        # Handle the exception
        print(f"An error occurred: {e}")


class MonitorServicer(monitor_pb2_grpc.MonitorServicer):

    def EventAdded(self, request, context):
        print(f"Received Event ID: {request.id}")
        background_executor.submit(on_event_added, request.id)
        return monitor_pb2.MonitorReply(result=0)       #Everythig ok :)
    
    def TopicRuleAdded(self, request, context):
        print(f"Received Topic Rule ID: {request.id}")
        background_executor.submit(on_topic_rule_added, request.id)
        return monitor_pb2.MonitorReply(result=0)       #Everythig ok :)


def main():
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