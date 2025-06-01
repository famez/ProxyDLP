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
import numpy as np
import grpc
from concurrent import futures
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


def chunk_text(text, chunk_size=500, overlap=50):
    """Split text into chunks of `chunk_size` with optional `overlap`."""
    words = text.split()
    chunks = []
    for i in range(0, len(words), chunk_size - overlap):
        chunk = ' '.join(words[i:i + chunk_size])
        chunks.append(chunk)
    return chunks


def analyze_text_ner(text):
    doc = nlp(text)
    return {ent.text: ent.label_ for ent in doc.ents}


def detect_global_topics(S, sim_thresh=0.3, min_support=0.3, min_coverage=0.3):
    """
    S: np.ndarray of shape (num_topics, num_chunks)
    Returns: List of topic indices that are 'global'
    """

    S = np.array(S)

    global_topics = []
    num_topics, num_chunks = S.shape

    for i in range(num_topics):
        sim_row = S[i]  # similarities for topic i across chunks
        high_sim_idxs = np.where(sim_row >= sim_thresh)[0]

        support = len(high_sim_idxs) / num_chunks

        if len(high_sim_idxs) == 0:
            coverage = 0
        elif num_chunks == 1:
            coverage = 1.0
        else:
            coverage = (high_sim_idxs[-1] - high_sim_idxs[0]) / (num_chunks - 1)


        print(f"Coverage: {coverage}, support: {support}, high_sim_idxs: {high_sim_idxs}")

        if support >= min_support and coverage >= min_coverage:
            global_topics.append(i)

    return global_topics


def analyze_topic_leak(cosine_similarity_matrix):

    #Detect with cosine similarity matrix if a topic is present along the text.
    global_topics = detect_global_topics(cosine_similarity_matrix["matrix"])

    #Obtain the ObjectIds of the matched topics in MongoDB on the global document.
    topic_ids = [cosine_similarity_matrix["topics"][i] for i in global_topics]

    #Obtain the name of the topics and return them.
    topics = [ doc['name'] for doc in cos_sim_collection.find({"_id": {"$in": topic_ids}}) ]

    return topics
        
    
def obtain_embeddings_from_text(text):
    chunks = chunk_text(text)
    embeddings = embeddings_model.encode(chunks, normalize_embeddings=True)

    linked_data = [{"chunk": chunk, "embedding": embedding.tolist()} for chunk, embedding in zip(chunks, embeddings)]

    return linked_data


def create_cos_sim_matrix(chunk_embeddings):
    label_embeddings = [ doc['embeddings'] for doc in cos_sim_collection.find() ]
    embeddings = [ embedding["embedding"] for embedding in chunk_embeddings ]

    #Cosine similarity matrix between topic embeddings and the chunk embeddings
    S = util.cos_sim(label_embeddings, embeddings)
    
    topic_ids = [doc['_id'] for doc in cos_sim_collection.find()]

    cosine_similarity_matrix = {"topics": topic_ids, "matrix": S.tolist()}

    return cosine_similarity_matrix


def analyze_text(text):
    leak = {}
    leak['regex'] = analyze_text_regex(text)
    #leak['ner'] = analyze_text_ner(text)
    leak['ner'] = {}                    #For the moment, don't use NER as it does not provide useful information.
    chunk_embeddings = obtain_embeddings_from_text(text)
    if cos_sim_collection.count_documents({}) == 0:     #If no topics to compare with, then return empty dicts.
        cosine_similarity_matrix = {}
        leak['topic'] = []
    else:
        cosine_similarity_matrix = create_cos_sim_matrix(chunk_embeddings)
        leak['topic'] = analyze_topic_leak(cosine_similarity_matrix)

    return leak, chunk_embeddings, cosine_similarity_matrix 

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
            leak, embeddings, cos_sim_matrix = analyze_text(event['content'])
            print(f"Done: {leak}")


            result = events_collection.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": {"leak": leak, "embeddings": embeddings, "cos_sim_matrix": cos_sim_matrix}}
            )

        elif event['rational'] == "Attached file":
            text, (leak, embeddings, cos_sim_matrix) = analyze_file(event['filepath'], event['content_type'])

            result = events_collection.update_one(
                {"_id": ObjectId(event_id)},
                {"$set": {"leak": leak, "content": text, "embeddings": embeddings, "cos_sim_matrix": cos_sim_matrix}}
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
    
        encoded = embeddings_model.encode(topic_rule['pattern'], normalize_embeddings=True)

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