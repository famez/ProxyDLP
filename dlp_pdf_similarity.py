# dlp_embedding_search.py

import fitz  # PyMuPDF for PDF reading
import nltk
nltk.download('punkt')
nltk.download('punkt_tab')
nltk.download('punkt')
nltk.download('wordnet')
nltk.download('omw-1.4')



from nltk.tokenize import sent_tokenize
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss

nltk.download('punkt')  # Sentence tokenizer

# --- CONFIGURATION ---
PDF_PATH = 'test.pdf'
MODEL_NAME = 'all-MiniLM-L6-v2'
CHUNK_SIZE = 300     # in words
CHUNK_OVERLAP = 50   # in words
TOP_K = 10            # number of matches to return
SIMILARITY_THRESHOLD = 0.3  # cosine similarity threshold

# --- 1. EXTRACT TEXT FROM PDF ---
def extract_text_from_pdf(path):
    doc = fitz.open(path)
    return [page.get_text() for page in doc]

# --- 2. CHUNK TEXT INTO OVERLAPPING WINDOWS ---
def chunk_text(text, max_words=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    sentences = sent_tokenize(text)
    chunks = []
    chunk = []
    length = 0

    for sentence in sentences:
        words = sentence.split()
        if length + len(words) > max_words:
            chunks.append(" ".join(chunk))
            chunk = chunk[-overlap:] if overlap else []
            length = sum(len(s.split()) for s in chunk)
        chunk.append(sentence)
        length += len(words)

    if chunk:
        chunks.append(" ".join(chunk))
    return chunks

# --- 3. BUILD CHUNK LIST FROM MULTIPLE PAGES ---
def build_chunks_from_pdf(pdf_path):
    pages = extract_text_from_pdf(pdf_path)
    all_chunks = []
    metadata = []
    for page_num, text in enumerate(pages):
        chunks = chunk_text(text)
        all_chunks.extend(chunks)
        metadata.extend([{'page': page_num + 1, 'chunk': c} for c in chunks])
    return all_chunks, metadata

# --- 4. ENCODE CHUNKS WITH SENTENCE TRANSFORMERS ---
def embed_chunks(model, chunks):
    return model.encode(chunks, convert_to_numpy=True, normalize_embeddings=True)

# --- 5. BUILD FAISS INDEX ---
def build_faiss_index(embeddings):
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)  # Inner Product for cosine similarity (after normalization)
    index.add(embeddings)
    return index

# --- 6. SEARCH INPUT TEXT AGAINST INDEX ---
def search(input_text, model, index, metadata, top_k=TOP_K, threshold=SIMILARITY_THRESHOLD):
    input_embedding = model.encode([input_text], convert_to_numpy=True, normalize_embeddings=True)
    scores, indices = index.search(input_embedding, top_k)
    results = []
    for score, idx in zip(scores[0], indices[0]):
        if score >= threshold:
            results.append({
                'score': float(score),
                'page': metadata[idx]['page'],
                'text': metadata[idx]['chunk'][:200] + '...'
            })
    return results

# --- MAIN WORKFLOW ---
def main():
    print("🔍 Loading PDF and chunking...")
    chunks, metadata = build_chunks_from_pdf(PDF_PATH)

    print(f"📄 Extracted {len(chunks)} chunks from PDF.")
    model = SentenceTransformer(MODEL_NAME)

    print("🧠 Embedding chunks...")
    embeddings = embed_chunks(model, chunks)

    print("📦 Building FAISS index...")
    index = build_faiss_index(embeddings)

    # 🔎 Example query
    query = "Authentication via Radius server."
    print(f"\n🔍 Searching for: \"{query}\"\n")
    results = search(query, model, index, metadata)

    print("📌 Top Matches:")
    for r in results:
        print(f"\n[Page {r['page']}] (Score: {r['score']:.2f})\n{r['text']}")

if __name__ == "__main__":
    main()
