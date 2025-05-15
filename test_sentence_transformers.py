from sentence_transformers import SentenceTransformer, util

model = SentenceTransformer('all-MiniLM-L6-v2')

feature = "Introduce user and password, go to the diagnostic interface and perform a test b clicking on the button to check that the loudspeakers work properly"
target = "User manual for engineering"

# Get embeddings
emb1 = model.encode(feature, convert_to_tensor=True)
emb2 = model.encode(target, convert_to_tensor=True)

similarity = util.cos_sim(emb1, emb2)
print("Similarity:", similarity.item())
