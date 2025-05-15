import spacy

nlp = spacy.load("en_core_web_sm")

text = "Introduce user and password, go to the diagnostic interface and perform a test by clicking on the button to check that the loudspeakers work properly."

doc = nlp(text)
for ent in doc.ents:
    print(ent.text, "-", ent.label_)
