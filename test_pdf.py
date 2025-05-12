import sys, pathlib, pymupdf
fname = "uploads/20250512_231853.pdf"  # get document filename
with pymupdf.open(fname) as doc:  # open document
    text = chr(12).join([page.get_text() for page in doc])
# write as a binary file to support non-ASCII characters
print(text)