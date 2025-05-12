from PIL import Image
import pytesseract

# (Optional) Set path to tesseract.exe if needed (Windows)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Load an image from file
image = Image.open('test.png')

# Use pytesseract to do OCR on the image
text = pytesseract.image_to_string(image)

# Print the extracted text
print("Extracted Text:")
print(text)
