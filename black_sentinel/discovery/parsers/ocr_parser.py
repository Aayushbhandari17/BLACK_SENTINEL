import os
import pytesseract
from PIL import Image

# Force link Python to your local Windows Tesseract engine location
TESSERACT_EXE_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

if os.path.exists(TESSERACT_EXE_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_EXE_PATH
else:
    print(f"[-] WARNING: Tesseract engine binary not found at {TESSERACT_EXE_PATH}. Please verify installation path.")

def extract_text_from_image(file_path):
    """
    Opens an image file, optimizes it briefly, and utilizes 
    Tesseract OCR to extract string sequences out of visual frames.
    """
    try:
        # Check if file exists safely before loading
        if not os.path.exists(file_path):
            return ""
            
        # Open the image file using Pillow
        with Image.open(file_path) as img:
            # Optional: Convert image to grayscale (L mode) to sharpen regex pattern accuracy
            if img.mode not in ('L', 'RGB'):
                img = img.convert('L')
                
            # Execute optical character recognition layout analysis
            extracted_text = pytesseract.image_to_string(img)
            
            if extracted_text.strip():
                return extracted_text
                
        return ""
        
    except Exception as e:
        print(f"[-] OCR Parsing execution failure for {file_path}: {str(e)}")
        return ""