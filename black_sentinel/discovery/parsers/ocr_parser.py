import os
import pytesseract
from PIL import Image

# Force link Python to your local Windows Tesseract engine location
TESSERACT_EXE_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

if os.path.exists(TESSERACT_EXE_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_EXE_PATH
else:
    print(f"[-] WARNING: Tesseract engine binary not found at {TESSERACT_EXE_PATH}. Please verify installation path.")

from PIL import Image, ImageFilter, ImageEnhance

def preprocess_for_ocr(img):
    img = img.convert('L')                              # grayscale
    img = img.filter(ImageFilter.SHARPEN)               # sharpen edges
    img = ImageEnhance.Contrast(img).enhance(2.0)       # boost contrast
    img = img.point(lambda x: 0 if x < 140 else 255)   # binarize
    return img

def get_tesseract_languages():
    try:
        return pytesseract.get_languages()
    except Exception:
        return ['eng']

def extract_text_with_confidence(img, min_confidence=60):
    available_langs = get_tesseract_languages()
    langs = []
    if 'eng' in available_langs:
        langs.append('eng')
    if 'hin' in available_langs:
        langs.append('hin')
    lang_str = '+'.join(langs) if langs else 'eng'
    
    try:
        data = pytesseract.image_to_data(
            preprocess_for_ocr(img),
            output_type=pytesseract.Output.DICT,
            lang=lang_str
        )
        words = []
        for word, conf in zip(data.get('text', []), data.get('conf', [])):
            try:
                conf_val = int(conf)
            except ValueError:
                conf_val = -1
            if word.strip() and conf_val >= min_confidence:
                words.append(word)
        return ' '.join(words)
    except Exception as e:
        print(f"[-] OCR failed with lang_str {lang_str}: {e}. Retrying with 'eng'...")
        try:
            return pytesseract.image_to_string(preprocess_for_ocr(img), lang='eng')
        except Exception as ex:
            print(f"[-] Fallback OCR failed: {ex}")
            return ""

def extract_text_from_image(file_path):
    """
    Opens an image file, optimizes it briefly, and utilizes 
    Tesseract OCR to extract string sequences out of visual frames.
    """
    try:
        if not os.path.exists(file_path):
            return ""
            
        with Image.open(file_path) as img:
            extracted_text = extract_text_with_confidence(img, min_confidence=60)
            if extracted_text.strip():
                return extracted_text
                
        return ""
        
    except Exception as e:
        print(f"[-] OCR Parsing execution failure for {file_path}: {str(e)}")
        return ""
    
class OCRParser:
    def parse(self, file_path):
        return extract_text_from_image(file_path)