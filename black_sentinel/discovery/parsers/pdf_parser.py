import pdfplumber
import pypdfium2 as pdfium
import os
from black_sentinel.discovery.parsers.ocr_parser import extract_text_with_confidence

def extract_text_from_pdf(file_path):
    """Extracts text content from a PDF file natively, or falls back to OCR if scanned."""
    try:
        if not os.path.exists(file_path):
            return ""
            
        text = ""
        try:
            with pdfplumber.open(file_path) as pdf:
                text = '\n'.join(p.extract_text() or '' for p in pdf.pages)
        except Exception as e:
            print(f"[-] Native pdfplumber extraction failed: {e}")
            
        if len(text.strip()) > 50:
            return text
            
        # Fall back to OCR using pypdfium2
        ocr_texts = []
        try:
            pdf = pdfium.PdfDocument(file_path)
            for page in pdf:
                bitmap = page.render(scale=3)  # ~300 DPI
                img = bitmap.to_pil()
                page_text = extract_text_with_confidence(img, min_confidence=60)
                if page_text.strip():
                    ocr_texts.append(page_text)
            return "\n".join(ocr_texts)
        except Exception as e:
            print(f"[-] OCR fallback failed for PDF {file_path}: {e}")
            return text
            
    except Exception as e:
        print(f"[-] PDF Parsing failed for {file_path}: {str(e)}")
        return ""
    
class PDFParser:
    def parse(self, file_path):
        return extract_text_from_pdf(file_path)