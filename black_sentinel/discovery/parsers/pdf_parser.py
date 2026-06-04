import pypdf
import os

def extract_text_from_pdf(file_path):
    """Extracts text content from a PDF file page by page."""
    text_content = []
    try:
        if not os.path.exists(file_path):
            return ""
            
        with open(file_path, 'rb') as f:
            reader = pypdf.PdfReader(f)
            # Loop through all pages and extract text
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_content.append(page_text)
                    
        return "\n".join(text_content)
        
    except Exception as e:
        print(f"[-] PDF Parsing failed for {file_path}: {str(e)}")
        return ""