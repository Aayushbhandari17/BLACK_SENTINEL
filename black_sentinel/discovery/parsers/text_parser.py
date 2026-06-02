import chardet
from black_sentinel.schemas.models import TextChunk

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

def parse(file_path: str) -> TextChunk:
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(MAX_FILE_SIZE)
            
        if not raw_data:
            return TextChunk(file_path=file_path, content="")
            
        result = chardet.detect(raw_data)
        encoding = result['encoding'] or 'utf-8'
        
        try:
            content = raw_data.decode(encoding)
        except UnicodeDecodeError:
            content = raw_data.decode('utf-8', errors='ignore')
            
        return TextChunk(file_path=file_path, content=content, metadata={"encoding": encoding})
    except Exception as e:
        print(f"Error parsing text file {file_path}: {e}")
        return TextChunk(file_path=file_path, content="")
