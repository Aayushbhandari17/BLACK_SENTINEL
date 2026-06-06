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
            
        if str(file_path).lower().endswith('.csv'):
            import csv
            import io
            try:
                f = io.StringIO(content)
                reader = csv.reader(f)
                rows = list(reader)
                if rows:
                    headers = [h.strip() if h else f"col{i}" for i, h in enumerate(rows[0])]
                    formatted_rows = []
                    formatted_rows.append(" | ".join(headers))
                    for row in rows[1:]:
                        row_strs = []
                        for c_idx, cell in enumerate(row):
                            header = headers[c_idx] if c_idx < len(headers) else f"col{c_idx}"
                            row_strs.append(f"{header}: {cell.strip()}")
                        if row_strs:
                            formatted_rows.append(" | ".join(row_strs))
                    content = "\n".join(formatted_rows)
            except Exception as e:
                print(f"Error custom parsing CSV file {file_path}: {e}")
                
        return TextChunk(file_path=file_path, content=content, metadata={"encoding": encoding})
    except Exception as e:
        print(f"Error parsing text file {file_path}: {e}")
        return TextChunk(file_path=file_path, content="")
    
class TextParser:
    def parse(self, file_path):
        result = parse(file_path)
        if isinstance(result, str):
            return result
        if hasattr(result, "content"):
            return result.content
        if hasattr(result, "text"):
            return result.text
        if isinstance(result, list):
            return "\n".join(
                getattr(x, "content", getattr(x, "text", str(x)))
                for x in result
            )
        return str(result)