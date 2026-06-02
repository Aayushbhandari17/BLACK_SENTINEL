import sqlite3
from black_sentinel.schemas.models import TextChunk

def parse(file_path: str) -> TextChunk:
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        all_text = []
        for table in tables:
            table_name = table[0]
            try:
                # Use double quotes around table name for safer handling
                cursor.execute(f'SELECT * FROM "{table_name}"')
                rows = cursor.fetchall()
                for row in rows:
                    for col in row:
                        if isinstance(col, str):
                            all_text.append(col)
            except Exception:
                continue
                
        conn.close()
        
        content = "\n".join(all_text)
        return TextChunk(file_path=file_path, content=content, metadata={"tables": len(tables)})
    except Exception as e:
        print(f"Error parsing sqlite file {file_path}: {e}")
        return TextChunk(file_path=file_path, content="")
