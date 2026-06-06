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
                col_names = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                for row in rows:
                    row_dict = dict(zip(col_names, row))
                    row_strs = []
                    
                    # Address reconstruction if split address columns exist
                    has_addr = any(c in col_names for c in ["address_line1", "address_line2", "city", "state", "zip", "pincode"])
                    if has_addr:
                        addr_parts = []
                        for k in ["address_line1", "address_line2", "city", "state"]:
                            val = row_dict.get(k)
                            if val:
                                addr_parts.append(str(val).strip())
                        zip_val = row_dict.get("zip") or row_dict.get("pincode")
                        addr_str = ", ".join(addr_parts)
                        if zip_val:
                            addr_str += " " + str(zip_val).strip()
                        if addr_str:
                            row_strs.append(f"address: {addr_str}")
                            
                    skip_cols = {"address_line1", "address_line2", "city", "state", "zip", "pincode", "country"} if has_addr else set()
                    
                    for name, col in zip(col_names, row):
                        if col is not None and name not in skip_cols:
                            row_strs.append(f"{name}: {col}")
                            
                    if row_strs:
                        all_text.append(", ".join(row_strs))
            except Exception:
                continue
                
        conn.close()
        
        content = "\n".join(all_text)
        return TextChunk(file_path=file_path, content=content, metadata={"tables": len(tables)})
    except Exception as e:
        print(f"Error parsing sqlite file {file_path}: {e}")
        return TextChunk(file_path=file_path, content="")
    
class SQLiteParser:
    def parse(self, file_path):
        return parse(file_path).content
