import re
import csv
from typing import List, Optional

def extract_urls_from_text(text: str) -> List[str]:
    """
    Finds HTTP/HTTPS URLs and bare domains in text.
    """
    found = []
    
    # 1. Standard Links (http/https) - stopping at delimiters
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^,\s"\'<>]*')
    found.extend(url_pattern.findall(text))
    
    # 2. Bare Domains (e.g. www.google.com, api.test.com)
    # Be careful not to match valid words, so look for dot in middle
    domain_pattern = re.compile(r'(?:\s|^|"|\'|,)([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,})(?:[^a-zA-Z0-9-]|$)', re.MULTILINE)
    domains = domain_pattern.findall(text)
    
    for d in domains:
        # Filter common false positives
        if d.lower() not in ["node.js", "react.js", "vue.js", "main.py", "styles.css"]:
            found.append(f"https://{d}")
    
    # Clean trailing punctuation
    cleaned = []
    for f in found:
        cleaned.append(f.strip(",.;'\""))
        
    return list(set(cleaned))

def read_file_robust(file_path: str) -> str:
    """Reads a file trying multiple encodings."""
    encodings = ['utf-8', 'latin-1', 'utf-16', 'cp1252']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.read()
        except: continue
    return ""

def extract_urls_from_csv(file_path: str, column: Optional[str] = None) -> List[str]:
    urls = []
    # Reuse robust file read
    content = read_file_robust(file_path)
    if content:
        urls = extract_urls_from_text(content)
    return urls

def extract_urls_from_excel(file_path: str) -> List[str]:
    """Scans an Excel file for URLs in all cells."""
    import openpyxl
    urls = []
    try:
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                for cell in row:
                    if cell is not None:
                        # Convert all cell types to string for regex scanning
                        cell_str = str(cell)
                        found = extract_urls_from_text(cell_str)
                        urls.extend(found)
        wb.close()
    except Exception as e:
        # Re-raise to let UI handle it
        raise e
    
    return list(set(urls))
