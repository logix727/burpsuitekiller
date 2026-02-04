from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from typing import List, Dict
import difflib

def generate_pdf_report(filename: str, results: List[Dict]):
    """Generates a simple PDF audit report."""
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "API Security Audit Report")
    y -= 30
    
    c.setFont("Helvetica", 12)
    for res in results:
        if y < 50:
            c.showPage()
            y = height - 50
            
        c.drawString(50, y, f"URL: {res.get('url')}")
        y -= 15
        c.drawString(50, y, f"Status: {res.get('status')}")
        y -= 15
        
        errors = res.get('errors', [])
        if errors:
            c.setFillColorRGB(1, 0, 0)
            c.drawString(50, y, f"Risks: {', '.join(errors)}")
            c.setFillColorRGB(0, 0, 0)
        else:
            c.setFillColorRGB(0, 0.5, 0)
            c.drawString(50, y, "No obvious risks found.")
            c.setFillColorRGB(0, 0, 0)
            
        y -= 30
        
    c.save()

def diff_responses(content_a: str, content_b: str) -> str:
    """Returns a simplified text diff between two response bodies."""
    diff = difflib.unified_diff(
        content_a.splitlines(), 
        content_b.splitlines(), 
        lineterm=''
    )
    # Filter for changes only
    changes = [line for line in diff if line.startswith('+') or line.startswith('-')]
    return "\n".join(changes[:20])  # Limit to first 20 lines
