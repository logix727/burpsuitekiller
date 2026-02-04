import re

def test_regex():
    # Mimic a CSV line
    csv_line = '1,http://example.com,data,more'
    
    # Updated Regex (same as in input_parser.py)
    pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^,\s"\'<>]*')
    matches = pattern.findall(csv_line)
    
    print(f"Input: {csv_line}")
    print(f"Matches (Raw): {matches}")
    
    cleaned = [m.strip(",.;'\"") for m in matches]
    print(f"Matches (Cleaned): {cleaned}")
    
    # Verification
    if "http://example.com" in cleaned[0] and len(cleaned[0]) == len("http://example.com"):
        print("SUCCESS: Found exact URL")
    else:
        print("FAILURE: Did not find exact URL (likely captured extra chars)")

if __name__ == "__main__":
    test_regex()
