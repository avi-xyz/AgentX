import re

def convert_oui():
    try:
        with open("src/engine/oui.txt", "rb") as f:
            content = f.read()
            
        with open("src/engine/mac-vendors.txt", "wb") as out:
            # IEEE format: "00-00-00   (hex)           XEROX CORPORATION"
            # Regex: ([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)
            
            pattern = re.compile(rb'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.*)')
            
            count = 0
            for line in content.splitlines():
                match = pattern.search(line)
                if match:
                    # Sanitize prefix to 000000 (no separators, upper)
                    raw_prefix = match.group(1).decode("utf8")
                    vendor = match.group(2).strip()
                    
                    prefix = raw_prefix.replace("-", "").upper()
                    
                    # Library expects bytes line: prefix:vendor
                    out.write(prefix.encode("utf8") + b":" + vendor + b"\n")
                    count += 1
                    
        print(f"Converted {count} entries.")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    convert_oui()
