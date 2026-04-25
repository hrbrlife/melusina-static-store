#!/usr/bin/env python3
"""Fix Python-style Unicode escapes and other text issues in main.jsx"""

with open('src/main.jsx', encoding='utf-8') as f:
    content = f.read()

# Count occurrences before
count1 = content.count("\\U0001FA9D")
count2 = content.count("\\U0001F3CD")
print(f"Found {count1} occurrences of \\U0001FA9D")
print(f"Found {count2} occurrences of \\U0001F3CD")

# Replace Python-style \U escapes with actual emoji characters
# \U0001FA9D = 🪝 (hook)
content = content.replace("\\U0001FA9D", "\U0001FA9D")

# \U0001F3CD = 🏍 (motorcycle) - keep the \uFE0F variant selector that follows
content = content.replace("\\U0001F3CD", "\U0001F3CD")

with open('src/main.jsx', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done - replaced with actual emoji characters")
