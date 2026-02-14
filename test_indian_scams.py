import main
from unittest.mock import MagicMock
import sys

# Setup Mock Groq Client
mock_client = MagicMock()
main.groq_client = mock_client

def mock_create(*args, **kwargs):
    messages = kwargs.get('messages', [])
    system_prompt = messages[0]['content']
    user_msg = messages[-1]['content'].lower()
    
    # Simulate LLM Logic based on content
    if "return strictly in this format" in system_prompt.lower():
        persona = "grandma"
        language = "english"
        
        # Indian Scam Logic Mock
        if "arrest" in user_msg or "drugs" in user_msg or "police" in user_msg:
            persona = "skeptic"
        elif "task" in user_msg or "youtube" in user_msg or "job" in user_msg:
            persona = "student"
        elif "electricity" in user_msg:
            persona = "grandma"
            
        # Language Logic
        if "kya" in user_msg or "hai" in user_msg or "bhai" in user_msg:
            language = "hinglish"
            
        return MagicMock(choices=[MagicMock(message=MagicMock(content=f"{persona}|{language}"))])
    
    return MagicMock(choices=[MagicMock(message=MagicMock(content="Default Reply"))])

mock_client.chat.completions.create.side_effect = mock_create

print("--- Testing Indian Scam Scenarios ---")

scam_tests = [
    ("This is CBI. You are under digital arrest. Drugs found in parcel.", "skeptic", "english"),
    ("Electricity bill unpaid. Connection disconnect tonight.", "grandma", "english"),
    ("Complete 3 prepaid tasks and earn 5000 daily. Like YouTube videos.", "student", "english"),
    ("Kya haal hai? Digital arrest warant nikla hai tumhare naam pe.", "skeptic", "hinglish")
]

for text, exp_persona, exp_lang in scam_tests:
    print(f"Input: '{text}'")
    p, l = main.select_persona_and_language(text)
    print(f"  -> Got: Persona={p}, Language={l}")
    
    if p == exp_persona and l == exp_lang:
        print("  ✅ PASS")
    else:
        print(f"  ❌ FAIL (Expected {exp_persona}|{exp_lang})")

print("\n--- Testing Entity Extraction (Indian IDs) ---")
id_text = "My PAN is ABCDE1234F and my Aadhar is 1234 5678 9012. IFSC is SBIN0123456."
entities = main.extract_entities(id_text)

print(f"Text: '{id_text}'")
print(f"Entities Found: {entities}")

if "ABCDE1234F" in entities.get("panNumbers", []) and \
   "1234 5678 9012" in entities.get("aadharNumbers", []) and \
   "SBIN0123456" in entities.get("ifscCodes", []):
    print("  ✅ ID Extraction PASS")
else:
    print("  ❌ ID Extraction FAIL")

sys.stdout.flush()
