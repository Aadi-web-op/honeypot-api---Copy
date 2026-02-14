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
    
    # 1. Classification (Persona | Language)
    if "return strictly in this format" in system_prompt.lower():
        persona = "grandma"
        language = "english"
        
        # Persona Logic
        if "lottery" in user_msg: persona = "student"
        elif "police" in user_msg: persona = "skeptic"
        
        # Language Logic
        if any(word in user_msg for word in ["kya", "hai", "bhai", "raha", "hoon", "kholo", "arre"]):
            language = "hinglish"
            
        return MagicMock(choices=[MagicMock(message=MagicMock(content=f"{persona}|{language}"))])
        
    # 2. Generation (Reply)
    else:
        # Check if language instruction is present
        if "reply in hinglish" in system_prompt.lower():
            return MagicMock(choices=[MagicMock(message=MagicMock(content="Haan bhai, main samajh gaya."))])
        else:
            return MagicMock(choices=[MagicMock(message=MagicMock(content="I understand, sir."))])

mock_client.chat.completions.create.side_effect = mock_create

print("--- Testing Language Detection & Persona Selection ---")

test_cases = [
    ("Hello sir, I am calling from bank.", "grandma", "english"),
    ("Kya haal hai bhai? Lottery lagi hai.", "student", "hinglish"),
    ("This is police. Open the door.", "skeptic", "english"),
    ("Arre sir, police bol raha hoon darwaza kholo.", "skeptic", "hinglish")
]

for text, exp_persona, exp_lang in test_cases:
    print(f"Input: '{text}'")
    p, l = main.select_persona_and_language(text)
    print(f"  -> Got: Persona={p}, Language={l}")
    
    if p == exp_persona and l == exp_lang:
        print("  ✅ PASS")
    else:
        print(f"  ❌ FAIL (Expected {exp_persona}|{exp_lang})")

print("\n--- Testing Prompt Injection ---")
# Test Hinglish Prompt
print("Generating reply for Hinglish session...")
main.generate_agent_reply([], "Kya hua?", {}, "student", "hinglish")
# We can't easily inspect the 'messages' passed to mock without more code, 
# but the mock_create returns a Hindi string if it sees the instruction.
# So if we get the hindi string back, it worked.

reply = main.generate_agent_reply([], "Kya hua?", {}, "student", "hinglish")
print(f"Reply: {reply}")
if "Haan bhai" in reply:
    print("  ✅ Prompt applied correctly")
else:
    print("  ❌ Prompt injection failed")

sys.stdout.flush()
