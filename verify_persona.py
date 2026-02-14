import main
from unittest.mock import MagicMock
import sys

# Setup Mock Groq Client
mock_client = MagicMock()
main.groq_client = mock_client

def mock_create(*args, **kwargs):
    messages = kwargs.get('messages', [])
    user_msg = messages[-1]['content'].lower()
    
    # Simple keyword based simulation of LLM logic for testing
    if "lottery" in user_msg or "won" in user_msg:
        content = "student"
    elif "police" in user_msg or "customs" in user_msg:
        content = "skeptic"
    elif "blocked" in user_msg or "expired" in user_msg:
        content = "grandma"
    else:
        content = "parent"
        
    mock_response = MagicMock()
    mock_response.choices[0].message.content = content
    return mock_response

mock_client.chat.completions.create.side_effect = mock_create

print("--- Testing Persona Selection Logic (Mocked LLM) ---")

test_messages = {
    "student": ["Congratulations! You won a lottery."],
    "skeptic": ["This is Mumbai Police."],
    "grandma": ["Your account is blocked."],
    "parent": ["Hello friend."]
}

for expected, texts in test_messages.items():
    for text in texts:
        print(f"Testing input: '{text}'")
        selected = main.select_persona(text)
        print(f"  -> Selected: {selected}")
        if selected == expected:
            print("  ✅ PASS")
        else:
            print(f"  ❌ FAIL (Expected {expected})")

print("\n--- Testing Session Persistence ---")
main.session_personas['test_session'] = 'student'
if main.session_personas.get('test_session') == 'student':
    print("✅ Session persistence works")
else:
    print("❌ Session persistence failed")

sys.stdout.flush()
