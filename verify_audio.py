import main
from unittest.mock import MagicMock
import base64
import sys

# Setup Mock Groq Client
mock_client = MagicMock()
main.groq_client = mock_client

# Mock Transcription Logic
def mock_transcribe(*args, **kwargs):
    # args[0] is file tuple: (filename, content)
    # content is bytes
    file_tuple = kwargs.get('file')
    if file_tuple:
        content = file_tuple[1]
        print(f"Received audio bytes length: {len(content)}")
        
    mock_resp = MagicMock()
    mock_resp.text = "Hello I am calling from SBI bank about your blocked account."
    return mock_resp

mock_client.audio.transcriptions.create.side_effect = mock_transcribe

# Mock Chat Completion for Analysis (to avoid real API call failure)
def mock_chat(*args, **kwargs):
    mock_choice = MagicMock()
    mock_choice.message.content = "grandma|english"
    return MagicMock(choices=[mock_choice])

mock_client.chat.completions.create.side_effect = mock_chat

print("--- Testing Audio Transcription Logic ---")

# Create dummy base64 audio (just random bytes)
dummy_audio = b"fake_audio_content"
b64_str = base64.b64encode(dummy_audio).decode('utf-8')

print("Invoking transcribe_audio...")
try:
    text = main.transcribe_audio(b64_str)
    print(f"Transcribed Text: '{text}'")
    
    expected = "Hello I am calling from SBI bank about your blocked account."
    if text == expected:
        print("✅ Transcription logic success")
    else:
        print(f"❌ Transcription mismatch. Got: {text}")
        
except Exception as e:
    print(f"❌ Error: {e}")

sys.stdout.flush()
