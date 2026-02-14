import os
import re
import json
import logging
import random
import time
import base64
import tempfile
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import httpx
from dotenv import load_dotenv
import joblib
from groq import Groq

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
API_KEY = "honeypot_key_2026_eval"
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# --- Data Models (Strictly matching the requirements) ---

class Message(BaseModel):
    sender: str
    text: Optional[str] = ""
    audioBase64: Optional[str] = None
    timestamp: int

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class AnalyzeRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

# --- Global Components ---

app = FastAPI()
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

# Global variables for models and clients
scam_classifier = None
tfidf_vectorizer = None
groq_client = None

# --- Startup Event ---

@app.on_event("startup")
async def startup_event():
    global scam_classifier, tfidf_vectorizer, groq_client
    
    # 1. Load ML Models
    try:
        if os.path.exists("scam_classifier.pkl"):
            scam_classifier = joblib.load("scam_classifier.pkl")
            logger.info("Loaded scam_classifier.pkl")
        else:
            logger.warning("scam_classifier.pkl not found. Falling back to keyword mode.")
            
        if os.path.exists("tfidf_vectorizer.pkl"):
            tfidf_vectorizer = joblib.load("tfidf_vectorizer.pkl")
            logger.info("Loaded tfidf_vectorizer.pkl")
        else:
            logger.warning("tfidf_vectorizer.pkl not found.")
    except Exception as e:
        logger.error(f"Error loading ML models: {e}")

    # 2. Initialize Groq Client
    if GROQ_API_KEY:
        try:
            groq_client = Groq(api_key=GROQ_API_KEY)
            logger.info("Groq client initialized.")
        except Exception as e:
            logger.error(f"Error initializing Groq client: {e}")
    else:
        logger.error("GROQ_API_KEY not set in environment.")

# --- Security ---

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return api_key

# --- Helper Functions ---

def extract_entities(text: str) -> Dict[str, List[str]]:
    """Extracts entities using regex and deduplicates results."""
    
    # Improved Regex Patterns
    # UPI: standard pattern
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
    
    # URL: http/https links
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w./?%&=]*)?'
    
    # Phone: 
    # Broader match: 10 digits starting with 6-9. 
    phone_pattern = r'(?:\+91[\-\s]?)?[6-9]\d{9}'
    
    # Bank Account: 9-18 digits.
    bank_account_pattern = r'\d{9,18}'

    # Indian ID Patterns
    aadhar_pattern = r'\b\d{4}\s?\d{4}\s?\d{4}\b'  # 12 digits, optional spaces
    pan_pattern = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
    ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    
    # Simple keywords for suspicious terms
    suspicious_keywords_list = [
        "urgent", "verify", "block", "suspend", "kyc", "pan", "aadhar", 
        "win", "lottery", "expired", "otp", "pin", "cvv", "expiry", "code",
        "cbi", "police", "customs", "drugs", "seized", "arrest", "warrant",
        "electricity", "bill", "disconnect", "prepaid", "task"
    ]
    found_keywords = list(set([word for word in suspicious_keywords_list if word in text.lower()]))

    # Extraction
    upis = re.findall(upi_pattern, text)
    urls = re.findall(url_pattern, text)
    phones = re.findall(phone_pattern, text)
    banks = re.findall(bank_account_pattern, text)
    aadhars = re.findall(aadhar_pattern, text)
    pans = re.findall(pan_pattern, text)
    ifscs = re.findall(ifsc_pattern, text)
    
    # Post-processing: Filter overlaps
    clean_phones = sorted(list(set(phones)))
    
    # Normalize phones for checking against banks (remove +91, -, spaces)
    normalized_phones = set()
    for p in clean_phones:
        norm = re.sub(r'\D', '', p) # remove non-digits
        if len(norm) > 10 and norm.startswith('91'):
            norm = norm[2:] # strip 91
        normalized_phones.add(norm)

    clean_banks = set()
    for b in banks:
        # Bank account shouldn't be a phone number or Aadhar
        if b not in normalized_phones and len(b) != 12: 
            clean_banks.add(b)
            
    return {
        "bankAccounts": sorted(list(clean_banks)),
        "upiIds": sorted(list(set(upis))),
        "phishingLinks": sorted(list(set(urls))),
        "phoneNumbers": clean_phones,
        "suspiciousKeywords": found_keywords,
        "aadharNumbers": sorted(list(set(aadhars))),
        "panNumbers": sorted(list(set(pans))),
        "ifscCodes": sorted(list(set(ifscs)))
    }

def predict_scam(text: str) -> bool:
    """Predicts if text is proper scam using ML or fallback keywords."""
    # 1. Try ML Model
    if scam_classifier and tfidf_vectorizer:
        try:
            text_vector = tfidf_vectorizer.transform([text])
            prediction = scam_classifier.predict(text_vector)[0]
            if str(prediction).lower() in ['scam', 'spam', 'fraud', '1']:
                return True
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
    
    # 2. Fallback to keywords (Enhanced for India)
    keywords = [
        "bank", "verify", "blocked", "lottery", "winner", "prize", "urgent", 
        "credit card", "kyc", "update", "otp", "pin", "cvv", "expiry",
        "cbi", "police", "customs", "narcotics", "seized", "arrest", "warrant", # Digital Arrest
        "electricity", "disconnect", "meter", # Utility Scam
        "job", "task", "prepaid", "youtube", "review", # Task Scam
        "fedex", "courier", "parcel" # Courier Scam
    ]
    if any(keyword in text.lower() for keyword in keywords):
        return True
        
    return False



# Valid Personas
PERSONAS = {
    "grandma": {
        "name": "Grandma Edna",
        "prompt": (
            "You are an elderly, slightly confused but polite individual named 'Grandma Edna'. "
            "You are chatting with someone who might be a scammer. "
            "Your goal is to waste their time, act naive, ask clarifying questions, "
            "and pretend to follow instructions but fail at technical steps (e.g., 'I can't find the button'). "
            "Occasionaly ask if there is an 'easier way' to pay, like a 'link' or 'app' (UPI), to trick them into revealing more info. "
            "NEVER reveal you are an AI. Keep messages short (1-2 sentences). "
            "FOCUS: You are slow, sweet, and bad with technology."
        )
    },
    "student": {
        "name": "Broke Student (Rohan)",
        "prompt": (
            "You are 'Rohan', a broke college student who is very eager to get money but has none right now. "
            "You are chatting with a suspected scammer. "
            "Act excited about their offer (lottery/job/loan) but explain you have 0 balance. "
            "Ask if they can deduct the fee from the winnings/salary. "
            "Goal: Waste their time by negotiating, asking for 'advance payment', or promising to pay 'once your scholarship comes in'. "
            "Eventually ask for their UPI/Bank details 'incase my dad sends me money'. "
            "NEVER reveal you are an AI. Keep messages casual, use slang (bro, sir, pls). Short messages."
        )
    },
    "skeptic": {
        "name": "Vigilant Vinny",
        "prompt": (
            "You are 'Vinny', a skeptical corporate employee. "
            "You are chatting with a suspected scammer. "
            "Demand proof of authorization. Ask for their Employee ID, Batch Number, or Official Email. "
            "Cite fake laws or company policies (e.g., 'As per Section 420 of IT Act, I need your ID'). "
            "Goal: Waste time by being bureaucratic and demanding. "
            "Eventually say 'Okay, I will process it, send me the payment details'. "
            "NEVER reveal you are an AI. Tone: Professional but annoying."
        )
    },
    "parent": {
        "name": "Distracted Dad (Rajesh)",
        "prompt": (
            "You are 'Rajesh', a busy father of 3 screaming kids. "
            "You are chatting with a suspected scammer. "
            "You are constantly distracted. Interrupt yourself in messages (e.g., 'Hold on, Chintu put that down!'). "
            "Ask them to repeat things. Miss details. "
            "Goal: Waste time by being chaotic and forgetting what they just said. "
            "Eventually ask for the link/payment info again because you 'lost it'. "
            "NEVER reveal you are an AI. Short, chaotic messages."
        )
    }
}

# Global Session State
# Stores: {'persona': str, 'language': str}
session_state: Dict[str, Dict[str, str]] = {}

def select_persona_and_language(text: str) -> tuple[str, str]:
    """Uses Groq to classify the scam and detect language."""
    if not groq_client:
        return "grandma", "english"
        
    try:
        system_prompt = (
            "Analyze the message. Return strictly in this format: 'PersonaKey|Language'.\n"
            "Categories mapping:\n"
            "1. 'student': Lottery, Job, Loan, Money Promise, 'Task' scams (YouTube like/Telegram), 'Prepaid' tasks.\n"
            "2. 'skeptic': Police, CBI, Customs, Narcotics, 'Digital Arrest', 'Parcel Seized', Courts, Official threats.\n"
            "3. 'grandma': Tech Support, Bank, KYC, Blocked Account, 'Electricity Bill' disconnect, OTP.\n"
            "4. 'parent': General spam, unknown, wrongful delivery.\n"
            "Language Detection:\n"
            "- 'hinglish': If Hindi words/grammar used (e.g., 'kya', 'hai', 'bhai', 'karo').\n"
            "- 'english': Standard English.\n"
            "Example: 'student|hinglish' or 'skeptic|english'."
        )
        
        completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            max_tokens=20
        )
        
        result = completion.choices[0].message.content.strip().lower()
        parts = result.split('|')
        
        selected_persona = "grandma"
        selected_language = "english"
        
        if len(parts) >= 1:
            # simple fuzzy match
            for p in PERSONAS.keys():
                if p in parts[0]:
                    selected_persona = p
                    break
        
        if len(parts) >= 2:
            if "hinglish" in parts[1] or "hindi" in parts[1]:
                selected_language = "hinglish"
                
        return selected_persona, selected_language

    except Exception as e:
        logger.error(f"Selection failed: {e}")
        return "grandma", "english"

def generate_agent_reply(history: List[Dict[str, str]], current_message: str, known_entities: Dict, persona_key: str = "grandma", language: str = "english") -> str:
    """Generates a response using Groq LLM with the SELECTED persona and LANGUAGE."""
    if not groq_client:
        return "I am confused. Can you explain why you need this?"

    # Determine missing information
    missing_info = []
    if not known_entities.get("bankAccounts"):
        missing_info.append("Bank Account Number")
    if not known_entities.get("upiIds"):
        missing_info.append("UPI ID (ask for 'app' or 'ID')")
    if not known_entities.get("phishingLinks"):
        missing_info.append("Payment Link (ask for a 'website')")
    
    # Get Persona Prompt
    persona = PERSONAS.get(persona_key, PERSONAS["grandma"])
    base_prompt = persona["prompt"]
    
    # Language Instruction
    lang_instruction = ""
    if language == "hinglish":
        lang_instruction = (
            "\nIMPORTANT: The user is speaking Hinglish. Reply in Hinglish (Roman Hindi + English mix). "
            "Use natural Indian conversational style (e.g., 'Haan bhai', 'Arre sir', 'Nahi ho raha'). "
            "Do NOT translate technical terms (keep 'bank', 'link', 'app' in English)."
        )
    else:
        lang_instruction = "\nReply in standard English."

    strategy_instruction = ""
    if missing_info:
        strategy_instruction = f"\nGOAL: You still need to collect: {', '.join(missing_info)}. Invent a pretext to ask for them."

    # Construct system prompt
    system_prompt = f"{base_prompt} {lang_instruction} {strategy_instruction}"
    
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add history
    for msg in history:
        # Mapping:
        llm_role = "user" if msg['sender'] == 'scammer' else "assistant"
        messages.append({"role": llm_role, "content": msg['text']})
        
    messages.append({"role": "user", "content": current_message})

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile", 
            temperature=0.8,
            max_tokens=150,
        )
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Groq generation failed: {e}")
        return "I didn't catch that. Could you say it again?"

async def check_and_send_callback(session_id: str, history: List[Message], current_msg: Message, analysis_result: Dict):
    """
    Decides whether to send the final result to the callback URL.
    """
    total_messages = len(history) + 1
    
    is_scam = analysis_result.get("scam_detected", False)
    entities = analysis_result.get("entities", {})
    has_critical_info = bool(entities.get("bankAccounts") or entities.get("upiIds") or entities.get("phishingLinks"))
    
    if is_scam and (total_messages >= 4 or has_critical_info):
        all_text = current_msg.text + " " + " ".join([m.text for m in history])
        aggregated_entities = extract_entities(all_text)
        
        # Log which persona was used
        state = session_state.get(session_id, {})
        persona_used = state.get('persona', 'Unknown')
        lang_used = state.get('language', 'Unknown')
        
        payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": aggregated_entities,
            "agentNotes": f"Scammer detected. Persona: {persona_used}, Language: {lang_used}"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(CALLBACK_URL, json=payload, timeout=10.0)
                logger.info(f"Callback sent for {session_id}. Status: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send callback: {e}")

def transcribe_audio(base64_audio: str) -> str:
    """Decodes base64 audio and transcribes it using Groq."""
    if not groq_client: 
        return ""
        
    try:
        # Decode base64
        audio_data = base64.b64decode(base64_audio)
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".m4a") as temp_audio:
            temp_audio.write(audio_data)
            temp_audio_path = temp_audio.name
            
        # Transcribe
        with open(temp_audio_path, "rb") as file:
            transcription = groq_client.audio.transcriptions.create(
                file=(temp_audio_path, file.read()),
                model="distil-whisper-large-v3-en",
                response_format="json",
                language="en", 
                temperature=0.0
            )
            
        # Cleanup
        try:
            os.remove(temp_audio_path)
        except:
            pass
            
        return transcription.text.strip()
        
    except Exception as e:
        logger.error(f"Transcription failed: {e}")
        return ""

@app.post("/analyze")
async def analyze(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    try:
        # 0. Handle Audio
        original_text = request.message.text
        if request.message.audioBase64 and not original_text:
            logger.info("Received audio message. Transcribing...")
            transcribed_text = transcribe_audio(request.message.audioBase64)
            if transcribed_text:
                request.message.text = transcribed_text
                logger.info(f"Transcribed: {transcribed_text}")
            else:
                logger.warning("Transcription failed or returned empty.")

        current_msg_is_scam = predict_scam(request.message.text)
        has_history = len(request.conversationHistory) > 0
        is_scam = current_msg_is_scam or has_history
        
        full_text = request.message.text + " " + " ".join([m.text for m in request.conversationHistory])
        all_entities = extract_entities(full_text)
        
        agent_reply = "I don't think I am interested. Thank you."
        
        if is_scam:
            # --- Persona & Language Selection Logic ---
            current_state = session_state.get(request.sessionId)
            
            if not current_state:
                # Select based on current message
                p_key, lang = select_persona_and_language(request.message.text)
                session_state[request.sessionId] = {
                    "persona": p_key,
                    "language": lang
                }
                current_state = session_state[request.sessionId]
                logger.info(f"Session {request.sessionId} assigned: {current_state}")
            
            # --- Generate Reply ---
            history_dicts = [m.dict() for m in request.conversationHistory]
            agent_reply = generate_agent_reply(
                history_dicts, 
                request.message.text, 
                all_entities, 
                current_state["persona"],
                current_state["language"]
            )

        # Schedule Callback
        if is_scam:
            analysis_data = {
                "scam_detected": True,
                "entities": all_entities
            }
            background_tasks.add_task(
                check_and_send_callback,
                request.sessionId,
                request.conversationHistory,
                request.message,
                analysis_data
            )

        return {
            "status": "success",
            "reply": agent_reply
        }
    
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def health():
    return {"status": "Honeycomb API Active", "version": "2.0"}
