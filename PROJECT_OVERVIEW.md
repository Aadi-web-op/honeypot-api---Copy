# Honeypot API - Project Overview (Feb 2026)

## 1. Project Mission
To build a **High-Fidelity AI Honeypot** that not only detects scammers but actively engages them to waste their time and gather intelligence. The system is specifically calibrated for **Indian Scam Contexts** (e.g., Digital Arrest, UPI Fraud, Job Scams) and uses **Counter-Intelligence** tactics.

---

## 2. Technology Stack
-   **Framework**: FastAPI (Python)
-   **LLM Engine**: Groq API (Llama-3.3-70b-Versatile) for rapid, intelligent replies.
-   **Audio Engine**: Groq Whisper (Distil-Whisper-Large-v3) for Speech-to-Text.
-   **ML Core**: Scikit-Learn (TF-IDF + Logistic Regression) for initial scam classification.
-   **Deployment**: Uvicorn / Docker-ready.

---

## 3. Core Features & Capabilities

### A. Hybrid Scam Detection
1.  **ML Model**: Uses a pre-trained `scam_classifier.pkl` to detect general fraud patterns.
2.  **Keyword Fallback**: Enhanced list including:
    -   *Generic*: "Verify", "Block", "Lottery", "KYC".
    -   *Indian-Specific*: "CBI", "Digital Arrest", "Narcotics", "Electricity disconnect", "Prepaid task".

### B. Intelligent Intelligence Extraction
The API regex engine is tuned to extract:
-   **Indian IDs**: Aadhar (12 digits), PAN (Alphanumeric), IFSC Codes.
-   **Financials**: UPI IDs, Bank Account Numbers (distinct from phone numbers).
-   **Contact**: Phone numbers (+91 support), Phishing Links.

### C. Dynamic Persona System
The agent routes the conversation to the most effective persona based on the scam type:
| Scam Type | Assigned Persona | Strategy |
| :--- | :--- | :--- |
| **Digital Arrest / Police / CBI** | **Vigilant Vinny (Skeptic)** | Demands "Batch ID", quotes fake laws, acts bureaucratic. |
| **Lottery / Job / Loan** | **Broke Student (Rohan)** | Acts greedy but broke. Asks to deduct fees from winnings. |
| **Bank / KYC / Utility** | **Grandma Edna** | Acts confused, fails technical steps, asks for "easier ways". |
| **General Spam** | **Distracted Dad (Rajesh)** | Chaotic, distracted by kids, forgets details. |

### D. Multi-Modal Support
-   **Hinglish Support**: Detects Roman Hindi ("Kya haal hai?") and strictly replies in the same dialect using the persona's voice.
-   **Audio Processing**: Accepts `audioBase64`. Decodes -> Transcribes (Whisper) -> Processes text as normal -> Replies in text.

### E. Counter-Intelligence (HoneyTraps) `[INNOVATION]`
-   **Trap Links**: If a scammer demands payment proof, the agent sends a link: `.../receipt/{txn_id}`.
-   **Effect**: The link opens a fake "Transaction Processing" page.
-   **Payload**: The server logs the Scammer's **IP Address**, **User-Agent** (Device), and Timestamp for intelligence gathering.

---

## 4. API Architecture

### Endpoints
1.  **`POST /analyze`** (Main Intelligence Hub)
    -   **Input**: JSON with `text`, `audioBase64`, `conversationHistory`.
    -   **Process**:
        1.  Transcribe Audio (if present).
        2.  Predict Scam (ML + Keywords).
        3.  Extract Entities.
        4.  Select Persona & Language (Groq Llama-3).
        5.  Generate Reply (Groq Llama-3).
        6.  Schedule Background Callback.
    -   **Output**: `reply` string.
    
2.  **`GET /receipt/{txn_id}`** (HoneyTrap)
    -   Returns HTML fake receipt.
    -   Logs visitor IP/Device.

3.  **`POST (Callback) /updateHoneyPotFinalResult`**
    -   Sends gathered intelligence (Entities, Persona used, Msg Count) to the central hackathon dashboard.

---

## 5. File Structure
-   `main.py`: Monolithic entry point containing all logic (Models, Endpoints, Personas).
-   `requirements.txt`: Dependencies (`fastapi`, `groq`, `uvicorn`, `scikit-learn`).
-   `scam_classifier.pkl` / `tfidf_vectorizer.pkl`: Serialized ML models.
-   `full_system_check.py`: **Master Test Suite** verifying all components.
-   `verify_*.py`: Individual verification scripts for Persona, Audio, Language.

## 6. Verification & Testing
A robust test suite `full_system_check.py` uses `unittest` to validate:
-   Correct routing of "Digital Arrest" scams to "Skeptic" persona.
-   Extraction of complicated Indian IDs from noisy text.
-   Accurate translation/detection of Hinglish.
-   End-to-End audio transcription flow.

## 7. Future Roadmap
-   **Voice Output**: Using TTS to reply in audio (Grandma voice vs Student voice).
-   **PsyOps**: Dynamic threats ("My nephew is in Cyber Crime").
