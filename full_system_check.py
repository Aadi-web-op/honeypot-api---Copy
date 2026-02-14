import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import base64

# Ensure we can import main
sys.path.append(os.getcwd())
import main

class TestHoneypotAPI(unittest.TestCase):

    def setUp(self):
        main.groq_client = MagicMock()
    
    # --- 1. Entity Extraction Tests ---
    def test_indian_ids_extraction(self):
        text = "User submitted PAN=ZXCVB4321L | Aadhaar: 1234-9999-8888 | IFSC: PUNB0456789"
        entities = main.extract_entities(text)
        
        self.assertIn("ZXCVB4321L", entities["panNumbers"])
        self.assertIn("1234-9999-8888", entities["aadharNumbers"])
        self.assertIn("PUNB0456789", entities["ifscCodes"])

    def test_phone_bank_separation(self):
        text = "Emergency contact 9988776655, primary a/c 6677889900112233"
        entities = main.extract_entities(text)
        
        self.assertIn("9988776655", entities["phoneNumbers"])
        self.assertIn("6677889900112233", entities["bankAccounts"])
        self.assertNotIn("9988776655", entities["bankAccounts"])

    def test_entities_with_noise(self):
        text = "☎️+91-9876543210 PAN:AAAAA9999A ### Acc-> 101010101010 IFSC=YESB0000123"
        entities = main.extract_entities(text)

        self.assertIn("9876543210", entities["phoneNumbers"])
        self.assertIn("AAAAA9999A", entities["panNumbers"])
        self.assertIn("101010101010", entities["bankAccounts"])
        self.assertIn("YESB0000123", entities["ifscCodes"])

    # --- 2. Scam Detection Tests ---
    def test_obfuscated_scam_language(self):
        scam_phrases = [
            "Your a/c will be restr1cted if K.Y.C not done today",
            "C B I cyber unit speaking, arrest process initiated",
            "Parcel held @ customs – unlawful content found",
            "Earn ₹5k/day by simple online t@sk",
            "Final power bill warning — disconnection in 2 hrs"
        ]
        for phrase in scam_phrases:
            with self.subTest(phrase=phrase):
                self.assertTrue(main.predict_scam(phrase))

    def test_scam_hidden_inside_normal_sentence(self):
        self.assertTrue(
            main.predict_scam(
                "Hope you're well, just informing your bank profile needs urgent verification today"
            )
        )

    def test_time_pressure_attack(self):
        self.assertTrue(main.predict_scam("Respond within 30 minutes or account permanently blocked"))

    def test_non_scam_similar_words(self):
        self.assertFalse(main.predict_scam("I need to update my college KYC documents tomorrow"))

    # --- 3. Persona & Language Routing Tests ---
    @patch('main.groq_client.chat.completions.create')
    def test_persona_routing_threatening_authority(self, mock_create):
        mock_create.return_value.choices = [
            MagicMock(message=MagicMock(content="skeptic|english"))
        ]
        
        persona, lang = main.select_persona_and_language(
            "Legal action initiated under cyber law section 66"
        )
        self.assertEqual(persona, "skeptic")
        self.assertEqual(lang, "english")

    @patch('main.groq_client.chat.completions.create')
    def test_persona_routing_mixed_hinglish(self, mock_create):
        mock_create.return_value.choices = [
            MagicMock(message=MagicMock(content="student|hinglish"))
        ]
        
        persona, lang = main.select_persona_and_language(
            "Bhai ek easy sa online kaam hai paisa instant milega"
        )
        self.assertEqual(persona, "student")
        self.assertEqual(lang, "hinglish")

    @patch('main.groq_client.chat.completions.create')
    def test_persona_routing_soft_threat(self, mock_create):
        mock_create.return_value.choices = [
            MagicMock(message=MagicMock(content="skeptic|english"))
        ]

        persona, lang = main.select_persona_and_language(
            "To avoid service interruption please verify now"
        )

        self.assertEqual(persona, "skeptic")
        self.assertEqual(lang, "english")

    # --- 4. Audio Transcription Tests ---
    @patch('main.groq_client.audio.transcriptions.create')
    def test_audio_transcription_scam_call(self, mock_transcribe):
        mock_transcribe.return_value.text = "Your account is under investigation kindly verify details"
        
        dummy_b64 = base64.b64encode(b"scam_audio").decode('utf-8')
        
        result = main.transcribe_audio(dummy_b64)
        self.assertEqual(result, "Your account is under investigation kindly verify details")
        self.assertTrue(mock_transcribe.called)

    @patch('main.groq_client.audio.transcriptions.create')
    def test_audio_transcription_casual(self, mock_transcribe):
        mock_transcribe.return_value.text = "I'm running late for class today"
        
        dummy_b64 = base64.b64encode(b"casual_audio").decode('utf-8')
        
        result = main.transcribe_audio(dummy_b64)
        self.assertEqual(result, "I'm running late for class today")

if __name__ == '__main__':
    unittest.main()
