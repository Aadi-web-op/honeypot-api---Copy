import joblib
import os

print("Checking model files...")
try:
    if os.path.exists("scam_classifier.pkl"):
        clf = joblib.load("scam_classifier.pkl")
        print("Classifier loaded successfully.")
    else:
        print("Classifier file NOT found.")
        
    if os.path.exists("tfidf_vectorizer.pkl"):
        vec = joblib.load("tfidf_vectorizer.pkl")
        print("Vectorizer loaded successfully.")
    else:
        print("Vectorizer file NOT found.")
        
except Exception as e:
    print(f"Error loading models: {e}")
