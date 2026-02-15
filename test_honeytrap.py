import requests
import sys

# URL of the local API
BASE_URL = "http://127.0.0.1:8000"

def test_honeytrap(txn_id):
    url = f"{BASE_URL}/receipt/{txn_id}"
    print(f"Testing HoneyTrap URL: {url}")
    
    try:
        # Simulate a scammer clicking the link with a custom User-Agent
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.181 Mobile Safari/537.36"
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            print("  ✅ Status Code 200 OK")
            
            # Check for Trap Content
            if "Transaction Status" in response.text and "Processing Transaction..." in response.text:
                print("  ✅ Correct Fake Receipt Page Returned")
            else:
                print("  ❌ Incorrect Content Returned")
                
            # We can't easily check the server logs programmatically here without complex setup, 
            # but getting 200 OK with correct content is a strong signal.
            
        else:
            print(f"  ❌ Failed with Status Code: {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

if __name__ == "__main__":
    test_honeytrap("test_txn_999")
