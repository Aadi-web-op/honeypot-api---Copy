import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_proxy_ip_logging():
    url = f"{BASE_URL}/receipt/test_proxy_ip"
    print(f"Testing Proxy IP Detection at: {url}")
    
    # Simulate a request coming through a proxy (like Render/Cloudflare)
    fake_ip = "203.0.113.195" # A test IP
    headers = {
        "X-Forwarded-For": f"{fake_ip}, 10.0.0.1",
        "User-Agent": "Mozilla/5.0 (TestDevice)"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("  ✅ Request sent successfully.")
            print(f"  👉 CHECK YOUR UVICORN CONSOLE.")
            print(f"  You should see: '🚨 HONEYTRAP TRIGGERED ... IP: {fake_ip}'")
        else:
            print(f"  ❌ Request failed: {response.status_code}")
            
    except Exception as e:
        print(f"  ❌ Error: {e}")

if __name__ == "__main__":
    test_proxy_ip_logging()
