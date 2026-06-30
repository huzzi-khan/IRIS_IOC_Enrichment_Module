import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"

def lookup_ip(ip_address):
    """
    Query AbuseIPDB for an IP address.
    Returns raw response dict or error dict.
    """
    try:
        response = requests.get(
            f"{BASE_URL}/check",
            headers={
                "Key": API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,  # look back 90 days of reports
                "verbose": True
            },
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            return {"error": "invalid_api_key"}
        elif response.status_code == 422:
            return {"error": "invalid_ip_format"}
        elif response.status_code == 429:
            return {"error": "rate_limit_hit"}
        else:
            return {"error": f"http_{response.status_code}"}

    except requests.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}
    
