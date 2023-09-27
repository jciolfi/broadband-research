import os, requests, json
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "https://atlas.ripe.net/api/v2"
API_KEY = os.getenv("API_KEY")

measurement_params = {
    "definitions": [{
        "target": "google.com",
        "description": "Traceroute to google.com",
        "type": "traceroute",
        "af": 4,
        "is_oneoff": True
    }],
    "probes": [{
        "requested": 1, # 1 probe
        "type": "area", # area type probe selector
        "value": "WW" # worldwide
    }]
}

headers = {
    "Authorization": f"Key {API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

response = requests.post(f"{BASE_URL}/measurements/", headers=headers, data=json.dumps(measurement_params))

if response.status_code != 201:
    print("Failed to create measurement!")
    exit(1)

print("Measurement Successfully Created")
measurement_result = response.json()
measurement_id = measurement_result["measurements"][0]

response = requests.get()