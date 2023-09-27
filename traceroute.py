import os, requests, json
from dotenv import load_dotenv

BASE_URL = "https://atlas.ripe.net/api/v2"
MEASUREMENTS = "measurements"
API_KEY = None

def init():
    load_dotenv()
    global API_KEY
    API_KEY = os.getenv("API_KEY")
    if not API_KEY:
        print("No Atlas API key found in .env!")


def get_measurement_id(headers):
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

    response = requests.post(f"{BASE_URL}/{MEASUREMENTS}", headers=headers, data=json.dumps(measurement_params))
    if response.status_code != 201:
        return None
    
    try:
        return response.json()[MEASUREMENTS][0]
    except:
        return None


def parse_measurement(measurement_id, headers):
    if measurement_id is None:
        print("Failed to create measurement!")
        exit(1)

    print("Measurement Successfully Created")
    response = requests.get(f"{BASE_URL}/{MEASUREMENTS}/{measurement_id}/results", headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to retrieve measurement results for id {measurement_id}")
        exit(1)

    filename = "traceroute_result.json"
    with open(filename, "w") as file:
        json.dump(response.json(), file)
        print(f"Successfully saved measurement results to {filename}!")



if __name__ == "__main__":
    headers = {
        "Authorization": f"Key {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    # measurement_id = get_measurement_id(headers)
    # parse_measurement(measurement_id, headers)
    init()