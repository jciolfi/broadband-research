import os, requests, json, time, math
from dotenv import load_dotenv

BASE_URL = "https://atlas.ripe.net/api/v2"
MEASUREMENTS = "measurements"
API_KEY = None
TARGET = "google.com"
TARGET_ASN = "15169"

def init():
    load_dotenv()
    global API_KEY
    API_KEY = os.getenv("API_KEY")
    if not API_KEY:
        print("No Atlas API key found in .env!")
        exit(1)
    print(f"using key: {API_KEY}")

def get_public_ip():
    response = requests.get('https://api.ipify.org')
    if response.status_code == 200:
        return response.text
    return None

def get_cur_timestamp_ms():
    return int(math.ceil(time.time() * 1000))

def build_params(target, is_oneoff, interval_s = None, duration_ms = None, probes = None):
    params = {}

    # set definitions
    params["definitions"] = [{
        "type": "traceroute", # type of measurement
        "af": 4, # IPv4
        "target": target,
        "description": f"Traceroute measurement to {target}",
        "resolve_on_probe": True,
        "response_timeout": 4000,
        "protocol": "IMCP",
        "packets": 3,
        "size": 48,
        "first_hop": 1,
        "max_hops": 32,
        "paris": 16,
        "destination_option_size": 0,
        "hop_by_hop_option_size": 0,
        "dont_fragment": False,
        "skip_dns_check": False,
        "interval": interval_s if interval_s else 900 # 900 is the default interval
    }]

    # set probes
    if probes:
        params["probes"] = probes
    else: 
        # default to three probes close to Northeastern University
        params["probes"] = [{
            "type": "probes",
            "value": "15763,1005127,6899",
            "requested": 3
        }]

    # set other attributes
    params["is_oneoff"] = is_oneoff
    params["bill_to"] = "ciolfi.j@northeastern.edu"
    if not is_oneoff:
        params["stop_time"] = get_cur_timestamp_ms() + duration_ms

    return params
    

def get_measurement_id(headers):
    measurement_params = build_params(get_public_ip(), False, 3 * 60, 1 * 60 * 60 * 1000, None)

    response = requests.post(f"{BASE_URL}/{MEASUREMENTS}", headers=headers, data=json.dumps(measurement_params))
    if response.status_code != 201:
        print(f"Warning: status {response.status_code} received:\n{response.json()}")
        return None
    
    try:
        print(f"Success: measurement created:\n{response.json()}")
        return response.json()[MEASUREMENTS][0]
    except:
        return None


def parse_measurement(measurement_id, headers):
    if measurement_id is None:
        print("Must specify measurement_id")
        exit(1)

    response = requests.get(f"{BASE_URL}/{MEASUREMENTS}/{measurement_id}/results", headers=headers)
    
    if response.status_code != 200:
        print(f"Failed to retrieve measurement results for id {measurement_id}")
        exit(1)

    filename = f"traceroute-{TARGET}-{measurement_id}.json"
    with open(filename, "w") as file:
        json.dump(response.json(), file)
        print(f"Successfully saved measurement results to {filename}!")


def stop_measurement(measurement_id, headers):
    stop_url = f"{BASE_URL}/{MEASUREMENTS}/{measurement_id}"

    # Data to indicate that the status should be changed to "Stopped"
    data_to_stop = {
        "status": {
            "id": 6  # 6 is the ID for "Stopped" status
        }
    }

    response = requests.put(stop_url, headers=headers, data=json.dumps(data_to_stop))
    
    if response.status_code != 200:
        print(f"Failed to stop measurement {measurement_id}. Response: {response.text}")
    else:
        print(f"Successfully stopped measurement {measurement_id}!")



if __name__ == "__main__":
    init()
    headers = {
        "Authorization": f"Key {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    measurement_id = get_measurement_id(headers)

    # parse_measurement(measurement_id, headers)