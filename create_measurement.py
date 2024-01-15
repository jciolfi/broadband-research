import os, requests, json, random
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
import probes

# BASE_URL = "https://atlas.ripe.net/api/v2"
# MEASUREMENTS = "measurements"
# API_KEY = None
# TARGET = "google.com"
# TARGET_ASN = "15169"

# TODO: publish code with Northeastern license (NEU intellectual property)

"""

launch traceroutes to targets (and other IPs in /24):
- target 2 IPs (one given, one random) and they go through different paths in /24 => model isn't sufficient (prefix-based)
- differences in paths (length, ASNs, etc.), RTT, etc.
- 

"""
        

class MeasurementLauncher:
    def __init__(self):
        # set class-specific constants
        self.base_url = "https://atlas.ripe.net/api/v2"
        self.measurements = "measurements"

        # extract API keys from env
        load_dotenv()
        self.bill_to = os.getenv("BILL_TO")
        self.api_key_create = os.getenv("API_KEY_CREATE")
        self.api_key_stop = os.getenv("API_KEY_STOP")
        if not self.api_key_create and not self.api_key_stop:
            raise EnvironmentError("Please set an environment variable for API_KEY_CREATE and/or API_KEY_STOP in .env")

        # create headers to go along with requests
        self.create_headers = {
            "Authorization": f"Key {self.api_key_create}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.stop_headers = {
            "Authorization": f"Key {self.api_key_stop}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }


    # get public IP for this machine
    def get_public_ip(self):
        response = requests.get('https://api.ipify.org')
        if response.status_code == 200:
            return response.text
        return None
    
    # get timestamp in milliseconds ƒloored to the nearest minute
    def get_cur_timestamp_ms(self):
        cur_time = datetime.now().replace(second=0, microsecond=0)
        return int(cur_time.timestamp() * 1000)
    
    
    # get timestamp in YYYY-MM-DD HH:MM format
    def get_cur_timef(self, delta_mins = 0):
        cur_time = datetime.utcnow() + timedelta(minutes=delta_mins)
        return cur_time.strftime("%Y-%m-%d %H:%M")
    
    
    # build params used to create a measurement
    def build_params(self, target, is_oneoff, interval_s = None, duration_mins = None, probes = None):
        params = {}

        # set definitions
        params["definitions"] = [{
            "type": "traceroute", # type of measurement
            "af": 4, # IPv4
            "target": target,
            "description": f"Traceroute measurement to {target}",
            "resolve_on_probe": True,
            "response_timeout": 4000,
            "protocol": "UDP",
            "packets": 3,
            "size": 48,
            "first_hop": 1,
            "max_hops": 32,
            "paris": 16,
            "destination_option_size": 0,
            "hop_by_hop_option_size": 0,
            "dont_fragment": False,
            "skip_dns_check": False
        }]

        # set probes
        if probes:
            params["probes"] = probes
        else: 
            # default to three probes close to Northeastern University
            params["probes"] = probes.SINGLE_BOSTON

        # set billing and if measurement is ongoing/one-off
        params["is_oneoff"] = is_oneoff
        params["bill_to"] = self.bill_to
        if not is_oneoff:            
            params["definitions"][0]["interval"] = interval_s if interval_s else 900 # 900 is the default interval
            params["start_time"] = self.get_cur_timef(2)
            params["stop_time"] = self.get_cur_timef(duration_mins + 2)
            # start_time = get_cur_timestamp_ms() + (1 * 60 * 1000)
            # params["start_time"] = start_time
            # params["stop_time"] = start_time + (duration_mins * 60 * 1000)

        return params
    
    
    # confirm starting a measurement
    def confirm_measurement(self, params):
        choice = input(f"\nStart measurement with the following params?\n{json.dumps(params, indent=2)}\n\n(yes/no): ").strip().lower()
        return choice in ("yes", "y")
    
    
    # make a post request to create a measurement
    def create_measurement(self, target, is_oneoff = True, interval_s = None, duration_mins = None, probes = None):
        measurement_params = self.build_params(target, is_oneoff, interval_s, duration_mins, probes)
        if not self.confirm_measurement(measurement_params):
            return None

        response = requests.post(f"{self.base_url}/{self.measurements}", headers=self.create_headers, data=json.dumps(measurement_params))
        if response.status_code != 201:
            print(f"Warning: status {response.status_code} received:\n{response.json()}")
            return None
        
        try:
            print(f"Success: measurement created:\n{response.json()}\n")
            return response.json()[self.measurements][0]
        except:
            return None


    # make put request to stop an ongoing measurement
    # NOTE: this is not tested very extensively - can also force stop a measurement through ripe atlas website.
    def stop_measurement(self, measurement_id):
        stop_url = f"{self.base_url}/{self.measurements}/{measurement_id}"

        # Data to indicate that the status should be changed to "Stopped"
        data_to_stop = {
            "status": {
                "id": 6  # 6 is the ID for "Stopped" status
            }
        }

        response = requests.put(stop_url, headers=self.stop_headers, data=json.dumps(data_to_stop))
        
        if response.status_code != 200:
            print(f"Failed to stop measurement {measurement_id}. Response: {response.text}")
        else:
            print(f"Successfully stopped measurement {measurement_id}!")                 
    
    
    # bulk launch one-off traceroutes for domains in domains.csv from [start_row, end_row] inclusive
    # only launch if IP is blank (nan)
    def bulk_one_off(self, start_row, end_row):
        num_domains = end_row - start_row + 1
        df = pd.read_csv("domains.csv", skiprows=range(1, start_row - 1), nrows=num_domains)
        for i, row in df.iterrows():
            if pd.isna(row["IP"]):
                print(f"Launching one-off for row {start_row + i} ({row['Domain']})...")
                m.create_measurement(row["Domain"], probes=probes.SINGLE_BOSTON)
            else:
                print(f"Row {start_row + i} ({row['Domain']}) already has an associated IP. Skipping...")
    
    
    # get neighbor ip in same /24 range
    def get_neighbor_ip_24(self, ip):
        last_octet = ip.rfind(".")
        last_val = int(ip[last_octet+1:])
        while (rand_val := random.randint(1,254)) == last_val:
            pass
        
        return f"{ip[:last_octet]}.{rand_val}"
    
    
    # start measurement for given IP and find a random neighbor. Also update domains.csv.
    def start_dual_measurements(self, row_num, _interval_s, _duration_mins, _probes):
        # extract data from domains.csv
        df = pd.read_csv("domains.csv", dtype={"Msmt_ID": str, "Neighbor_Msmt_ID": str, "IP": str})
        row_idx = row_num - 2
        row = df.iloc[row_idx]
        ip = row["IP"]
        neighbor_ip = self.get_neighbor_ip_24(ip)
        
        # start measurements
        msmt_id = self.create_measurement(ip, is_oneoff=False, interval_s=_interval_s, duration_mins=_duration_mins , probes=_probes)
        neighbor_msmt_id = self.create_measurement(neighbor_ip, is_oneoff=False, interval_s=_interval_s, duration_mins=_duration_mins , probes=_probes)
        
        # update domains.csv
        df.at[row_idx, "Msmt_ID"] = msmt_id
        df.at[row_idx, "Neighbor_IP"] = neighbor_ip
        df.at[row_idx, "Neighbor_Msmt_ID"] = neighbor_msmt_id
        df.to_csv("domains.csv", index=False)
            

if __name__ == "__main__":
    m = MeasurementLauncher()
    # m.bulk_one_off(13, 15)
    # m.start_dual_measurements(13, 6 * 60 * 60, 25 * 60, probes.SAN_FRANCISCO)
    # m.start_dual_measurements(14, 6 * 60 * 60, 25 * 60, probes.BOSTON)
    # m.start_dual_measurements(15, 6 * 60 * 60, 25 * 60, probes.SEATTLE)