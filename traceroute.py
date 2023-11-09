import os, requests, json, math
from datetime import datetime, timedelta
from dotenv import load_dotenv

# BASE_URL = "https://atlas.ripe.net/api/v2"
# MEASUREMENTS = "measurements"
# API_KEY = None
# TARGET = "google.com"
# TARGET_ASN = "15169"

class Measurement:
    def __init__(self) -> None:
        load_dotenv()
        self.base_url = "https://atlas.ripe.net/api/v2"
        self.measurements = "measurements"

        self.api_key_create = os.getenv("API_KEY_CREATE")
        self.api_key_stop = os.getenv("API_KEY_STOP")
        if not self.api_key_create and not self.api_key_stop:
            raise EnvironmentError("Please set an environment variable for API_KEY_CREATE and/or API_KEY_STOP in .env")

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
                "requested": 1
            }]

        # set other attributes
        params["is_oneoff"] = is_oneoff
        params["bill_to"] = "ciolfi.j@northeastern.edu"
        if not is_oneoff:
            # start_time = get_cur_timestamp_ms() + (1 * 60 * 1000)
            # params["start_time"] = start_time
            # params["stop_time"] = start_time + (duration_mins * 60 * 1000)
            params["start_time"] = self.get_cur_timef(2)
            params["stop_time"] = self.get_cur_timef(duration_mins + 2)


        return params
    
    # make a post request to create a measurement
    def create_measurement(self, target, is_oneoff = True, interval_s = None, duration_mins = None, probes = None):
        measurement_params = self.build_params(target, is_oneoff, interval_s, duration_mins, probes)
        print(measurement_params)

        response = requests.post(f"{self.base_url}/{self.measurements}", headers=self.create_headers, data=json.dumps(measurement_params))
        if response.status_code != 201:
            print(f"Warning: status {response.status_code} received:\n{response.json()}")
            return None
        
        try:
            print(f"Success: measurement created:\n{response.json()}")
            return response.json()[self.measurements][0]
        except:
            return None
        
    # save measurement data to json
    def save_measurement(self, measurement_id, target):
        if measurement_id is None:
            print("Must specify measurement_id")
            exit(1)

        response = requests.get(f"{self.base_url}/{self.measurements}/{measurement_id}/results", headers=self.create_headers)
        
        if response.status_code != 200:
            print(f"Failed to retrieve measurement results for id {measurement_id}")
            exit(1)

        filename = f"traceroute-{target}-{measurement_id}.json"
        with open(filename, "w") as file:
            json.dump(response.json(), file)
            print(f"Successfully saved measurement results to {filename}!")


    # make put request to stop an ongoing measurement
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
            
    # create .txt report for a measurement report
    def format_measurement(self, output_file, data_path):
        with open(output_file, "w") as out_file:
            with open(data_path, "r") as in_file:
                traceroutes = json.load(in_file)
                for t in traceroutes:
                    out_file.write(f"Report for {t['src_addr']} -> {t['dst_addr']} ({t['dst_name']})\n")
                    out_file.write(f"Protocol: {t['proto']}, Time: {datetime.utcfromtimestamp(t['endtime']).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                    
                    for hop in t["result"]:
                        out_file.write(f"  Hop {hop['hop']}:\n")
                        for res in hop["result"]:
                            if "from" in res:
                                out_file.write(f"    IP: {res['from']}, RTT: {res['rtt']} ms, Size: {res['size']} bytes, TTL: {res['ttl']}\n")
                            else:
                                out_file.write(f"    * No results found\n")
                    out_file.write("\n")
        




if __name__ == "__main__":
    m = Measurement()

    # measurement_id = m.create_measurement(m.get_public_ip(), False, 3 * 60, 60, None)

    measurement_id, target = 63359430, "73.219.241.3"
    # m.save_measurement(measurement_id, target)
    m.format_measurement(f"report-{target}-{measurement_id}.txt", "traceroute-73.219.241.3-63359430.json")