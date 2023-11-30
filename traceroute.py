import os, requests, json, csv, ipaddress, random
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
from ipwhois import IPWhois
from geopy.geocoders import Nominatim
import geoip2.database
import probes

# BASE_URL = "https://atlas.ripe.net/api/v2"
# MEASUREMENTS = "measurements"
# API_KEY = None
# TARGET = "google.com"
# TARGET_ASN = "15169"


"""

launch traceroutes to targets (and other IPs in /24):
- target 2 IPs (one given, one random) and they go through different paths in /24 => model isn't sufficient (prefix-based)
- differences in paths (length, ASNs, etc.), RTT, etc.
- 

"""
class GeoIP:
    def get_location(self, ip, cache):
        try:
            if ip in cache:
                return cache[ip]
            with geoip2.database.Reader("./other_data/geoip.mmdb") as reader:
                response = reader.city(ip)
                country = response.country.name
                city = response.city.name
                subdivs = ", ".join(map(lambda x: x.name, response.subdivisions))
                location = ", ".join((city, subdivs, country))
                cache[ip] = location
                return location
        except:
            return ""
        

class Measurement:
    def __init__(self):
        # set class-specific constants
        self.base_url = "https://atlas.ripe.net/api/v2"
        self.measurements = "measurements"

        # extract API keys from env
        load_dotenv()
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
        params["bill_to"] = "ciolfi.j@northeastern.edu"
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
        choice = input(f"\nStart measurement with the following params?\n{params}\n\n(yes/no):").strip().lower()
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

        filename = f"traceroute_data/traceroute-{target}-{measurement_id}.json"
        with open(filename, "w") as file:
            json.dump(response.json(), file)
            print(f"Successfully saved measurement results to {filename}!")
            
        return filename


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
    
    
    # create report name by continually incrementing version to not overwrite existing reports.
    def create_report_name(self, measurement_id, target, type):
        filename = f"reports/report-{target}-{measurement_id}.{type}"
        if not os.path.exists(filename):
            return filename
        
        version = 2
        extension = filename.rfind(f".{type}")
        while True:
            test_filename = filename[:extension] + f"-{version}" + filename[extension:]
            if not os.path.exists(test_filename):                
                return test_filename
            version += 1
    
    
    # add layer of delegation for formatting measurements
    def format_measurement(self, output_file, data_path):
        print("Formatting measurement...")
        filetype = output_file[output_file.rfind(".") + 1:]
        if filetype == "txt":
            self.format_measurement_txt(output_file, data_path)
        elif filetype == "csv":
            self.format_measurement_csv(output_file, data_path)
        else:
            raise NotImplementedError(f"No formatting implementation for {filetype} files exists.")

        print(f"Report saved to {output_file}!")
            
            
    # create .txt report for a measurement report with human-readable formatting
    def format_measurement_txt(self, output_file, data_path):
        with open(output_file, "w") as out_file:
            with open(data_path, "r") as in_file:
                traceroutes = json.load(in_file)
                for t in traceroutes:
                    # write header with info on traceroute
                    out_file.write(f"Report for {t['src_addr']} -> {t['dst_addr']} ({t['dst_name']})\n")
                    out_file.write(f"Protocol: {t['proto']} (IPv{t['af']}), Time: {datetime.utcfromtimestamp(t['endtime']).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                    
                    for hop in t["result"]:
                        out_file.write(f"  Hop {hop['hop']}:\n")
                        for pkt, res in enumerate(hop["result"]):
                            out_file.write(f"    pkt {pkt + 1}: ")
                            if "from" in res:
                                # base fields for every hop w/ measurement
                                out_file.write(f"IP={res['from']}, RTT={res['rtt']} ms, TTL={res['ttl']}, Size={res['size']} B")

                                # IP type of service
                                if 'itos' in res: 
                                    out_file.write(f", itos={res['itos']}")
                                
                                # ICMP extensions field
                                if 'icmpext' in res:
                                    res_icmp = res['icmpext']
                                    out_file.write(f", ICMP: ver={res_icmp['version']}, rfc4884: {res_icmp['rfc4884']}, info={res_icmp['obj']}")
                            else:
                                out_file.write(f"* No results found")
                            out_file.write("\n")
                    out_file.write("\n")
               
                    
    # check if this ip is in the reserved private IP ranges.
    def is_private_ip(self, ip):
        _ip = ipaddress.ip_address(ip)
        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16")
        )
        return any(_ip in priv_range for priv_range in private_ranges)
    
    
    # try to get ASN associated with this IP
    def asn_from_ip(self, ip, cache):
        asn, asn_desc = "", ""
        try:
            if ip in cache:
                asn, asn_desc = cache[ip]
            else:
                _ipwhois = IPWhois(ip)
                asn_data = _ipwhois.lookup_rdap()
                asn, asn_desc = asn_data["asn"], asn_data["asn_description"]
                cache[ip] = (asn, asn_desc)
        except Exception as e:
            print(f"Could not find ASN for {ip}: {e}")
        
        return asn, asn_desc
    
    
    # extract hop info from a traceroute hop object
    def extract_hop_info(self, hop_info, ip_asn_cache, ip_loc_cache, geoip):
        try:
            # hop IP and ASN info
            hop_ip = hop_info["from"]
            asn = asn_desc = loc = ""
            if not self.is_private_ip(hop_ip):
                asn, asn_desc = self.asn_from_ip(hop_ip, ip_asn_cache)
                loc = geoip.get_location(hop_ip, ip_loc_cache)                               
            
            # other properties
            ttl = hop_info["ttl"]
            size = hop_info["size"]
            rtt = hop_info["rtt"]
            
            # handle itos (not in every record)
            itos = ""
            if "itos" in hop_info:
                itos = hop_info["itos"]
                
            # handle icmp (not in every record)
            icmp_ver = icmp_rfc4884 = icmp_obj = ""
            if 'icmpext' in hop_info:
                icmpext = hop_info["icmpext"]
                icmp_ver = icmpext["version"]
                icmp_rfc4884 = icmpext["rfc4884"]
                icmp_obj = icmpext["obj"]
                
            return [hop_ip, asn, asn_desc, loc, rtt, ttl, size, itos, icmp_ver, icmp_rfc4884, icmp_obj]
        except KeyError:
            return []
                 
       
    # format raw json measurement details to a more readable csv format
    def format_measurement_csv(self, output_file, data_path):
        ip_asn_cache = {}
        ip_loc_cache = {}
        geoip = GeoIP()
        
        with open(output_file, "w") as out_file:
            writer = csv.writer(out_file)
            # write header for flattened traceroute json data
            writer.writerow(["hop", "pkt", "ip_src", "ip_dst", "hop_ip", "ASN", "ASN_desc", "loc", "RTT", "TTL", "size", "itos", "icmp_ver", "icmp_rfc4884", "icmp_obj"])
            with open(data_path, "r") as in_file:
                traceroutes = json.load(in_file)
                for traceroute in traceroutes:
                    # get ip src and dst for this traceroute
                    ip_dst = traceroute["dst_addr"]
                    ip_src = traceroute["src_addr"]
                    
                    # get hop datum for this traceroute
                    for hop_data in traceroute["result"]:
                        hop = hop_data["hop"]
                        
                        # get hop info for this hop
                        for pkt, hop_info in enumerate(hop_data["result"]):
                            writer.writerow([hop, pkt + 1, ip_src, ip_dst] + self.extract_hop_info(hop_info, ip_asn_cache, ip_loc_cache, geoip))
                                
                    # write extra row for spacing between traceroutes
                    writer.writerow([" "])
    
    
    # generate a report with the given measurement_id and target
    def extract_data_and_report(self, measurement_id, target):
        data_path = self.save_measurement(measurement_id, target)
        report_name = self.create_report_name(measurement_id, target, 'csv')
        
        self.format_measurement(report_name, data_path)
        
    
    # bulk launch one-off traceroutes for domains in domains.csv from [start_row, end_row] inclusive
    # only launch if IP is blank (nan)
    def bulk_one_off(self, start_row, end_row):
        num_domains = end_row - start_row
        df = pd.read_csv("domains.csv", skiprows=range(1, start_row), nrows=num_domains)
        for _, row in df.iterrows():
            if pd.isna(row["IP"]):
                m.create_measurement(row["Domain"], probe=probes.SINGLE_BOSTON)
    
    
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
        df = pd.read_csv("domains.csv", dtype={"Msmt_ID": str, "Neighbor_Msmt_ID": str})
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
        
    def save_traceroute(self, row_num):
        # extract data from domains.csv
        df = pd.read_csv("domains.csv", dtype={"Msmt_ID": str, "Neighbor_Msmt_ID": str})
        row_idx = row_num - 2
        row = df.iloc[row_idx]
        msmt_id, neighbor_msmt_id = row["Msmt_ID"], row["Neighbor_Msmt_ID"]
        target = f'{row["IP"]}_{row["Domain"]}'
        neighbor_target = row["Neighbor_IP"]
        
        self.extract_data_and_report(msmt_id, target)
        self.extract_data_and_report(neighbor_msmt_id, neighbor_target)
        
        
            

if __name__ == "__main__":
    m = Measurement()
    
    # m.start_dual_measurements(7, _interval_s=6 * 60 * 60, _duration_mins=24 * 60, _probes=probes.SEATTLE)
    for row_num in range(5, 13):
        if row_num != 10:
            m.save_traceroute(row_num)