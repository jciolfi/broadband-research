import os, requests, json, csv, ipaddress, sys, time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from ipwhois import IPWhois
from geopy.geocoders import Nominatim

# BASE_URL = "https://atlas.ripe.net/api/v2"
# MEASUREMENTS = "measurements"
# API_KEY = None
# TARGET = "google.com"
# TARGET_ASN = "15169"


"""
TODO
(in future): add rows/cols for cleaning json -> .csv file
tool that translates mapping between IPs -> ASNs (bdrmapit)
IP repeated across many boundaries

launch traceroutes to targets (and other IPs in /24):
target 2 IPs (one given, one random) and they go through different paths in /24 => model isn't sufficient (prefix-based)
- 

"""
class GeoIP:
    def __init__(self, reader):
        self.reader = reader
        self.geolocator = Nominatim(user_agent="jinco")

    def get_lat_lon(self, ip):
        data = self.reader.get(ip)
        if not data:
            return None
        lat, lon = data['location']['latitude'], data['location']['longitude']
        return (lat, lon)
    
    def get_label(self, lat_lon):
        loc = self.geolocator.reverse(lat_lon)
        if not loc:
            return ""
        
        addr = loc.raw.get("address", {})
        places = [
            addr.get("city", ""),
            addr.get("town", ""),
            addr.get("state", ""),
            addr.get("region", ""),
            addr.get("country", ""),
        ]
        return ", ".join(filter(lambda x: x, places))   
    
    def get_location(self, ip):
        return self.get_label(self.get_lat_lon(ip))
    


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
            params["probes"] = [{
                "type": "probes",
                "value": "15763,1005127,6899",
                "requested": 1
            }]

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
        return choice == "yes"
    
    
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
    
    
    # create report name by continually incrementing version to not overwrite existing reports.
    def create_report_name(self, measurement_id, target, type):
        filename = f"report-{target}-{measurement_id}.{type}"
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
            if not self.is_private_ip(ip):
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
                   
                    
    # format raw json measurement details to a more readable csv format
    def format_measurement_csv(self, output_file, data_path):
        ip_mappings = {}
        
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
                            try:
                                # hop IP and ASN info
                                hop_ip = hop_info["from"]
                                asn, asn_desc = self.asn_from_ip(hop_ip, ip_mappings)
                                
                                # location if present
                                with geoipdb.Reader("geoip.mmdb") as reader:
                                    geoip = GeoIP(reader)
                                    # loc = str(geoip.get_lat_lon(hop_ip))
                                    loc = str(geoip.get_location(hop_ip))
                                
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
                                    
                                writer.writerow([hop, pkt + 1, ip_src, ip_dst, hop_ip, asn, asn_desc, loc, rtt, ttl, size, itos, icmp_ver, icmp_rfc4884, icmp_obj])
                            except KeyError:
                                writer.writerow([hop, pkt + 1, ip_src, ip_dst])
                                
                    # write extra row for spacing between traceroutes
                    writer.writerow([" "])


if __name__ == "__main__":
    sys.path.append(os.path.dirname('./vendor/geoipdb'))
    import geoipdb
    m = Measurement()

    # print(m.create_measurement("chemeketa.edu")) # -> target IP is 15.197.180.139
    # 15.197.180.1 is Amazon: ('16509', 'AMAZON-02, US')
    # WEST COAST (WA, Seattle)
    # print(m.create_measurement("15.197.180.139", False, 2 * 60, 20, None))
    # print(m.create_measurement("15.197.180.1", False, 2 * 60, 20, None))
    
    
    # print(m.create_measurement("k12espanola.org")) # -> target IP is 162.159.135.49
    # WEST COAST (CA, San Francisco)
    # 162.159.135.49 is k12, 162.159.135.1 is cloudflare: ('13335', 'CLOUDFLARENET, US')
    # print(m.create_measurement("162.159.135.1", False, 2 * 60, 20, None))
    # print(m.create_measurement("162.159.135.49", False, 2 * 60, 20, None))

    # For test measurement (3 min interval, 60 mins long, to personal public IP from closeby probes)
    # print(m.create_measurement(m.get_public_ip(), False, 3 * 60, 60, None))
    # measurement_id, target = 63359430, "73.219.241.3"
    measurement_id, target = 61056514, "google.com"
    # m.format_measurement(m.create_report_name(measurement_id, target, "csv"), "traceroute-73.219.241.3-63359430.json")
    m.format_measurement(m.create_report_name(measurement_id, target, "csv"), "traceroute-google.com-61056514.json")
    # m.format_measurement_txt(m.create_report_name(measurement_id, target, "txt"), "traceroute-73.219.241.3-63359430.json")
    # m.save_measurement(measurement_id, target)