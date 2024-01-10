import os, requests, json, csv, ipaddress, random
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
from ipwhois import IPWhois
from geopy.geocoders import Nominatim
import geoip2.database
import probes

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


class MeasurementImporter:
    def __init__(self):
        self.base_url = "https://atlas.ripe.net/api/v2"
        self.measurements = "measurements"
        
        load_dotenv()
        self.api_key_create = os.getenv("API_KEY_CREATE")
        
        self.create_headers = {
            "Authorization": f"Key {self.api_key_create}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }


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
    
    
    # generate a report with the given measurement_id and target
    def extract_data_and_report(self, measurement_id, target):
        data_path = self.save_measurement(measurement_id, target)
        report_name = self.create_report_name(measurement_id, target, 'csv')
        
        self.format_measurement(report_name, data_path)
    
    
    # save traceroute data with a report
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
    m = MeasurementImporter()
    
    for row_num in range(12, 13):
        if row_num != 10:
            m.save_traceroute(row_num)
    