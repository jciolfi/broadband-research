import json, os
import numpy as np
import pandas as pd
from collections import defaultdict


"""
Things to look for
- overall path length (number of hops)
- latency (RTT for each hop, total RTT)
- hop addresses (are certain addresses used more than others)
- consistency (are there variations in the paths for different traceroutes)
- path stability (fluctuations in latency or path changes over time)

Questions
- How to handle hops with no data? Ie sometimes hard to draw conclusions if half hops don't have RTT
"""

class MeasurementAnalyzer:
    def __init__(self):
        pass
    
    # return dictionary sorted by value
    def sort_by_value(self, d, reverse = False):
        return dict(sorted(d.items(), key=lambda item: item[1], reverse=reverse))


    # extract values in row as a tuple from domains.csv from [start_row, stop_row] inclusive
    def extract_reports(self, start, stop):
        df = pd.read_csv("domains.csv", dtype={"Msmt_ID": str, "Neighbor_Msmt_ID": str})
        reports = []
        for i in range(start - 2, stop - 1):
            row = df.iloc[i]
            
            if any(row.isna()):
                print(f"Warning: row {i + 2} ({row['Domain']}) contains empty values. Skipping...")
                continue
            
            # extract domain, build target report and neighbor report file paths
            # NOTE: minimal error handling here if filepaths don't exist
            domain = row["Domain"]
            ip, msmt_id = row["IP"], row["Msmt_ID"]
            nbr_ip, nbr_msmt_id = row["Neighbor_IP"], row["Neighbor_Msmt_ID"]
            target_report = f"./reports/report-{ip}_{domain}-{msmt_id}.csv"
            nbr_report = f"./reports/report-{nbr_ip}-{nbr_msmt_id}.csv"
            reports.append((i + 2, domain, target_report, nbr_report))
            
        return reports


    """
    For each IP
    - create path as string, e.g. ip (ASN) -> * -> ip ...
    - create a map of RTTs, e.g. (src, dst): [RTT1, RTT2,...] and averages
    - map of ASN: times visited
    """
    def analyze(self, report_path):
        
        # add current path joined by arrows to nonlocal paths list
        def add_to_paths(cur_paths):
            nonlocal paths
            wrote_none = True
            for cp in cur_paths:
                if len(cp) > 0:
                    paths.append(f"  (hops {len(cp)}): {' -> '.join(cp)}")
                    wrote_none = False
            
            if not wrote_none:
                paths.append(f"  {'-' * 200}")
            
        
        paths = []
        total_hop_rtts = defaultdict(list)
        hop_rtts = defaultdict(list)
        total_hop_count = defaultdict(int)
        hop_count = defaultdict(int)
        total_asn_count_ipwhois = defaultdict(int)
        total_asn_count_bdrmapit = defaultdict(int)
        
        df = pd.read_csv(report_path, dtype={"asn_bdrmapit": str, "asn_ipwhois": str, "hop_ip": str, "hop": str})
        cur_paths = [[], [], []]
        for _, row in df.iterrows():
            hop_num = row["hop"]
            
            # break in trace - reset paths
            if pd.isnull(hop_num):
                add_to_paths(cur_paths)
                cur_paths = [[], [], []]
                continue
            
            # ! hardcoded check - change if not 3 packets per hop.
            pkt_idx = int(row["pkt"]) - 1
            if pkt_idx >= 3:
                continue
            
            # extract hop data from current row
            hop_ip = row["hop_ip"]
            rtt = row["rtt"]
            if isinstance(hop_ip, str):
                # hop_key = (hop_ip, int(hop_num))
                hop_num_str = "{:2}".format(hop_num)
                hop_key = f"{hop_num_str} hops | {hop_ip}"
                
                total_hop_count[hop_ip] += 1
                hop_count[hop_key] += 1
                
                total_hop_rtts[hop_ip].append(rtt)
                hop_rtts[hop_key].append(rtt)
            else:
                hop_ip = "*"
            
            cur_paths[pkt_idx].append(hop_ip)
            
            asn_ipwhois = row["asn_ipwhois"]
            if not pd.isna(asn_ipwhois):
                total_asn_count_ipwhois[asn_ipwhois] += 1
                
            asn_bdrmapit = row["asn_bdrmapit"]
            if not pd.isna(asn_bdrmapit):
                total_asn_count_bdrmapit[asn_bdrmapit] += 1
            
        
        # get average hop RTT for each hop IP
        total_avg_hop_rtt = {}
        for hop, rtts in total_hop_rtts.items():
            total_avg_hop_rtt[hop] = np.round(np.mean(rtts), decimals = 5)
        
        # get average hop RTT for each (hop IP, num hops from source)
        avg_hop_rtt = {}
        for hop_key, rtts in hop_rtts.items():
            avg_hop_rtt[hop_key] = np.round(np.mean(rtts), decimals = 5)
        
        paths_str = "\n".join(paths)
        
        # sort by value
        total_avg_hop_rtt = self.sort_by_value(total_avg_hop_rtt)
        avg_hop_rtt = self.sort_by_value(avg_hop_rtt)
        total_hop_count = self.sort_by_value(total_hop_count, True)
        hop_count = self.sort_by_value(hop_count, True)
        total_asn_count_ipwhois = self.sort_by_value(total_asn_count_ipwhois, True)
        total_asn_count_bdrmapit = self.sort_by_value(total_asn_count_bdrmapit, True)
        
        return  f"paths:\n  {'-' * 200}\n{paths_str}\n\n" + \
                f"total_avg_hop_rtt: {json.dumps(total_avg_hop_rtt, indent=2)}\n\n" + \
                f"avg_hop_rtt: {json.dumps(avg_hop_rtt, indent=2)}\n\n" + \
                f"total_hop_count: {json.dumps(total_hop_count, indent=2)}\n\n" + \
                f"hop_count: {json.dumps(hop_count, indent=2)}\n\n" + \
                f"total_asn_count_ipwhois: {json.dumps(total_asn_count_ipwhois, indent=2)}\n\n" + \
                f"total_asn_count_bdrmapit: {json.dumps(total_asn_count_bdrmapit, indent=2)}"


    # create a name for the analysis that doesn't already exist
    def create_analysis_name(self, filename):
        if not os.path.exists(f"{filename}.txt"):
            return f"{filename}.txt"
        
        version = 2
        while os.path.exists(f"{filename}-{version}.txt"):
            version += 1
        
        return f"{filename}-{version}.txt"
        

    # create analysis reports for [start_row, stop_row] inclusive based on domains.csv
    def bulk_analyze(self, start_row, stop_row):
        for row_num, domain, target_report, nbr_report in self.extract_reports(start_row, stop_row):
            base_filename = f"./analyses/{row_num}-{domain}"
            
            domain_filename = self.create_analysis_name(base_filename)
            with open(domain_filename, "w") as file:
                file.write(f"{target_report}:\n\n{self.analyze(target_report)}\n")
                
            complement_filename = self.create_analysis_name(f"{base_filename}-complement")
            with open(complement_filename, "w") as file:
                file.write(f"{nbr_report}:\n\n{self.analyze(nbr_report)}\n")


if __name__ == "__main__":
    ma = MeasurementAnalyzer()
    ma.bulk_analyze(2, 15)