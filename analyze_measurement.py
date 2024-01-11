import numpy as np
import pandas as pd

"""
Things to look for
- overall path length (number of hops)
- latency (RTT for each hop, total RTT)
- hop addresses (are certain addresses used more than others)
- consistency (are there variations in the paths for different traceroutes)
- path stability (fluctuations in latency or path changes over time)
"""

class MeasurementAnalyzer:
    def __init__(self):
        pass

    # extract values in row as a tuple from domains.csv from [start_row, stop_row] inclusive
    def extract_reports(self, start, stop):
        df = pd.read_csv("domains.csv", dtype={"Msmt_ID": str, "Neighbor_Msmt_ID": str})
        reports = []
        for i in range(start - 2, stop - 1):
            row = df.iloc[i]
            if any(row.isna()):
                print(f'warning: row {i + 2} ({row["Domain"]}) contains empty values. Skipping...')
                continue
            
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
        def add_to_paths(cur_paths):
            nonlocal paths
            for cp in cur_paths:
                if len(cp) > 0:
                    paths.append(f"        (hops {len(cp)}): {' -> '.join(cp)}")
            
        
        paths = []
        hop_rtts = {}
        hop_count = {}
        asn_count = {}
        
        df = pd.read_csv(report_path, dtype={"ASN": str, "hop_ip": str, "hop": str})
        cur_paths = [[], [], []]
        for _, row in df.iterrows():
            # break in trace - reset paths
            if pd.isnull(row["hop"]):
                add_to_paths(cur_paths)
                cur_paths = [[], [], []]
                continue
            
            # hardcoded check - change if not 3 packets per hop.
            pkt_idx = int(row["pkt"]) - 1
            if pkt_idx >= 3:
                continue
                
            hop_ip = row["hop_ip"]
            rtt = row["RTT"]
            if isinstance(hop_ip, str):
                hop_count[hop_ip] = hop_count.get(hop_ip, 0) + 1
                if hop_ip in hop_rtts:
                    hop_rtts[hop_ip].append(rtt)
                else:
                    hop_rtts[hop_ip] = [rtt]
            else:
                hop_ip = "*"
            
            # if hop_ip != "*" or cur_paths[pkt_idx][-1] != "*":
            cur_paths[pkt_idx].append(hop_ip)
            
            asn = row["ASN"]
            if isinstance(asn, str):
                asn_count[asn] = asn_count.get(asn, 0) + 1
        
        avg_hop_rtt = {}
        for hop, rtts in hop_rtts.items():
            avg_hop_rtt[hop] = np.round(np.mean(rtts), decimals = 5)
        
        paths_str = "\n\n".join(paths)
        
        return \
        f"""
        avg_hop_rtt: {avg_hop_rtt}
            
        hop_count: {hop_count}
            
        asn_count: {asn_count}
        
        paths:
{paths_str}
        """


    # create analysis reports for [start_row, stop_row] inclusive based on domains.csv
    def bulk_analyze(self, start_row, stop_row):
        for row_num, domain, target_report, nbr_report in self.extract_reports(start_row, stop_row):
            with open(f"./analyses/{row_num}-{domain}.txt", "w") as file:
                file.write(f"{target_report}:\n{self.analyze(target_report)}\n")
                file.write(f"{'-' * 200}\n\n")
                file.write(f"{nbr_report}:\n{self.analyze(nbr_report)}")





if __name__ == "__main__":
    ma = MeasurementAnalyzer()
    ma.bulk_analyze(2, 12)