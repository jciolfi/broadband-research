import numpy as np
import pandas as pd


def extract_reports(start, stop):
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
def analyze(report_path):
    paths = []
    hop_rtts = {}
    hop_count = {}
    asn_count = {}
    
    df = pd.read_csv(report_path, dtype={"ASN": str, "hop_ip": str, "hop": str})
    cur_paths = [[], [], []]
    for index, row in df.iterrows():
        # break in trace - reset paths
        if not row["hop"].isdigit():
            for cp in cur_paths:
                paths.append(" -> ".join(cp))
            cur_paths = [[], [], []]
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
        pkt_idx = int(row["pkt"]) - 1
        if 0 <= pkt_idx < 3:
            cur_paths[pkt_idx].append(hop_ip)
        
        asn = row["ASN"]
        if isinstance(asn, str):
            asn_count[asn] = asn_count.get(asn, 0) + 1
        
    for cp in cur_paths:
        paths.append(" -> ".join(cp))
        
    avg_hop_rtt = {}
    for hop, rtts in hop_rtts.items():
        avg_hop_rtt[hop] = np.round(np.mean(rtts), decimals = 5)
        
    def format_paths(paths):
        res = []
        for path in paths:
            res.append(f"        {path}")
        return "\n\n".join(res)
    
    return \
    f"""        
    avg_hop_rtt: {avg_hop_rtt}
        
    hop_count: {hop_count}
        
    asn_count: {asn_count}
    
    paths:
{format_paths(paths)}
    """


def bulk_analyze(start_row, stop_row):
    for row_num, domain, target_report, nbr_report in extract_reports(start_row, stop_row):
        with open(f"./analyses/{row_num}-{domain}.txt", "w") as file:
            file.write(f"{target_report}:\n{analyze(target_report)}")
            file.write(f"{'-' * 200}\n\n")
            file.write(f"{nbr_report}:\n\n{analyze(nbr_report)}")

if __name__ == "__main__":
    bulk_analyze(6, 6)