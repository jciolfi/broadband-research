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
        target_report = f"report-{ip}_{domain}-{msmt_id}.csv"
        nbr_report = f"report-{nbr_ip}-{nbr_msmt_id}"
        reports.append((target_report, nbr_report))
        
    return reports

"""
For each IP
- create path as string, e.g. ip (ASN) -> * -> ip ...
- create a map of RTTs, e.g. (src, dst): [RTT1, RTT2]
- map of ASN: times visited
"""
def analyze(report_path):
    paths = []
    rtts = {}
    asns = {}
    
    df = pd.read_csv(report_path, dtype={"ASN": str, "hop_ip": str})
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
            if hop_ip in rtts:
                rtts[hop_ip].append(rtt)
            else:
                rtts[hop_ip] = [rtt]
        else:
            hop_ip = "*"
        cur_paths[int(row["pkt"]) - 1].append(hop_ip)
        
        asn = row["ASN"]
        if isinstance(asn, str):
            asns[asn] = asns.get(asn, 0) + 1
        
    for cp in cur_paths:
        paths.append(" -> ".join(cp))
    
    print(f"{len(paths)}, {paths}\n\n{rtts}\n\n{asns}")
        
            
    
    
    


if __name__ == "__main__":
    analyze("./reports/test.csv")