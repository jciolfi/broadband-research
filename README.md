# Traceroute Launcher via RIPE Atlas

This code was developed at Northeastern University.

The following code provides utility for creating a traceroute measurement, importing traceroute measurement data, and an automated analysis for imported data. For convenience, domain info is held in domains.csv, which contains domains, their associated IP(s), a neighboring IP (one that is in the same /24 subnet), and RIPE Atlas measurement IDs for launched traceroutes. The goal of this code is to streamline the process to determine if two IPs in the same /24 subnet have differing physical paths. For all functions, the start row and stop row are inclusive.

## Launching a Traceroute

Since it takes time for traceroutes to be launched, there are a few steps involved before importing and analyzing traceroute data. Probes may be disconnected from RIPE Atlas, so it is good to use the RIPE Atlas wizard to find new probes/verify the probe IDs still are up. The wizard can be found by going to Measurements -> Create Measurement, and under Step 2, click Search.

1. Make sure the desired domain exists in `domains.csv`.
2. Launch a one-off traceroute using the associated row number in `domains.csv` to determine the associated IP with that domain. For now, manually enter these IPs into `domains.csv`.
3. Start dual measurement traceroutes with that row number with the desired parameters (interval between measurements in seconds, total duration in minutes, and the source probes which the traceroute is initiated from). This will launch traceroutes for the associated IP found in step (2) and another random IP in the same /24 subnet.

## Importing Traceroute Data

Importing is much simpler than launching. Just specify which rows you'd like to import data for. There are a few moving pieces that make the importing a bit longer - IP geolocation, IP to ASN lookups, etc. The raw data will be imported into the `traceroute_data` folder, and the flattened data is put into the `reports` folder.

## Analyzing Traceroute Data

Analyzing is also simpler like importing - just specify the rows you'd like to generate an analysis report for. These will show up in the `analyses` folder.

## ip2as
Instead of IPWhois, [ip2as](https://alexmarder.github.io/ip2as/) from [bdrmapit](https://alexmarder.github.io/bdrmapit/) was used with the following command: ip2as -p rib.prefixes -R rels-file -c cone-file -a as2org -P peeringdb.json -o ip2as.prefixes.

Below are links to download the required files:
- rib.prefixes: https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/
- rels-file: https://data.caida.org/datasets/as-organizations/
- cone-file: https://data.caida.org/datasets/as-organizations/
- as2org: https://data.caida.org/datasets/as-organizations/
- peeringdb.json: https://data.caida.org/datasets/peeringdb-v2/
- ip2as.prefixes: the output file.

This should be kept up to date in line with when each of the above files has a new release for the most accurate results.