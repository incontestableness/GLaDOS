#!/usr/bin/env python3

# Purpose: Provide an IP whitelist for GLaDOS API inputs

import netaddr
import requests
import subprocess



# Get networks from Valve's NetworkDatagramConfig.json
response = requests.get("https://raw.githubusercontent.com/SteamDatabase/SteamTracking/master/Random/NetworkDatagramConfig.json", headers={"User-Agent": "valve_whitelist.py/1.0 (https://github.com/incontestableness/GLaDOS)"})
ndc = response.json()
regions = ndc["pops"].items()
networks = set()
for region in regions:
	data = region[1]
	if "relays" in data:
		for r in data["relays"]:
			networks.add(netaddr.IPAddress(r["ipv4"]))
	if "service_address_ranges" in data:
		for item in data["service_address_ranges"]:
			if "-" in item:
				start_ip, end_ip = item.split("-")
				networks.add(netaddr.IPRange(start_ip, end_ip))
			else:
				networks.add(netaddr.IPNetwork(item))

# Get networks from Valve's ASN
output = subprocess.check_output("whois -h whois.radb.net '!gas32590'", shell=True)
asn_cidrs = output.decode().split("\n")[1].split()
for cidr in asn_cidrs:
	networks.add(netaddr.IPNetwork(cidr))

# Compress networks into the smallest possible list of CIDRs
cidrs = netaddr.cidr_merge(networks)

if __name__ == "__main__":
	for i in cidrs:
		print(i)
