#!/usr/bin/env python3

# Purpose: Query a Steam API for each of Valve's servers to determine what ports TF2 servers are running on, then store per-region lists of them.
# This is a much more lightweight and efficient method of host discovery compared to zeolite.py.

import argparse
import a2s
import concurrent.futures
from itertools import islice
import json
import netaddr
import os
import pprint
import requests
import sys
import time



parser = argparse.ArgumentParser()

# If you really want to scan regions with no tf2 servers, you can, I guess
parser.add_argument("--scan-empty-only", action="store_true")

# Essentially how many API calls to be making at the same time. There may be one extra worker. I hope you know what you're doing!
# 64 workers takes 9-10 minutes to scan non-empty regions.
# 128 workers takes about 4-5 minutes.
# If you set workers to 256 you can get ratelimited in about two minutes ^:)
parser.add_argument("--workers", type=int, default=128)

args = parser.parse_args()


empty_regions = "ams atl canm can cant canu dfw eze fra lhr ord par pwg pwj pwu pww pwz sea sham sha shat shau shb sof sto2 tsnm tsn tsnt tsnu tyo1 vie waw"
empty_regions = empty_regions.split(" ")


# This function is a bit ugly. Too bad!
def getPossibleServers():
	# The first thing we need to do is fetch a list of Valve's server IP ranges.
	# SteamDatabase maintains a nice collection for us...
	response = requests.get("https://raw.githubusercontent.com/SteamDatabase/SteamTracking/master/Random/NetworkDatagramConfig.json")
	ndc = json.loads(response.content)
	regions = ndc["pops"].items()
	region_server_lists = []
	for region in regions:
		shortname = region[0]

		# This logic is particularly dumb but I can't remember how to do it better right now
		if args.scan_empty_only:
			if shortname not in empty_regions:
				continue
		else:
			if shortname in empty_regions:
				continue

		data = region[1]
		longname = shortname
		if "desc" in data:
			longname = data["desc"]
		nicename = f"{longname} ({shortname})"
		print(f"Region {nicename}:")
		ip_list = set()
		for i in ["relay_addresses", "relays", "service_address_ranges"]:
			if i in data:
				ip_data = data[i]
				formatted = pprint.pformat(ip_data)
				print(f"{i}: {formatted}")
				for j in ip_data:
					if type(j) == str:
						# Is this a CIDR?
						if "/" in j:
							# Get a list of IPs in this range
							for k in netaddr.IPNetwork(j):
								ip_list.add(k)
						# If there is a hyphen and colon, this is an IP with a port range
						elif "-" in j and ":" in j:
							ip = j.split(":")[0]
							ip_list.add(ip)
						# There wasn't both a hyphen and colon; this is just an IP range string like X.X.X.X-Y.Y.Y.Y
						else:
							start_ip, end_ip = j.split("-")
							# Get a list of IPs in this range
							for k in netaddr.IPRange(start_ip, end_ip):
								ip_list.add(k)
					else:
						# We've been given a dict
						ip_list.add(j["ipv4"])
		print(f"Region {nicename} contains {len(ip_list)} IP addresses.\n")
		region_server_lists.append({"region": nicename, "shortname": shortname, "ip_list": ip_list})
	return region_server_lists


# The nasty function above handles that mess for us and gives us a ton of individual IP addresses to query the API for.
region_server_lists = getPossibleServers()


# Ask the Steam API about what servers are running behind this IP
def query_ip_list(ip_list):
	tf_servers = []
	session = requests.Session()
	session.headers.update({"user-agent": "potato.py/1.0 (https://github.com/incontestableness/GLaDOS)"})
	for ip in ip_list:
		response = session.get(f"https://api.steampowered.com/ISteamApps/GetServersAtAddress/v0001?addr={ip}")
		try:
			json_obj = json.loads(response.content)
		except json.decoder.JSONDecodeError:
			print(response.content)
			os.abort()
		if json_obj["response"]["success"] != True:
			raise RuntimeError(f"API call was not successful for IP {ip}!")
		servers = json_obj["response"]["servers"]
		for i in servers:
			if i["appid"] == 440:
				tf_servers.append(f"{ip}:{i['gameport']}")
	return tf_servers


# We're going to scan region-by-region and build up a list of TF2 dedicated servers
region_tf_lists = []
for i in region_server_lists:
	nicename = i["region"]
	shortname = i["shortname"]
	ip_list = i["ip_list"]
	num_ips = len(ip_list)

	# Q: Why not just use e.g. 64 workers running a theoretical scanIP(ip) function that calls requests.get() on the API?
	# A: Each requests.get() will perform a DNS lookup. The thread pool constantly has 64 instances of the function running. If the API is fast enough, you'll spam your DNS server with queries every 10 ms or so. Two problems with that; a. it's an unnecessary and wasteful usage of traffic - about 25% of the packets would be DNS related, and b. your DNS resolver might eventually shit itself and cause the error "No address associated with hostname".

	# To solve those problems, we're going to split the IP address list into args.workers chunks, the lengths of which will vary depending on the number of addresses in a region.
	# Then we're going to asynchronously spawn query_IP_list() instances which will (ideally) use a single connection per worker for many IP queries.
	# We use significantly fewer connections and DNS lookups while still getting good throughput via multiple workers in the thread pool this way.
	it = iter(ip_list)
	chunk_size = int(len(ip_list) / args.workers)
	chunked = list(iter(lambda: tuple(islice(it, chunk_size)), ()))

	print(f"[{time.time()}] Querying the Steam API for {num_ips} IP addresses in {nicename} using {len(chunked)} workers...")
	tf_servers = []
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
	future_objs = []
	for chunk in chunked:
		future_obj = executor.submit(query_ip_list, chunk)
		future_objs.append(future_obj)
	for future_obj in concurrent.futures.as_completed(future_objs):
		found_servers = future_obj.result()
		for i in found_servers:
			tf_servers.append(i)
	region_tf_lists.append({"region": nicename, "shortname": shortname, "ip_list": tf_servers})

	# Load old list if any
	filename = shortname + ".tf_list"
	old = []
	try:
		file = open(filename, "r")
		data = file.read()
		file.close()
		old = data.split("\n")[:-1]
	except FileNotFoundError:
		pass

	# Add to existing list if possible
	for server in tf_servers:
		if server not in old:
			old.append(server)

	# Save the lists for each region to their own file
	old.sort()
	file = open(filename, "a")
	file.truncate(0)
	for server in old:
		file.write(f"{server}\n")
	file.close()

# Additional processing can be done after-the-fact like so
for region in region_tf_lists:
	shortname = region["shortname"]
	for server in region["ip_list"]:
		break
