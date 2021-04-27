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
import subprocess
import sys
import time



parser = argparse.ArgumentParser()

# Scans a single region only
# Useful for testing or making sure we really have all the data for a region
parser.add_argument("--single-region", type=str)

# If you really want to scan regions with no tf2 servers, you can, I guess
parser.add_argument("--scan-empty-only", action="store_true")

# Essentially how many API calls to be making at the same time. There may be one extra worker. I hope you know what you're doing!
# 64 workers takes 9-10 minutes to scan non-empty regions.
# 128 workers takes about 4-5 minutes.
# If you set workers to 256 you can get ratelimited in about two minutes ^:)
parser.add_argument("--workers", type=int, default=128)

# The endpoint potato.py uses does not require an API key.
# This is only useful for testing provided a Valve-approved higher API call limit, or for the sake of more transparent API usage.
# If you store your key in api-key.txt, that will be used instead.
parser.add_argument("--api-key", type=str)

# Commit changed lists after running
parser.add_argument("--commit", action="store_true")

# Push commited changes after running
parser.add_argument("--push", action="store_true")

args = parser.parse_args()


key_param = ""
try:
	file = open("api-key.txt", "r")
	data = file.read()
	file.close()
	key_param = f"&key={data.strip()}"
except FileNotFoundError:
	if hasattr(args, "api_key"):
		key_param = f"&key={args.api_key}"

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

		if args.single_region and shortname != args.single_region:
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
	to_remove = []
	session = requests.Session()
	session.headers.update({"user-agent": "potato.py/1.0 (https://github.com/incontestableness/GLaDOS)"})
	for ip in ip_list:
		response = session.get(f"https://api.steampowered.com/ISteamApps/GetServersAtAddress/v0001?addr={ip}{key_param}")
		try:
			json_obj = json.loads(response.content)
		except json.decoder.JSONDecodeError:
			print(response.content)
			os.system("touch potato_ratelimited")
			os.abort()
		if json_obj["response"]["success"] != True:
			raise RuntimeError(f"API call was not successful for IP {ip}!")
		servers = json_obj["response"]["servers"]
		if len(servers) == 0:
			for port in range(27015, 27080):
				to_remove.append(f"{ip}:{port}")
		for i in servers:
			if i["appid"] == 440:
				tf_servers.append(f"{ip}:{i['gameport']}")
	return tf_servers, to_remove


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
	chunk_size = int(len(ip_list) / args.workers) if len(ip_list) >= args.workers else len(ip_list)
	chunked = list(iter(lambda: tuple(islice(it, chunk_size)), ()))

	# Load old list first if any
	# This way, when the API reports no TF2 servers for an IP, we can remove that server from the list if it was previously discovered
	filename = shortname + ".tf_list"
	old = []
	try:
		file = open(filename, "r")
		data = file.read()
		file.close()
		old = data.split("\n")[:-1]
	except FileNotFoundError:
		pass

	print(f"[{time.time()}] Querying the Steam API for {num_ips} IP addresses in {nicename} using {len(chunked)} workers...")
	tf_servers = []
	count_removed = 0
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
	future_objs = []
	for chunk in chunked:
		future_obj = executor.submit(query_ip_list, chunk)
		future_objs.append(future_obj)
	for future_obj in concurrent.futures.as_completed(future_objs):
		found_servers, to_remove = future_obj.result()
		for i in found_servers:
			tf_servers.append(i)
		# This is probably the simplest way to do this, sadly
		for server in to_remove:
			try:
				old.remove(server)
				count_removed += 1
			except ValueError:
				pass
	print(f"Removed {count_removed} servers from {shortname}")
	region_tf_lists.append({"region": nicename, "shortname": shortname, "ip_list": tf_servers})

	# Add to existing list if possible
	for server in tf_servers:
		if server not in old:
			old.append(server)

	# Save the lists for each region to their own file
	if len(old) > 0:
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


if args.commit:
	# Check git status for staged files
	status, _ = subprocess.getstatusoutput("git status | grep \"Changes to be committed\"")
	if status == 0:
		print("Not committing because there are staged files.")
		exit()
	# Check git status for non-staged changes
	status, _ = subprocess.getstatusoutput("git status | grep -v \"\.tf_list\" | grep modified")
	if status == 0:
		print("Not committing because there are non-staged changes.")
		exit()
	# Commit list changes
	os.system("git add *.tf_list; git commit -m \"Update data (potato)\"")
	if args.push:
		# Check if this is the only new commit
		status, _ = subprocess.getstatusoutput("git status | grep \"Your branch is ahead of 'origin/master' by 1 commit.\"")
		if status != 0:
			print("Not pushing because there is not only one commit (no list changes or unpushed commits).")
			exit()
		# Push updates
		os.system("git push")
