#!/usr/bin/env python3

# Purpose: Scan all of Valve's servers. Store per-region lists of those that run TF2 source dedicated servers.

import a2s
import concurrent.futures
import json
import netaddr
import pprint
import requests
import socket
import sys
import time



default_ports = list(range(27015, 27068 + 1))
empty_regions = "ams atl canm can cant canu dfw eze fra lhr ord par pwg pwj pwu pww pwz sea sham sha shat shau shb sof sto2 tsnm tsn tsnt tsnu tyo1 vie waw"


# Scans a given IP:PORT string, then returns it and whether it's a TF2 SRCDS
def scanIP(ip_port_str):
	ip, port = ip_port_str.split(":")
	port = int(port)
	is_tf2_srcds = False
	try:
		response = a2s.info((ip, port), timeout=0.500)
		is_tf2_srcds = response.folder == "tf"
	except (a2s.BrokenMessageError, socket.timeout):
		pass
	return ip_port_str, is_tf2_srcds


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
		if shortname in empty_regions:
			continue

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

		data = region[1]
		longname = shortname
		if "desc" in data:
			longname = data["desc"]
		nicename = f"{longname} ({shortname})"
		print(f"Region {nicename}:")
		ip_port_list = set()
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
								for l in default_ports:
									item = f"{str(k)}:{l}"
									if item not in old:
										ip_port_list.add(item)
						# If there is a hyphen and colon, this is an IP with a port range
						elif "-" in j and ":" in j:
							ip, port_range = j.split(":")
							port_range = port_range.split("-")
							start_port = int(port_range[0])
							end_port = int(port_range[1])
							for port in list(range(start_port, end_port + 1)):
								item = f"{ip}:{port}"
								if item not in old:
									ip_port_list.add(item)
						# There wasn't both a hyphen and colon; this is just an IP range string like X.X.X.X-Y.Y.Y.Y
						else:
							start_ip, end_ip = j.split("-")
							# Get a list of IPs in this range
							temp = []
							for k in netaddr.IPRange(start_ip, end_ip):
								for l in default_ports:
									temp.append(f"{str(k)}:{l}")
					else:
						# We've been given a dict
						ip, port_range = j["ipv4"], j["port_range"]
						for port in list(range(port_range[0], port_range[1] + 1)):
							item = f"{ip}:{port}"
							if item not in old:
								ip_port_list.add(item)
		print(f"Region {nicename} contains {len(ip_port_list)} possible servers.\n")
		region_server_lists.append({"region": nicename, "shortname": shortname, "ip_port_list": ip_port_list})
	return region_server_lists


# The nasty function above handles that mess for us and gives us a ton of individual IP:PORT pairs to scan.
region_server_lists = getPossibleServers()

# We're going to scan region-by-region and build up a list of TF2 dedicated servers
region_tf_lists = []
for i in region_server_lists:
	nicename = i["region"]
	shortname = i["shortname"]
	ip_port_list = i["ip_port_list"]
	num_servers = len(ip_port_list)
	print(f"[{time.time()}] Scanning for {num_servers} possible servers in {nicename}...")
	tf_servers = []
	executor = concurrent.futures.ThreadPoolExecutor(max_workers=768)
	future_objs = []
	for index, j in enumerate(ip_port_list):
		# Print progress
		percentage = round((index / num_servers) * 100, 2)
		sys.stdout.write(f"\rExecutor load progress: {percentage}%")
		sys.stdout.flush()

		ip, port = j.split(":")
		# Scan this server!
		future_obj = executor.submit(scanIP, f"{ip}:{port}")
		future_objs.append(future_obj)
	print()
	for future_obj in concurrent.futures.as_completed(future_objs):
		ip_port, result = future_obj.result()
		if result:
			tf_servers.append(ip_port)
	region_tf_lists.append({"region": nicename, "shortname": shortname, "ip_port_list": tf_servers})

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
	for server in region["ip_port_list"]:
		break
