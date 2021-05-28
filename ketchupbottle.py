#!/usr/bin/env python3

# Purpose: Find servers on ports the Steam API doesn't report for some reason

import argparse
import asyncio
import a2s
from itertools import islice
import json
import multiprocessing
import netaddr
import random
import requests
import resource
import time



parser = argparse.ArgumentParser()
parser.add_argument("-c", "--connections", type=int, default=1024, help="The number of IP addresses to scan concurrently IN EACH PROCESS. This value should be limited with respect to single-thread CPU performance. Default 1024.")
parser.add_argument("-p", "--processes", type=int, default=1, help="How many processes to spawn. Default 1.")
parser.add_argument("--port-range", type=str, default="27090-27115", help="Inclusive port range to scan. Ex: 27015-27115. Default 27090-27115.")
parser.add_argument("--regions", type=str)
args = parser.parse_args()


start_port, end_port = args.port_range.split("-")
start_port, end_port = int(start_port), int(end_port)
default_ports = list(range(start_port, end_port + 1))

if args.regions:
	args.regions = args.regions.split(",")

empty_regions = "ams atl canm can cant canu dfw eze fra lhr ord par pwg pwj pwu pww pwz sea sham sha shat shau shb sof sto2 tsnm tsn tsnt tsnu tyo1 vie waw"
empty_regions = empty_regions.split(" ")


# Generously increase open file limit
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (32768, hard))


# Returns lists of IP addresses that may be running TF2 servers in each region
def getPossibleServers():
	# The first thing we need to do is fetch a list of Valve's server IP ranges.
	# SteamDatabase maintains a nice collection for us...
	response = requests.get("https://raw.githubusercontent.com/SteamDatabase/SteamTracking/master/Random/NetworkDatagramConfig.json")
	ndc = json.loads(response.content)
	regions = ndc["pops"].items()
	region_ip_lists = {}
	for region in regions:
		shortname = region[0]

		if shortname in empty_regions:
			continue

		if args.regions and shortname not in args.regions:
			continue

		region_ip_lists[shortname] = set()
		data = region[1]
		longname = data["desc"]
		nicename = f"{longname} ({shortname})"
		for r in data["relays"]:
			# We've been given a dict
			region_ip_lists[shortname].add(r["ipv4"])
		for cidr in data["service_address_ranges"]:
			# Get a list of IPs in this CIDR range
			for ip in netaddr.IPNetwork(cidr):
				region_ip_lists[shortname].add(str(ip))
		print(f"Region {nicename} contains {len(region_ip_lists[shortname])} IP addresses.")
	return region_ip_lists


# The function above gives us a ton of individual IP addresses to query the API for.
region_ip_lists = getPossibleServers()


# Scans a server asynchronously. Makes 3 attempts in the case of timeout or message error.
async def scanServer(ip, port, shortname, attempts=1):
	server_str = f"{ip}:{port}"
	try:
		response = await a2s.ainfo((ip, port), timeout=0.500)
		return response.folder == "tf", server_str, shortname
	except ConnectionRefusedError:
		pass
	except (a2s.BrokenMessageError, asyncio.TimeoutError):
		if attempts < 3:
			await asyncio.sleep(random.randint(100, 600) / 1000)
			return await scanServer(ip, port, shortname, attempts + 1)
	return False, None, None


# Not certain we need locking but it doesn't hurt terribly.
manager = multiprocessing.Manager()
lock = manager.Lock()


# Runs scans in a process
def MSWin31StartupSound(id, servers, region_tf_lists, lock):
	asyncio.run(chunkHandler(id, servers, region_tf_lists, lock))


# Handles the scanning of a group of servers
async def chunkHandler(id, servers, region_tf_lists, lock):
	# Create awaitable objects
	awaitables = []
	for s in servers:
		awaitables.append(scanServer(s.ip, s.port, s.shortname))
	# Process args.connections awaitables at a time
	it = iter(awaitables)
	batches = list(iter(lambda: tuple(islice(it, args.connections)), ()))
	for index, batch in enumerate(batches):
		if id == 0:
			print(f"[{time.time()}] [Process {id}] Batch {index + 1}/{len(batches)}")
		for coroutine in asyncio.as_completed(batch):
			is_tf2_srcds, server_str, shortname = await coroutine
			if is_tf2_srcds:
				with lock:
					rtl = region_tf_lists[shortname]
					rtl.append(server_str)
					region_tf_lists[shortname] = rtl


# Represents a server to scan
class Server:
	def __init__(self, ip, port, shortname):
		self.ip = ip
		self.port = port
		self.shortname = shortname


def main():
	region_tf_lists = manager.dict()
	for shortname in region_ip_lists:
		region_tf_lists[shortname] = []

	for port in default_ports:
		start = time.time()
		servers = []
		for shortname in region_ip_lists:
			ip_list = region_ip_lists[shortname]
			for ip in ip_list:
				servers.append(Server(ip, port, shortname))
		# Break the servers into groups for each process
		it = iter(servers)
		chunk_size = int(len(servers) / args.processes) if len(servers) >= args.processes else len(servers)
		chunks = list(iter(lambda: tuple(islice(it, chunk_size)), ()))
		# Spin up processes
		print(f"\n[{time.time()}] Scanning all servers on port {port}...")
		processes = []
		for index, server_group in enumerate(chunks):
			process = multiprocessing.Process(target=MSWin31StartupSound, args=(index, server_group, region_tf_lists, lock))
			process.start()
			processes.append(process)
		for p in processes:
			p.join()
		elapsed = round(time.time() - start, 2)
		print(f"[{time.time()}] Scans complete (took {elapsed} secs)...")


	print(f"\n[{time.time()}] Writing final data...")
	for shortname in region_tf_lists:
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
		for server in region_tf_lists[shortname]:
			if server not in old:
				old.append(server)

		# Save the lists for each region to their own file
		old.sort()
		file = open(filename, "a")
		file.truncate(0)
		for server in old:
			file.write(f"{server}\n")
		file.close()


if __name__ == "__main__":
	main()
