#!/usr/bin/env python3

import asyncio
import a2s
import concurrent.futures
from debug import *
import json
from object_classes import TFMap, PName, Server
import pickle
import re
import requests
import socket
from string import ascii_letters, digits, punctuation
import threading
import time
import traceback



# API setup
with open("api-key.txt") as file:
	api_key = file.read().strip()

session = requests.Session()
session.headers.update({"user-agent": "GLaDOS.py/3.0 (https://github.com/incontestableness/GLaDOS)"})


# Times code execution inside a with Timer() block
class Timer:
	def __init__(self, prefix, suffix="", precision=2):
		self.prefix = prefix
		self.suffix = suffix
		self.precision = precision

	def __enter__(self):
		self.start = time.time()

	def __exit__(self, type, value, traceback):
		elapsed = round(time.time() - self.start, self.precision)
		print(f"{self.prefix} (took {elapsed} secs)...{self.suffix}")


# Handles active server scanning
class MoralityCore:
	def __init__(self, scan_frequency, scan_timeout, suspicious_times_seen, cheater_times_seen):
		# Init
		self.scan_frequency = scan_frequency
		self.scan_timeout = scan_timeout
		self.suspicious_times_seen = suspicious_times_seen
		self.cheater_times_seen = cheater_times_seen
		self.last_save = time.time()

		# Stops scanning when set to True
		self.halt = False

		# Signals the restart endpoint that it's okay to proceed
		self.halted = False

		# Keeps track of potential bot names
		self.bot_names = {}

		# Cached API data
		self.region_map_trackers = []

		# No need to create these every time they're needed
		self.dupematch = re.compile("^(\([1-9]\d?\))")
		self.allowed_chars = ascii_letters + digits + punctuation + " "

		# We need to load these the first time
		self.load_blacklists()

		# Load saved data where possible
		for vname in ["bot_names", "region_map_trackers"]:
			try:
				file = open(f"{vname}.pkl", "rb")
				exec(f"self.{vname} = pickle.load(file)")
				file.close()
				print(f"Successfully loaded pickled data for self.{vname}")
			except FileNotFoundError:
				print(f"Failed to load pickled data for self.{vname}")

		# Run server scans in another thread
		# This thread just repopulates the class object's data on bot maps,
		# so it's okay to terminate it with the main thread
		snoipin = threading.Thread(target=self.lucksman, args=(), daemon=True)
		snoipin.start()


	def save_data(self):
		for vname in ["bot_names", "region_map_trackers"]:
			file = open(f"{vname}.pkl", "wb")
			exec(f"pickle.dump(self.{vname}, file)")
			file.close()
			print(f"Successfully saved pickled data for self.{vname}")


	def load_blacklists(self):
		patterns = []
		evasion_sequences = []
		evasion_sequences_OR_mode = []
		with open("name_blacklist.txt", "r") as bl:
			data = bl.read()
			# Store this so blacklist_name() can check and prevent duplicates
			self.name_blacklist = data.split("\n")[:-1]
			for pattern in self.name_blacklist:
				# Ignore empty lines
				if pattern == "":
					continue
				# Trust me, this entire line is necessary
				pattern = pattern.encode().decode("unicode-escape").encode("UTF-8").decode()
				# Add the prefix
				pattern = "^(\([1-9]\d?\))?" + pattern
				# https://docs.python.org/3/library/re.html#re.ASCII
				compiled = re.compile(pattern, flags=re.ASCII)
				patterns.append(compiled)
		self.patterns = patterns
		print("Name pattern blacklist loaded!")
		with open("evade_blacklist.txt", "r") as bl:
			data = bl.read()
			evade_blacklist = data.split("\n")[:-1]
			for pattern in evade_blacklist:
				compiled = re.compile(pattern)
				evasion_sequences.append(compiled)
		self.evasion_sequences = evasion_sequences
		# Some evasion patterns contain ".*"; we need to recompile these patterns to make stripping names possible
		for evade_pattern in self.evasion_sequences:
			evade_pattern_OR_mode = re.compile(evade_pattern.pattern.replace(".*", "|"))
			evasion_sequences_OR_mode.append(evade_pattern_OR_mode)
		self.evasion_sequences_OR_mode = evasion_sequences_OR_mode
		print("Evasion sequences loaded!")


	# Formats the given name and adds it to names_blacklist.txt, then reloads patterns from the file
	# This will persist changes in a human readable/writable format
	def blacklist_name(self, name):
		name = name.encode("unicode-escape").decode()
		name = re.escape(name)
		if name in self.name_blacklist:
			print(f"Not adding duplicate name {name}!")
			return
		file = open("name_blacklist.txt", "a")
		file.write(f"{name}\n")
		file.close()
		print(f"Updated name_blacklist.txt...")
		self.load_blacklists()


	# Returns the first pattern that matches the name, if any
	def check_name(self, name):
		# We've been given some name to check.
		# If GLaDOS knows about this name but it's not blacklisted yet, do so when confident.
		# First, try to match the name against existing patterns
		for name_pattern in self.patterns:
			if name_pattern.fullmatch(name):
				match_debug(f"Name \"{self.unevade(name)}\" matched pattern: {self.unevade(name_pattern.pattern)}")
				return name_pattern
		# No match? Try removing evasion characters and then matching
		stripped = name
		for evade_pattern_OR_mode in self.evasion_sequences_OR_mode:
			# Strip each evasion character
			stripped = re.sub(evade_pattern_OR_mode, "", stripped)
		# Now try matching
		for name_pattern in self.patterns:
			if name_pattern.fullmatch(stripped):
				match_debug(f"This name ({self.unevade(name)}), when STRIPPED, matched pattern: {self.unevade(name_pattern.pattern)}")
				# Add this variant to the stripped name
				pn = self.bot_names.setdefault(stripped, PName(stripped))
				pn.variants.add(name)
				self.bot_names[stripped] = pn
				return name_pattern
		# We didn't match against existing patterns, even when the name is stripped
		# If the name starts with (N), warn about it
		if self.dupematch.match(name):
			match_debug(f"Name \"{self.unevade(name)}\" matched dupe pattern! New bot name or evade char?")
			return self.dupematch
		# We didn't match any patterns for the name, but it's possible that it's been seen used with char injection before.
		# Check this name's times_seen - if this is happening often enough, blacklist it
		# blacklist_name() checks for a duplicate before adding which makes this thread-safe
		pn = self.bot_names.get(name)
		if pn is not None:
			if pn.times_seen >= self.suspicious_times_seen:
				# This name wasn't caught by the dupematch but it's suspicious and we're still seeing it.
				# Since it won't be incremented as a result of matching the dupematch we have to do it ourselves here.
				pn.increment()
				name_debug(f"Saw a recurring name ({self.unevade(name)}) not yet blacklisted. Times seen: {pn.times_seen}")
				if pn.times_seen >= self.cheater_times_seen:
					name_debug(f"The aforementioned name will now be blacklisted.")
					self.blacklist_name(name)
					return None
		# Check the stripped name's times seen
		else:
			stripped = self.strip_name(name)
			if len(stripped) == 0 or stripped.replace(" ", "") == "":
				return None
			pn = self.bot_names.get(stripped)
			if pn is None:
				return None
			if pn.times_seen >= self.suspicious_times_seen:
				name_debug(f"This name ({self.unevade(name)}), when STRIPPED, matches a previously seen name ({self.unevade(pn.name)}). Times seen: {pn.times_seen}")
				if pn.times_seen >= self.cheater_times_seen:
					name_debug(f"The aforementioned name will now be blacklisted in stripped form.")
					self.blacklist_name(stripped)
					return None


	# Removes the leading (N) from names
	def undupe(self, name):
		return re.sub(self.dupematch, "", name)


	# Helper function to increment or create the PName for the given bot name
	def incrementPName(self, name):
		# https://groups.google.com/g/comp.lang.python/c/unFvJJB-iAM
		# https://docs.python.org/3/library/stdtypes.html#dict.setdefault
		pn = self.bot_names.setdefault(name, PName(name))
		pn.increment()
		self.bot_names[name] = pn


	# Same concept here but with TFMaps
	def updateMap(self, popular_bot_maps, name, bot_count, server_seen_on):
		if bot_count > 0:
			for i in popular_bot_maps:
				if i.name == name:
					i.bot_count += bot_count
					i.servers.add(server_seen_on)
					return popular_bot_maps
			# Map doesn't exist yet, create it and append to the list
			m = TFMap(name, bot_count, server_seen_on)
			popular_bot_maps.append(m)
		return popular_bot_maps


	# Scan a server and return information about it for map targeting
	async def scanServer(self, server_str, map_name):
		ip, port = server_str.split(":")
		server = (ip, int(port))
		try:
			players = await a2s.aplayers(server, timeout=self.scan_timeout)
			total_players = 0
			bot_count = 0
			for p in players:
				if p.name == "":
					continue
				total_players += 1
				if self.check_name(p.name):
					# This can run multiple times, increasing map "score" by bot count, unless we break out of the loop.
					# Currently we allow it to do so.
					bot_count += 1
					self.incrementPName(self.undupe(p.name))
			bot_count += len(self.getNamestealers(players))
			return map_name, total_players, bot_count, server_str
		except ConnectionRefusedError:
			print(f"Server {server_str} refused the connection...")
			return None, None, None, None
		except asyncio.TimeoutError:
			timeout_debug(f"Server {server_str} timed out after {self.scan_timeout} seconds...")
			return None, None, None, None
		except a2s.exceptions.BrokenMessageError:
			print(f"Server {server_str} sent a bad response...")
			return None, None, None, None


	# Returns an ASCII-only string
	def strip_name(self, name):
		return "".join(filter(lambda x: x in self.allowed_chars, name))


	# Returns true if the name has evading character sequences in it
	def is_evaded(self, name):
		for seq in self.evasion_sequences:
			match = seq.search(name)
			if match is not None:
				return True
		return False


	# Return a name suitable for printing
	def unevade(self, name):
		return name.encode("unicode-escape").decode()


	# Returns a list of player names that are likely spoofing as another player or evading name detection
	def getNamestealers(self, players):
		# Extract names from Player objects
		names = []
		for p in players:
			if p.name != "":
				names.append(p.name)
		namestealers = set()
		to_check = names
		for first_name in names:
			# Don't check first_name against itself
			to_check = to_check[1:]
			fs = self.strip_name(first_name)

			# If the name is practically empty after stripping non-ascii characters, skip it
			if len(fs) == 0 or fs.replace(" ", "") == "":
				continue

			matches = []
			for second_name in to_check:
				ss = self.strip_name(second_name)
				if len(ss) == 0 or ss.replace(" ", "") == "":
					continue
				if fs == ss:
					matches.append(second_name)
			for m in matches:
				if self.is_evaded(m) and not self.is_evaded(first_name):
					namesteal_debug(f"{self.unevade(m)} stole {self.unevade(first_name)}'s name!")
					namestealers.add(m)
					try:
						to_check.remove(m)
					except ValueError:
						pass
				elif self.is_evaded(first_name) and not self.is_evaded(m):
					namesteal_debug(f"{self.unevade(first_name)} stole {self.unevade(m)}'s name!")
					namestealers.add(first_name)
					try:
						to_check.remove(first_name)
					except ValueError:
						pass
				elif (not self.is_evaded(first_name)) and (not self.is_evaded(m)):
					print("WARNING: is_evaded() didn't catch the injected chars!")
					print(f"First name: {self.unevade(first_name)}")
					print(f"Second name: {self.unevade(m)}")
					# Throw these in so getnames.py can deal with it
					self.incrementPName(self.undupe(first_name))
					self.incrementPName(self.undupe(m))
				else:
					inject_debug(f"{self.unevade(first_name)} and {self.unevade(m)} are char injecting")
					namestealers.add(first_name)
					namestealers.add(m)
					self.incrementPName(self.strip_name(first_name))
					self.incrementPName(self.strip_name(m))
					try:
						to_check.remove(first_name)
					except ValueError:
						pass
					try:
						to_check.remove(m)
					except ValueError:
						pass
		if len(namestealers) > 0:
			unevaded = []
			for i in namestealers:
				unevaded.append(self.unevade(i))
			namesteal_debug(f"{len(namestealers)} namestealers: {unevaded}")
		return list(namestealers)


	# This function is called when a user or bot is assigned a match server
	# In addition to checking regex patterns, it also looks for namestealers
	def checkServer(self, server):
		ip, port = server.split(":")
		server = (ip, int(port))
		players = a2s.players(server, timeout=self.scan_timeout)
		bot_count = 0
		for p in players:
			if self.check_name(p.name):
				bot_count += 1
		namestealers = self.getNamestealers(players)
		return bot_count, namestealers


	# Purpose: Fetch active TF2 servers from the Steam API and pre-process the data for asynchronous scanning.
	def start_scan(self):
		all_servers = []
		try:
			with Timer("Fetched TF2 servers from Steam API"):
				response = session.get(f"https://api.steampowered.com/IGameServersService/GetServerList/v1/?key={api_key}&filter=appid\\440\\white\\1&limit=5000")
				all_servers = response.json()["response"]["servers"]
		except (requests.exceptions.ConnectionError, requests.exceptions.SSLError, KeyError, json.decoder.JSONDecodeError) as ex:
			print(traceback.format_exc())
			if type(ex) == json.decoder.JSONDecodeError:
				print(f"Failed to decode response content:\n{response.content}")
			elif type(ex) == KeyError:
				print(f"The Steam API didn't return a proper response:\n{response.json()}")
			else:
				print("Failed to contact the Steam API server.")
			time.sleep(1)
		servers_by_region = {}
		for region_id in range(0, 7 + 1):
			servers_by_region[region_id] = []
		for server in all_servers:
			# Wrong lever!
			if "mvm" in server["gametype"].split(","):
				continue
			if server["players"] == 0:
				continue
			region_servers = servers_by_region[server["region"]]
			region_servers.append(Server(server["addr"], server["map"]))
			servers_by_region[server["region"]] = region_servers
		loop = asyncio.get_event_loop()
		with Timer("Scans complete"):
			loop.run_until_complete(self.scan_servers(servers_by_region))


	# Purpose: Scan TF2 gameservers to determine what maps malicious bots are currently on so that they can be targeted every time bots queue.
	async def scan_servers(self, servers_by_region):
		# Asynchronous badassness. We can scan all the active TF2 dedicated servers in under 5 seconds.
		region_map_trackers = {}
		region_awaitables = []
		for region_id in servers_by_region:
			server_list = servers_by_region[region_id]
			region_awaitables.append(self.scan_region(region_id, server_list))
		for coroutine in asyncio.as_completed(region_awaitables):
			tracker = await coroutine
			region_map_trackers[tracker["region_id"]] = tracker
		# Give new, completed data to the API by updating the class object-scoped variable
		self.region_map_trackers = dict(sorted(region_map_trackers.items()))


	# Scans all the servers in a region asynchronously
	async def scan_region(self, region_id, server_list):
		popular_bot_maps = []
		casual_total = 0
		bot_total = 0
		server_awaitables = []

		for sv in server_list:
			server_awaitables.append(self.scanServer(sv.server_str, sv.map_name))
		for coroutine in asyncio.as_completed(server_awaitables):
			map_name, total_players, bot_count, server_str = await coroutine
			# Cheap fix
			if map_name is None:
				continue
			popular_bot_maps = self.updateMap(popular_bot_maps, map_name, bot_count, server_str)
			casual_total += total_players
			bot_total += bot_count

		popular_bot_maps.sort(reverse=True)
		scanner_debug(f"Sorted popular_bot_maps for region {region_id}: {popular_bot_maps}")
		scanner_debug(f"Total players seen in region {region_id}: {casual_total}")
		scanner_debug(f"Total bots seen in region {region_id}: {bot_total}")
		tracker = {"region_id": region_id, "popular_bot_maps": popular_bot_maps, "casual_in_game": casual_total, "malicious_in_game": bot_total}
		return tracker


	# GLaDOS scanning thread
	def lucksman(self):
		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		while True:
			# Start a scan
			start = time.time()
			self.start_scan()
			# Save data every 5 minutes
			if time.time() - self.last_save > 60 * 5:
				self.save_data()
				self.last_save = time.time()
			if self.halt:
				self.halted = True
				break
			# Stabilize the scanning frequency
			delay = self.scan_frequency - (time.time() - start)
			if delay > 0:
				delay = round(delay, 2)
				print(f"Sleeping for {delay}s...\n")
				time.sleep(delay)
