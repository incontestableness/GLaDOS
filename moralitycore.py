#!/usr/bin/env python3

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


# Handles active server scanning
class MoralityCore:
	def __init__(self, scan_timeout, workers, suspicious_times_seen, cheater_times_seen):
		# Init
		self.scan_timeout = scan_timeout
		self.workers = workers
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
				match_debug(f"Stripped name \"{stripped}\" matched pattern: {self.unevade(name_pattern.pattern)}")
				# TODO: Create a rule for this variant of the name?
				return name_pattern
		# We didn't match against existing patterns, even when the name is stripped
		# If the name starts with (N), warn about it
		if self.dupematch.match(name):
			match_debug(f"Name \"{self.unevade(name)}\" matched dupe pattern! New bot name or evade char?")
			return self.dupematch
		# Check this name's times_seen
		# If this is a highly recurrent name, blacklist it
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
		else:
			stripped = self.strip_name(name)
			if len(stripped) == 0 or stripped.replace(" ", "") == "":
				return None
			pn = self.bot_names.get(stripped)
			if pn is None:
				return None
			if pn.times_seen >= self.suspicious_times_seen:
				name_debug(f"This name ({self.unevade(name)}), when STRIPPED,  matches a previously seen name ({self.unevade(pn.name)}). Times seen: {pn.times_seen}")
				if pn.times_seen >= self.cheater_times_seen:
					name_debug(f"The aforementioned name will now be blacklisted in stripped form.")
					self.blacklist_name(stripped)
					return None


	# Removes the leading (N) from names
	def undupe(self, name):
		return re.sub(self.dupematch, "", name)


	# Helper function to update or create the PName for the given bot name and return an updated list
	def updatePName(self, name):
		# We can ignore this particular case of bot_names changing size and just not increment the name
		try:
			for i in self.bot_names.values():
				if i.name == name:
					i.increment()
					return
			# PName doesn't exist yet, create it and append to the list
			pn = PName(name)
			self.bot_names[name] = pn
		except RuntimeError:
			print(traceback.format_exc())


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
	def scanServer(self, server_str, map_name):
		ip, port = server_str.split(":")
		server = (ip, int(port))
		try:
			players = a2s.players(server, timeout=self.scan_timeout)
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
					self.updatePName(self.undupe(p.name))
			bot_count += len(self.getNamestealers(players))
			return map_name, total_players, bot_count, server_str
		except socket.timeout:
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
					except:
						pass
				elif self.is_evaded(first_name) and not self.is_evaded(m):
					namesteal_debug(f"{self.unevade(first_name)} stole {self.unevade(m)}'s name!")
					namestealers.add(first_name)
					try:
						to_check.remove(first_name)
					except:
						pass
				elif (not self.is_evaded(first_name)) and (not self.is_evaded(m)):
					print("WARNING: is_evaded() didn't catch the injected chars!")
					print(f"First name: {self.unevade(first_name)}")
					print(f"Second name: {self.unevade(m)}")
					# Throw these in so getnames.py can deal with it
					self.updatePName(self.undupe(first_name))
					self.updatePName(self.undupe(m))
				else:
					inject_debug(f"{self.unevade(first_name)} and {self.unevade(m)} are char injecting")
					namestealers.add(first_name)
					namestealers.add(m)
					self.updatePName(self.strip_name(first_name))
					self.updatePName(self.strip_name(m))
					try:
						to_check.remove(first_name)
					except:
						pass
					try:
						to_check.remove(m)
					except:
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


	# Purpose: Scan TF2 gameservers to determine what maps malicious bots are currently on so that they can be targeted every time bots queue.
	def scan_servers(self):
		all_servers = []
		try:
			response = session.get(f"https://api.steampowered.com/IGameServersService/GetServerList/v1/?key={api_key}&filter=appid\\440\\white\\1&limit=5000")
			all_servers = response.json()["response"]["servers"]
		except (requests.exceptions.ConnectionError, requests.exceptions.SSLError, json.decoder.JSONDecodeError) as ex:
			print(traceback.format_exc())
			if type(ex) == json.decoder.JSONDecodeError:
				print(f"Failed to decode response content:\n{response.content}")
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

		region_map_trackers = []
		for region_id in servers_by_region:
			server_list = servers_by_region[region_id]
			popular_bot_maps = []
			casual_total = 0
			bot_total = 0

			# Multithreading badassness. We can scan all the active TF2 dedicated servers in under 5 seconds.
			executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers)
			future_objs = []
			for sv in server_list:
				future_obj = executor.submit(self.scanServer, sv.server_str, sv.map_name)
				future_objs.append(future_obj)
			for future_obj in concurrent.futures.as_completed(future_objs):
				map_name, total_players, bot_count, server_str = future_obj.result()
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
			region_map_trackers.append(tracker)
		return region_map_trackers


	# GLaDOS scanning thread
	def lucksman(self):
		while True:
			# Start a scan
			start = time.time()
			# Give new, completed data to the API by updating the class object-scoped variable
			self.region_map_trackers = self.scan_servers()
			elapsed = round(time.time() - start, 2)
			print(f"Scans complete (took {elapsed} secs)...\n")
			# Save data every 5 minutes
			if time.time() - self.last_save > 60 * 5:
				self.save_data()
			if self.halt:
				self.halted = True
				break