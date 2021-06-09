#!/usr/bin/env python3

import a2s
import argparse
import concurrent.futures
from flask import abort, Flask, jsonify, redirect, request
from flask_caching import Cache
import json
import logging
from logging.handlers import RotatingFileHandler
from object_classes import TFMap, PName, Server
import os
import pickle
import re
import requests
import socket
from string import ascii_letters, digits, punctuation
import sys
import threading
import time
import traceback



# For running as a WSGI application, as it should be in production
if __name__ != "__main__":
	os.chdir(os.path.expanduser("~/GLaDOS"))


# Debugging options
parser = argparse.ArgumentParser()
parser.add_argument("--scanner-debug", action="store_true")
parser.add_argument("--server-debug", action="store_true")
parser.add_argument("--timeout-debug", action="store_true")
parser.add_argument("--match-debug", action="store_true")
parser.add_argument("--name-debug", action="store_true", default=True)
parser.add_argument("--namesteal-debug", action="store_true")
parser.add_argument("--inject-debug", action="store_true")
# You may wish to tune this based on your ping to the servers
parser.add_argument("--scan-timeout", type=float, default=0.500)
parser.add_argument("--workers", type=int, default=1024)
parser.add_argument("--suspicious-times-seen", type=int, default=720)
parser.add_argument("--cheater-times-seen", type=int, default=2160)
args = parser.parse_args()


# API setup
with open("api-key.txt") as file:
	api_key = file.read().strip()

session = requests.Session()
session.headers.update({"user-agent": "GLaDOS.py/3.0 (https://github.com/incontestableness/GLaDOS)"})


# Logging setup
logging.basicConfig(
        handlers = [RotatingFileHandler("log.txt", maxBytes=1024 * 1024 * 20, backupCount=2)],
        level = logging.INFO,
        format = "[%(asctime)s] [%(funcName)s:%(lineno)d] %(message)s",
        datefmt = "%a %b %d @ %R:%S")
logger = logging.getLogger()
print = logger.info


def scanner_debug(what):
	if args.scanner_debug:
		print(what)


def server_debug(what):
	if args.server_debug:
		print(what)


def timeout_debug(what):
	if args.timeout_debug:
		print(what)


def match_debug(what):
	if args.match_debug:
		print(what)


def name_debug(what):
	if args.name_debug:
		print(what)


def namesteal_debug(what):
	if args.namesteal_debug:
		print(what)


def inject_debug(what):
	if args.inject_debug:
		print(what)


# Read in regions.json for nicer stats output
file = open("regions.json", "r")
data = file.read()
file.close()
regions_data = json.loads(data)


# Handles active server scanning
class MoralityCore:
	def __init__(self):
		# We need to load these the first time
		self.load_blacklists()

		# Stops scanning when set to True
		self.halt = False

		# Signals the restart endpoint that it's okay to proceed
		self.halted = False

		# Run server scans in another thread
		# This thread just repopulates the class object's data on bot maps,
		# so it's okay to terminate it with the main thread
		snoipin = threading.Thread(target=self.lucksman, args=(), daemon=True)
		snoipin.start()

		# No need to create these every time they're needed
		self.dupematch = re.compile("^(\([1-9]\d?\))")
		self.allowed_chars = ascii_letters + digits + punctuation + " "

		# Keeps track of potential bot names
		self.bot_names = {}

		# API data
		self.region_map_trackers = []

		# Load saved data where possible
		for vname in ["bot_names", "region_map_trackers"]:
			try:
				file = open(f"{vname}.pkl", "rb")
				exec(f"self.{vname} = pickle.load(file)")
				file.close()
				print(f"Successfully loaded pickled data for self.{vname}")
			except FileNotFoundError:
				print(f"Failed to load pickled data for self.{vname}")

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
			if pn.times_seen >= args.suspicious_times_seen:
				# This name wasn't caught by the dupematch but it's suspicious and we're still seeing it.
				# Since it won't be incremented as a result of matching the dupematch we have to do it ourselves here.
				pn.increment()
				name_debug(f"Saw a recurring name ({self.unevade(name)}) not yet blacklisted. Times seen: {pn.times_seen}")
				if pn.times_seen >= args.cheater_times_seen:
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
			if pn.times_seen >= args.suspicious_times_seen:
				name_debug(f"This name ({self.unevade(name)}), when STRIPPED,  matches a previously seen name ({self.unevade(pn.name)}). Times seen: {pn.times_seen}")
				if pn.times_seen >= args.cheater_times_seen:
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
			players = a2s.players(server, timeout=args.scan_timeout)
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
			timeout_debug(f"Server {server_str} timed out after {args.scan_timeout} seconds...")
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
		players = a2s.players(server, timeout=args.scan_timeout)
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
			executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
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
			if self.halt:
				self.halted = True
				break


# Create a GLaDOS core
core = MoralityCore()


# Declare our Flask instance and define all the API routes
api = Flask(__name__)
config = {
	"JSON_SORT_KEYS": False,
	"CACHE_TYPE": "SimpleCache", # Flask-Caching
	"CACHE_DEFAULT_TIMEOUT": 5
}
api.config.from_mapping(config)
cache = Cache(api)


def whitelisted():
	with open("ip_whitelist.txt", "r") as wl:
		whitelist = wl.read().split("\n")[:-1]
		return request.remote_addr in whitelist


# Redirect to static content about the API
@api.route("/")
@cache.cached(timeout=60 * 60)
def root():
	return redirect(location="/api.html")


# We can load an updated regex name blacklist on demand without restarting
# The requesting IP must be whitelisted in ip_whitelist.txt
@api.route("/reload")
def reload():
	if not whitelisted():
		abort(403)
	core.load_blacklists()
	return jsonify({"response": {"success": True}})


# Save current data and terminate the backend.
# Useful for using new code without re-collecting data.
@api.route("/restart")
def restart():
	if not whitelisted():
		abort(403)
	# Ask the core to stop doing stuff
	core.halt = True
	# Wait
	while not core.halted:
		time.sleep(0.100)
	# Save stuff
	for vname in ["bot_names", "region_map_trackers"]:
		file = open(f"{vname}.pkl", "wb")
		exec(f"pickle.dump(core.{vname}, file)")
		file.close()
	# Crash
	os.abort()


# Return a list of map names to target
@api.route("/popmaps/<desired_region>")
@cache.cached(forced_update=whitelisted)
def popmaps(desired_region):
	targeted = []
	for tracker in core.region_map_trackers:
		if str(tracker["region_id"]) != desired_region:
			continue
		for i in tracker["popular_bot_maps"]:
			targeted.append(i.name)
	return jsonify({"response": {"popular_bot_maps": targeted}})


# Return a list of bot names we have seen while scanning
# The counter accumulates, which makes it useful for measuring "presence" over time
# A bot will have a higher score at the end of the measurement period
@api.route("/botnames")
@cache.cached(forced_update=whitelisted)
def botnames():
	bot_names = []
	now = time.time()
	for pn in sorted(core.bot_names.values(), reverse=True):
		# Ignore names older than 24h
		if now - pn.last_seen >= 60 * 60 * 24:
			continue
		json_quote_escaped = pn.name.replace("\"", "\\\"")
		bot_names.append({
			"name": json_quote_escaped,
			"properties": {
				"times_seen": pn.times_seen,
				"first_seen": f"{int((now - pn.first_seen) / 60)} minutes ago",
				"last_seen": f"{int((now - pn.last_seen) / 60)} minutes ago"
			}
		})
	return jsonify({"response": {"bot_names": bot_names}})


# "I know you're there. I can feel you here."
# Hathook users and bots can automatically accept/reject assigned matches depending on whether they have bots, before joining them
# portalgun will convert the namestealers list into a format hathook can process safely
# Namestealing bots will be marked as soon as users/bots join the match
# TODO: Make sure the IP given is within Valve's server ranges
# A timeout of 3 seconds would give more recent data upon multiple calls but 30 would ensure stability. Play it safe for now.
@api.route("/check/<server>")
@cache.cached(timeout=30)
def user_checkServer(server):
	try:
		bot_count, namestealers = core.checkServer(server)
	except socket.timeout:
		return jsonify({"response": {"success": False}})
	return jsonify({"response": {"success": True, "server": server, "bot_count": bot_count, "namestealers": namestealers}})


# TODO: Statistics events
@api.route("/event/exampleEvent/<data>")
def exampleEventHandler(data):
	if not whitelisted:
		abort(403)
	return jsonify({})


# TODO: Cumulative statistics from bot events
@api.route("/stats")
@cache.cached(forced_update=whitelisted)
def stats():
	casual_total = 0
	bot_total = 0
	players_per_region = {}
	bots_per_region = {}
	for tracker in core.region_map_trackers:
		region_simple_name = regions_data[f"Region ID {tracker['region_id']}"]["simple_name"]
		casual_total += tracker["casual_in_game"]
		bot_total += tracker["malicious_in_game"]
		players_per_region[region_simple_name] = tracker["casual_in_game"]
		bots_per_region[region_simple_name] = tracker["malicious_in_game"]
	return jsonify({"response": {
			"casual_in_game": {
				"totals": {"all_players": casual_total, "malicious_bots": bot_total},
				"per_region": {"all_players": players_per_region, "malicious_bots": bots_per_region}
			}
		}
	})


# "You picked the wrong house, fool!"
# Automatic TF2BD rules list creation based on current common bot names
@api.route("/namerules")
@cache.cached(forced_update=whitelisted)
def namerules():
	bnames = []
	snames = []
	for pn in sorted(core.bot_names.values(), reverse=True):
		# Ignore names older than 24h
		if time.time() - pn.last_seen >= 60 * 60 * 24:
			continue
		# Scans run about every 5 seconds. This is taken into account.
		# Very high confidence. For a false positive, a single user with a name starting with (N) would have to be in-game for the full course of 3 hours.
		if pn.times_seen >= args.cheater_times_seen:
			bnames.append(pn)
		# Reasonably confident. For a false positive, a single user with a name starting with (N) would have to be in-game for the full course of an hour.
		elif pn.times_seen >= args.suspicious_times_seen:
			snames.append(pn)
	data = {"$schema": "https://raw.githubusercontent.com/PazerOP/tf2_bot_detector/master/schemas/v3/rules.schema.json"}
	data["file_info"] = {
		"authors": ["Sydney", "The Great Milenko"],
		"title": "Vibe check",
		"description": "GLaDOS automatic bot name detection rules list",
		"update_url": "https://milenko.ml/api/namerules"
	}
	rules = []
	for pn in bnames:
		rule = {"actions": {"transient_mark": ["cheater"]}}
		json_quote_escaped = pn.name.replace("\"", "\\\"")
		name_re_json_escaped = re.escape(pn.name).replace("\"", "\\\"")
		rule["description"] = f"\"{json_quote_escaped}\" seen {pn.times_seen} times in 24h"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": [f"(\([1-9]\d?\))?{name_re_json_escaped}"]
			}
		}
		rules.append(rule)
	for pn in snames:
		rule = {"actions": {"transient_mark": ["suspicious"]}}
		json_quote_escaped = pn.name.replace("\"", "\\\"")
		name_re_json_escaped = re.escape(pn.name).replace("\"", "\\\"")
		rule["description"] = f"\"{json_quote_escaped}\" seen {pn.times_seen} times in 24h"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": [f"(\([1-9]\d?\))?{name_re_json_escaped}"]
			}
		}
		rules.append(rule)
	data["rules"] = rules
	response = jsonify(data)
	response.headers["Content-Disposition"] = "inline; filename=rules.GLaDOS.json"
	return response


# Run the GLaDOS API server in the main thread, if running directly for development/testing and not as a WSGI application
if __name__ == "__main__":
	api.run(port=8000)
