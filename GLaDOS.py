#!/usr/bin/env python3

import a2s
import argparse
import concurrent.futures
from flask import abort, Flask, jsonify, redirect, request
from flask_caching import Cache
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import pickle
import re
import socket
from string import ascii_letters, digits, punctuation
import threading
import time



# For running as a WSGI application, as it should be in production
if __name__ != "__main__":
	os.chdir(os.path.expanduser("~/GLaDOS"))


parser = argparse.ArgumentParser()
parser.add_argument("--scanner-debug", action="store_true")
parser.add_argument("--server-debug", action="store_true")
parser.add_argument("--timeout-debug", action="store_true")
parser.add_argument("--name-debug", action="store_true")
parser.add_argument("--namesteal-debug", action="store_true")
# You may wish to tune this based on your ping to the servers
# cat *.tf_list | grep "[0-9.]*:" -o | sort -u | grep "[0-9.]*" -o | xargs -n 1 ping -c 1 -n -w 1 | grep time=
parser.add_argument("--scan-timeout", type=float, default=0.500)
parser.add_argument("--workers", type=int, default=1024)
args = parser.parse_args()


logging.basicConfig(
        handlers = [RotatingFileHandler("log.txt", maxBytes=1024 * 1024, backupCount=5)],
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


def name_debug(what):
	if args.name_debug:
		print(what)


def namesteal_debug(what):
	if args.namesteal_debug:
		print(what)


# Represents a map and the number of malicious bots that have been seen on it in the last scan
# Also keeps a list of the servers bots were seen on
class TFMap:
	def __init__(self, name, bot_count, first_server):
		self.name = name
		self.bot_count = bot_count
		self.servers = {first_server}

	def __lt__(self, other):
		return self.bot_count < other.bot_count

	def __repr__(self):
		return f"{self.name}: {self.bot_count} bots across {len(self.servers)} servers: {self.servers}"


# Track common dupnames that are likely bot names
class PName:
	def __init__(self, name):
		self.name = name
		self.times_seen = 1
		self.first_seen = time.time()
		self.last_seen = self.first_seen

	def __lt__(self, other):
		return self.times_seen < other.times_seen

	def increment(self):
		now = time.time()
		# If we're seeing this bot again but it's been over 24h, reset the counter
		if now - self.first_seen >= 60 * 60 * 24:
			self.times_seen = 0
			self.first_seen = now
		self.times_seen += 1
		self.last_seen = now


# Handles active server scanning
class MoralityCore:
	def __init__(self):
		# We need to load these the first time
		self.load_blacklists()
		self.loadTFLs()

		# Stops scanning when set to True
		self.halt = False

		# Signals the restart endpoint that it's okay to proceed
		self.halted = False

		# Run server scans in another thread
		# This thread just repopulates the class object's data on bot maps,
		# so it's okay to terminate it with the main thread
		snoipin = threading.Thread(target=self.lucksman, args=(), daemon=True)
		snoipin.start()

		self.dupematch = re.compile("^(\([1-9]\d?\))")

		# Make a list of bot names publicly available for TF2BD rules list creators to use
		self.bot_names = set()

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
		self.patterns = []
		self.evasion_sequences = []
		with open("name_blacklist.txt", "r") as bl:
			data = bl.read()
			name_blacklist = data.split("\n")[:-1]
			for pattern in name_blacklist:
				# Trust me, this entire line is necessary
				pattern = pattern.encode().decode("unicode-escape").encode("UTF-8").decode()
				# Add the prefix
				pattern = "^(\([1-9]\d?\))?" + pattern
				# https://docs.python.org/3/library/re.html#re.ASCII
				compiled = re.compile(pattern, flags=re.ASCII)
				self.patterns.append(compiled)
		print("Name pattern blacklist loaded!")
		with open("evade_blacklist.txt", "r") as bl:
			data = bl.read()
			evade_blacklist = data.split("\n")[:-1]
			for pattern in evade_blacklist:
				compiled = re.compile(pattern)
				self.evasion_sequences.append(compiled)
		print("Evasion sequences loaded!")

	# Returns the first pattern that matches the name, if any
	def check_name(self, name):
		for pattern in self.patterns:
			if pattern.fullmatch(name):
				name_debug(f"Name \"{name}\" matched pattern: {pattern.pattern}")
				return pattern
		if self.dupematch.match(name):
			print(f"Name \"{name}\" matched dupe pattern!")
			return self.dupematch
		return None

	# Removes the leading (N) from names
	def undupe(self, name):
		return re.sub(self.dupematch, "", name)

	# Helper function to update or create the PName for the given bot name and return an updated list
	def updatePName(self, bot_names, name):
		for i in bot_names:
			if i.name == name:
				i.increment()
				return bot_names
		# PName doesn't exist yet, create it and append to the list
		pn = PName(name)
		bot_names.add(pn)
		return bot_names

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
	def scanServer(self, server_str):
		ip, port = server_str.split(":")
		server = (ip, int(port))
		try:
			server_info = a2s.info(server, timeout=args.scan_timeout)
			if server_info.max_players == 6:
				server_debug(f"Ignoring MVM server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None, None
			elif server_info.max_players == 12:
				server_debug(f"Ignoring competitive server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None, None
			elif server_info.player_count == 0:
				server_debug(f"Ignoring empty casual server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None, None

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
					self.bot_names = self.updatePName(self.bot_names, self.undupe(p.name))
			bot_count += len(self.getNamestealers(players))
			return server_info.map_name, total_players, bot_count, server_str
		except socket.timeout:
			timeout_debug(f"Server {server_str} timed out after {args.scan_timeout} seconds...")
			return None, None, None, None
		except a2s.exceptions.BrokenMessageError:
			print(f"Server {server_str} sent a bad response...")
			return None, None, None, None

	# Returns an ASCII-only string
	def strip_name(self, name):
		allowed = ascii_letters + digits + punctuation + " "
		return "".join(filter(lambda x: x in allowed, name))

	# Returns true if the name has evading character sequences in it
	def evaded(self, name):
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
			# If the name is empty after stripping non-ascii characters, skip it
			if len(fs) == 0 or fs == " ":
				continue
			matches = []
			for second_name in to_check:
				ss = self.strip_name(second_name)
				if len(ss) == 0 or ss == " ":
					continue
				if fs == ss:
					matches.append(second_name)
			for m in matches:
				if self.evaded(m) and not self.evaded(first_name):
					namesteal_debug(f"{self.unevade(m)} stole {self.unevade(first_name)}'s name!")
					namestealers.add(m)
					try:
						to_check.remove(m)
					except:
						pass
				elif self.evaded(first_name) and not self.evaded(m):
					namesteal_debug(f"{self.unevade(first_name)} stole {self.unevade(m)}'s name!")
					namestealers.add(first_name)
					try:
						to_check.remove(first_name)
					except:
						pass
				elif (not self.evaded(first_name)) and (not self.evaded(m)):
					print("WARNING: evaded() didn't catch the injected chars!")
					print(f"First name: {self.unevade(first_name)}")
					print(f"Second name: {self.unevade(m)}")
					# Throw these in so getnames.py can deal with it
					self.botnames = self.updatePName(self.bot_names, self.undupe(first_name))
					self.botnames = self.updatePName(self.bot_names, self.undupe(first_name))
				else:
					namesteal_debug(f"{self.unevade(first_name)} and {self.unevade(m)} are char injecting")
					namestealers.add(first_name)
					namestealers.add(m)
					try:
						to_check.remove(first_name)
					except:
						pass
					try:
						to_check.remove(m)
					except:
						pass
		if len(namestealers) > 0:
			namesteal_debug(f"{len(namestealers)} namestealers: {namestealers}")
		return namestealers

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

	# Loads cached TF2 server lists into the core
	def loadTFLs(self):
		tfls = []
		contents = os.listdir()
		for filename in contents:
			if filename.endswith(".tf_list"):
				shortname = filename.split(".tf_list")[0]
				tf_list = open(filename, "r")
				data = tf_list.read()
				tf_list.close()
				server_list = data.split("\n")[:-1]
				tfls.append({"shortname": shortname, "server_list": server_list})
		self.tfls = tfls
		self.last_tfl_load = time.time()
		print("Loaded TF lists!")

	# Purpose: Scan TF2 gameservers from cached lists to determine what maps malicious bots are currently on so that they can be targeted every time bots queue.
	def scan_servers(self):
		region_map_trackers = []
		for region in self.tfls:
			shortname = region["shortname"]
			server_list = region["server_list"]
			scanner_debug(f"Scanning {shortname}...")
			popular_bot_maps = []
			casual_total = 0
			bot_total = 0
			# Multithreading badassness. We can scan all the active TF2 dedicated servers in 10 seconds flat.
			executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
			future_objs = []
			for server_str in server_list:
				future_obj = executor.submit(self.scanServer, server_str)
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
			scanner_debug(f"Sorted popular_bot_maps for {shortname}: {popular_bot_maps}")
			scanner_debug(f"Total players seen in {shortname}: {casual_total}")
			scanner_debug(f"Total bots seen in {shortname}: {bot_total}")
			tracker = {"shortname": shortname, "popular_bot_maps": popular_bot_maps, "casual_in_game": casual_total, "malicious_in_game": bot_total}
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
			print(f"Scans complete (took {elapsed} secs)...")
			# Reload lists hourly
			if time.time() - self.last_tfl_load > 60 * 60:
				self.loadTFLs()
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
	"CACHE_DEFAULT_TIMEOUT": 10
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
	for region in core.region_map_trackers:
		if region["shortname"] != desired_region:
			continue
		for i in region["popular_bot_maps"]:
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
	for pn in sorted(core.bot_names, reverse=True):
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
	bot_count, namestealers = core.checkServer(server)
	return jsonify({"response": {"server": server, "bot_count": bot_count, "namestealers": namestealers}})


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
	players_per_region = []
	bots_per_region = []
	for region in core.region_map_trackers:
		casual_total += region["casual_in_game"]
		bot_total += region["malicious_in_game"]
		players_per_region.append({region["shortname"]: region["casual_in_game"]})
		bots_per_region.append({region["shortname"]: region["malicious_in_game"]})
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
	cpats = set()
	bnames = []
	snames = []
	for pn in sorted(core.bot_names, reverse=True):
		# Pop names off. If they match a blacklist pattern, use that pattern as the rule. Make rules for the rest.
		pat = core.check_name(pn.name)
		if pat is not None:
			if pat != core.dupematch:
				cpats.add(pat)
				continue
			else: print("wow dupematch")
		# Ignore names older than 24h
		if time.time() - pn.last_seen >= 60 * 60 * 24:
			continue
		# Scans run every 10 seconds. This is taken into account.
		# Very high confidence. At a minimum, a single user with a name starting with (N) over the full course of almost 3 hours.
		if pn.times_seen >= 1000:
			bnames.append(pn)
		# Reasonably confident. At a minimum, a single user with a name starting with (N) over the full course of an hour.
		elif pn.times_seen >= 360:
			snames.append(pn)
	data = {"$schema": "https://raw.githubusercontent.com/PazerOP/tf2_bot_detector/master/schemas/v3/rules.schema.json"}
	data["file_info"] = {
		"authors": ["Sydney", "The Great Milenko"],
		"title": "Vibe check",
		"description": "GLaDOS automatic bot name detection rules list",
		"update_url": "http://milenko.ml/api/namerules"
	}
	rules = []
	for pat in cpats:
		rule = {"actions": {"transient_mark": ["cheater"]}}
		# Add 1 because core.dupematch doesn't have a trailing "?"
		short = pat.pattern[len(core.dupematch.pattern) + 1:]
		short = short.replace("\"", "\\\"")
		rule["description"] = f"Confirmed pattern: {short}"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": [f"{pat.pattern}"]
			}
		}
		rules.append(rule)
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
