#!/usr/bin/env python3

import a2s
import argparse
import concurrent.futures
from flask import abort, Flask, jsonify, request
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import os
import re
import socket
import threading
import time



# For running as a WSGI application, as it should be in production
if __name__ != "__main__":
	os.chdir(os.path.expanduser("~/GLaDOS"))


parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()


def debug(what):
	if args.debug: print(what)


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
		# We need to load this the first time
		self.load_blacklist()

		# Run server scans in another thread
		# This thread just repopulates the class object's data on bot maps,
		# so it's okay to terminate it with the main thread
		snoipin = threading.Thread(target=self.lucksman, args=(), daemon=True)
		snoipin.start()

		self.dupmatch = re.compile("^\(\d+\)")

		# Make a list of bot names publicly available for TF2BD rules list creators to use
		self.bot_names = set()

	def load_blacklist(self):
		self.patterns = []
		with open("name_blacklist.txt") as bl:
			data = bl.read()
			name_blacklist = data.split("\n")[:-1]
			for pattern in name_blacklist:
				# https://docs.python.org/3/library/re.html#re.ASCII
				compiled = re.compile(pattern, flags=re.ASCII)
				self.patterns.append(compiled)
		print("Blacklist loaded!")

	# Returns the first pattern that matches the name, if any
	def check_name(self, name):
		for pattern in self.patterns:
			if pattern.fullmatch(name):
				print(f"Name \"{name}\" matched pattern: {pattern.pattern}")
				return pattern
		return None

	# Removes the leading (N) from names
	def undupe(self, name):
		return re.sub(self.dupmatch, "", name)

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
			server_info = a2s.info(server)
			if server_info.max_players == 6:
				debug(f"Ignoring MVM server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None
			elif server_info.max_players == 12:
				debug(f"Ignoring competitive server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None
			elif server_info.player_count == 0:
				debug(f"Ignoring empty casual server: {server_info.map_name} \t// {server_info.keywords}")
				return None, None, None

			players = a2s.players(server)
			bot_count = 0
			for p in players:
				if self.check_name(p.name):
					# This can run multiple times, increasing map "score" by bot count, unless we break out of the loop.
					# Currently we allow it to do so.
					bot_count += 1
					self.bot_names = self.updatePName(self.bot_names, self.undupe(p.name))
			return server_info.map_name, bot_count, server_str
		except socket.timeout:
			debug(f"Server {server_str} timed out after {a2s.defaults.DEFAULT_TIMEOUT} seconds...")
			return None, None, None

	# TODO: Returns a list of player names that are likely spoofing as another player
	def getNamestealers(self, players):
		return []

	# This function is called when a user or bot is assigned a match server
	# In addition to checking regex patterns, it also looks for namestealers
	def checkServer(self, server):
		ip, port = server.split(":")
		server = (ip, int(port))
		players = a2s.players(server)
		bot_count = 0
		for p in players:
			if self.check_name(p.name):
				bot_count += 1
		namestealers = self.getNamestealers(players)
		return bot_count, namestealers

	# Purpose: Scan TF2 gameservers from cached lists to determine what maps malicious bots are currently on so that they can be targeted every time bots queue.
	# TODO: This function does NOT handle namesteal detection yet.
	def scan_servers(self):
		contents = os.listdir()
		region_map_trackers = []
		for filename in contents:
			if filename.endswith(".tf_list"):
				shortname = filename.split(".tf_list")[0]

				tf_list = open(filename, "r")
				data = tf_list.read()
				tf_list.close()
				server_list = data.split("\n")[:-1]

				print(f"Scanning {shortname}...")
				popular_bot_maps = []
				total = 0
				# Multithreading badassness. It takes about a minute to scan all the active TF2 dedicated servers.
				executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
				future_objs = []
				for server_str in server_list:
					future_obj = executor.submit(self.scanServer, server_str)
					future_objs.append(future_obj)
				for future_obj in concurrent.futures.as_completed(future_objs):
					map_name, bot_count, server_str = future_obj.result()
					# Cheap fix
					if map_name is None:
						continue
					popular_bot_maps = self.updateMap(popular_bot_maps, map_name, bot_count, server_str)
					total += bot_count
				popular_bot_maps.sort(reverse=True)
				print(f"Sorted popular_bot_maps for {shortname}: {popular_bot_maps}")
				print(f"Total bots seen in {shortname}: {total}")
				tracker = {"shortname": shortname, "popular_bot_maps": popular_bot_maps}
				region_map_trackers.append(tracker)
		return region_map_trackers

	# GLaDOS scanning thread
	def lucksman(self):
		while True:
			# Start a scan
			print("Lucksman starting scans...")
			start = time.time()
			# Give new, completed data to the API by updating the class object-scoped variable
			self.region_map_trackers = self.scan_servers()
			elapsed = round(time.time() - start, 2)
			print(f"Scans complete (took {elapsed} secs), sleeping...")
			# Wait a minute between scans
			time.sleep(60)


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
limiter = Limiter(
	api,
	key_func=get_remote_address,
)
cache = Cache(api)


whitelist = []
with open("ip_whitelist.txt", "r") as wl:
	whitelist = wl.read().split("\n")[:-1]


def whitelisted():
	return request.remote_addr in whitelist


# We can load an updated regex name blacklist on demand without restarting
# The requesting IP must be whitelisted in ip_whitelist.txt
@api.route("/reload")
def reload():
	if not whitelisted():
		abort(403)
	core.load_blacklist()
	core.bot_names = set()
	return jsonify({"response": {"success": True}})


# Return a list of map names to target
@api.route("/popmaps/<desired_region>")
@cache.cached(forced_update=whitelisted)
@limiter.limit("10/minute")
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
# A bot will have a higher score at the end of the day
# TODO: Should we reset the counter every N scans?
@api.route("/botnames")
@cache.cached(forced_update=whitelisted)
@limiter.limit("10/minute")
def botnames():
	bot_names = []
	for i in core.bot_names:
		bot_names.append({i.name: {"times_seen": i.times_seen}})
	return jsonify({"response": {"bot_names": bot_names}})


# "I know you're there. I can feel you here."
# Hathook users and bots can automatically accept/reject assigned matches depending on whether they have bots, before joining them
# portalgun will convert the namestealers list into a format hathook can process safely
# Namestealing bots will be marked as soon as users/bots join the match
# TODO: Make sure the IP given is within Valve's server ranges
@api.route("/check/<server>")
@cache.cached()
@limiter.limit("20/minute")
def user_checkServer(server):
	bot_count, namestealers = core.checkServer(server)
	return jsonify({"response": {"server": server, "bot_count": bot_count, "namestealers": namestealers}})


# TODO: Statistics events
@api.route("/event/exampleEvent/<data>")
def exampleEventHandler(data):
	abort(503)
	return jsonify({})


# TODO: Cumulative statistics from bot events
# Statistics will be cached for 60 seconds, compared to other calls which are by default 10
@api.route("/stats")
@cache.cached(forced_update=whitelisted, timeout=60)
@limiter.limit("10/minute")
def stats():
	abort(503)
	return jsonify({})


# "You picked the wrong house, fool!"
# Automatic TF2BD rules list creation based on current common bot names
# Cached for five minutes
@api.route("/namerules")
@cache.cached(forced_update=whitelisted, timeout=60 * 5)
@limiter.limit("10/minute")
def namerules():
	pnames = []
	for pn in core.bot_names:
		# Ignore names older than 24h
		if time.time() - pn.last_seen >= 60 * 60 * 24:
			continue
		# High confidence
		if pn.times_seen >= 100:
			pnames.append(pn)
	data = {"$schema": "https://raw.githubusercontent.com/PazerOP/tf2_bot_detector/master/schemas/v3/rules.schema.json"}
	data["file_info"] = {
		"authors": ["Sydney"],
		"title": "Vibe check",
		"description": "GLaDOS automatic bot name detection rules list",
		"update_url": "http://milenko.ml/api/namerules"
	}
	rules = []
	for pn in pnames:
		rule = {"actions": {"transient_mark": ["cheater"]}}
		rule["description"] = f"\"{pn.name}\" seen {pn.times_seen} times in 24h"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": [f"\([1-9]\d?\)?{re.escape(pn.name)}"]
			}
		}
		rules.append(rule)
	data["rules"] = rules
	return jsonify(data)


# Run the GLaDOS API server in the main thread, if running directly for development/testing and not as a WSGI application
if __name__ == "__main__":
	api.run(port=8000)
