#!/usr/bin/env python3

__version__ = "3.2.3"

import argparse
from debug import lc
from flask import abort, Flask, jsonify, redirect, request
from flask_caching import Cache
from helpers import matchify
import json
import logging
from logging.handlers import RotatingFileHandler
from moralitycore import MoralityCore
import netaddr
import os
import re
import socket
import time
from valve_whitelist import cidrs



# GLaDOS modules will not import correctly if you don't do this.
if __name__ == "__main__":
	raise RuntimeError("You need to run ./GLaDOS.wsgi for development.")


# Configuration options
parser = argparse.ArgumentParser()
# You may wish to tune this based on your ping to the servers
parser.add_argument("--scan-timeout", type=float, default=0.500)
# How frequently a scan runs, in seconds. Affects times seen requirements and delay between scans.
parser.add_argument("--scan-frequency", type=float, default=5.0)
args = parser.parse_args()


# Logging setup
logging.basicConfig(
        handlers = [RotatingFileHandler("log.txt", maxBytes=1024 * 1024 * 20, backupCount=2)],
        level = logging.INFO,
        format = "[%(asctime)s] [%(funcName)s:%(lineno)d] %(message)s",
        datefmt = "%a %b %d @ %R:%S")
logger = logging.getLogger()
print = logger.info


# Calculate appropriate times seen requirements based on scanning speed
# Reasonably confident. For a false positive, a single user with a name starting with (N) would have to be in-game for the full course of an hour.
suspicious_times_seen = int((60 * 60) / args.scan_frequency)
# Very high confidence. For a false positive, a single user with a name starting with (N) would have to be in-game for the full course of 3 hours.
cheater_times_seen = int((60 * 60 * 3) / args.scan_frequency)
print(f"Times seen requirements: {suspicious_times_seen} for suspicious, {cheater_times_seen} for cheater")


# Read in region/datacenter mappings
with open("mappings.json") as f:
	mappings = json.load(f)


# Create a GLaDOS core
core = MoralityCore(args.scan_frequency, args.scan_timeout, suspicious_times_seen, cheater_times_seen)


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
# The same goes for logging settings
# The requesting IP must be whitelisted in ip_whitelist.txt
@api.route("/reload")
def reload():
	if not whitelisted():
		abort(403)
	lc.reload_settings()
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
	core.save_data()
	# Crash
	os.abort()


# Return a list of map names to target
@api.route("/popmaps/<region_id>")
@cache.cached(forced_update=whitelisted)
def popmaps(region_id):
	targeted = []
	mapper = mappings["datacenters"]["by_region_id"]
	for datacenter_id in mapper[region_id]:
		try:
			tracker = core.datacenter_map_trackers[datacenter_id]
			for i in tracker["popular_bot_maps"]:
				targeted.append(i.name)
		# Datacenter hasn't been scanned
		except KeyError:
			pass
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
# A timeout of 3 seconds would give more recent data upon multiple calls but 30 would ensure stability. Play it safe for now.
@api.route("/check/<server>")
@cache.cached(timeout=30)
def user_checkServer(server):
	if ":" not in server:
		server = f"{server}:27015"
	ip, port = server.split(":")
	# Is this a Valve IP?
	ip = netaddr.IPAddress(ip)
	if not any(ip in cidr for cidr in cidrs):
		return jsonify({"response": {"success": False, "message": "IP address does not appear to be a Valve IP"}})
	# Is this a reasonable port?
	if int(port) not in range(27015, 27270 + 1):
		return jsonify({"response": {"success": False, "message": "Port not allowed"}})
	try:
		bot_count, namestealers = core.checkServer(server)
	except socket.timeout:
		return jsonify({"response": {"success": False, "message": "Connection timed out"}})
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
	players_per_datacenter = {}
	bots_per_datacenter = {}
	datacenter_mapper = mappings["datacenters"]["by_id"]
	region_mapper = mappings["regions"]["by_id"]
	for datacenter_id in core.datacenter_map_trackers:
		tracker = core.datacenter_map_trackers[datacenter_id]
		casual_total += tracker["casual_in_game"]
		bot_total += tracker["malicious_in_game"]
		region_descriptor = region_mapper[datacenter_mapper[datacenter_id]["region_id"]]["descriptor"]
		# Initialize regions as necessary
		if region_descriptor not in players_per_region:
			players_per_region[region_descriptor] = 0
		if region_descriptor not in bots_per_region:
			bots_per_region[region_descriptor] = 0
		# Accumulate stats
		players_per_region[region_descriptor] += tracker["casual_in_game"]
		bots_per_region[region_descriptor] += tracker["malicious_in_game"]
		# Now do the basic datacenter one
		players_per_datacenter[datacenter_id] = tracker["casual_in_game"]
		bots_per_datacenter[datacenter_id] = tracker["malicious_in_game"]
	return jsonify({"response": {
			"casual_in_game": {
				"totals": {"all_players": casual_total, "malicious_bots": bot_total},
				"per_region": {"all_players": players_per_region, "malicious_bots": bots_per_region},
				"per_datacenter": {"all_players": players_per_datacenter, "malicious_bots": bots_per_datacenter}
			}
		}
	})


@api.route("/info")
def info():
	return jsonify({"response": {"info": {"api_version": __version__}}})


@api.route("/debug")
def debug():
	if not whitelisted():
		abort(403)
	patterns = [pat.pattern for pat in core.patterns]
	return jsonify({"response": {"debug": {"patterns": patterns}}})


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
		if pn.times_seen >= cheater_times_seen:
			bnames.append(pn)
		elif pn.times_seen >= suspicious_times_seen:
			snames.append(pn)
	data = {"$schema": "https://raw.githubusercontent.com/PazerOP/tf2_bot_detector/master/schemas/v3/rules.schema.json"}
	data["file_info"] = {
		"authors": ["Sydney", "The Great Milenko"],
		"title": "Vibe check",
		"description": "GLaDOS automatic bot name detection rules list",
		"update_url": "https://milenko.ml/api/namerules"
	}
	rules = []
	dup_prefix_regex = "(\\([1-9]\\d?\\))?"
	for pn in bnames:
		rule = {"actions": {"transient_mark": ["cheater"]}}
		patterns = [f"{dup_prefix_regex}{matchify(pn.name)}"]
		for variant in pn.variants:
			patterns.append(f"{dup_prefix_regex}{matchify(variant)}")
		rule["description"] = f"\"{pn.name}\" seen {pn.times_seen} times in 24h"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": patterns
			}
		}
		rules.append(rule)
	for pn in snames:
		rule = {"actions": {"transient_mark": ["suspicious"]}}
		patterns = [f"{dup_prefix_regex}{matchify(pn.name)}"]
		for variant in pn.variants:
			patterns.append(f"{dup_prefix_regex}{matchify(variant)}")
		rule["description"] = f"\"{pn.name}\" seen {pn.times_seen} times in 24h"
		rule["triggers"] = {
			"username_text_match": {
				"case_sensitive": True,
				"mode": "regex",
				"patterns": patterns
			}
		}
		rules.append(rule)
	data["rules"] = rules
	response = jsonify(data)
	response.headers["Content-Disposition"] = "inline; filename=rules.GLaDOS.json"
	return response
