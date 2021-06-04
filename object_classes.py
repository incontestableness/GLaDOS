#!/usr/bin/env python3

import time



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


# Represents a server given by the API. Quick solution.
class Server:
	def __init__(self, server_str, map_name):
		self.server_str = server_str
		self.map_name = map_name

	def __repr__(self):
		return self.server_str
