#!/usr/bin/env python3

# Quick script to print bot names from the API in various formats

import argparse
import re
import requests



parser = argparse.ArgumentParser()
parser.add_argument("-q", "--no-count", action="store_true")
parser.add_argument("-s", "--sort-by-count", action="store_true")
parser.add_argument("-m", "--minimum-count", type=int, default=0)
parser.add_argument("-p", "--print", action="store_true")
parser.add_argument("-l", "--live", action="store_true")
args = parser.parse_args()


botnames = []
response = requests.get("http://milenko.ml/api/botnames")
for i in response.json()["response"]["bot_names"]:
	unicode_escaped = i["name"].encode("unicode-escape").decode()
	re_escaped = re.escape(unicode_escaped)
	fixed = re_escaped.replace("\\\\", "\\")
	fixed = fixed.replace("\\ ", " ")
	botnames.append([fixed, i["properties"]["times_seen"], i["properties"]["last_seen"] == "0 minutes ago"])

if args.sort_by_count:
	botnames = sorted(botnames, key = lambda x: x[1])
else:
	botnames.sort()
for name, count, live in botnames:
	if args.live and not live:
		continue
	if count < args.minimum_count:
		continue
	if args.no_count:
		print(name)
	elif args.print:
		decoded = name.encode().decode("unicode-escape")
		spacing = " " * ((160 - len(name)) - len(decoded))
		print(f"{name}{spacing}{decoded}")
	else:
		print(name.ljust(80), count)
