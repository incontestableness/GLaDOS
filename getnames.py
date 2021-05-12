#!/usr/bin/env python3

# Quick script to print bot names from the API in name_blacklist.txt format

import argparse
import re
import requests



parser = argparse.ArgumentParser()
parser.add_argument("-q", "--no-count", action="store_true")
parser.add_argument("-s", "--sort-by-count", action="store_true")
parser.add_argument("-m", "--minimum-count", type=int, default=0)
args = parser.parse_args()


botnames = []
response = requests.get("http://milenko.ml/api/botnames")
for i in response.json()["response"]["bot_names"]:
	unicode_escaped = i["name"].encode("unicode-escape").decode()
	re_escaped = re.escape(unicode_escaped)
	fixed = re_escaped.replace("\\\\", "\\")
	fixed = fixed.replace("\\ ", " ")
	botnames.append([fixed, i["properties"]["times_seen"]])

if args.sort_by_count:
	botnames = sorted(botnames, key = lambda x: x[1])
else:
	botnames.sort()
for name, count in botnames:
	if count < args.minimum_count:
		continue
	if args.no_count:
		print(name)
	else:
		print(name.ljust(160), count)
