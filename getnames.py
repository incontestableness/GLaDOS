#!/usr/bin/env python3

# Quick script to print bot names from the API in name_blacklist.txt format

import argparse
import re
import requests



parser = argparse.ArgumentParser()
parser.add_argument("--no-count", action="store_true")
args = parser.parse_args()


botnames = []
response = requests.get("http://milenko.ml/api/botnames")
for i in response.json()["response"]["bot_names"]:
	botnames.append([re.escape(i["name"]).replace("\\ ", " ").encode("unicode-escape").decode(), i["properties"]["times_seen"]])

botnames.sort()
for name, count in botnames:
	if args.no_count:
		print(name)
	else:
		print(name.ljust(160), count)
