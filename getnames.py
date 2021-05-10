#!/usr/bin/env python3

# Quick script to print bot names from the API in name_blacklist.txt format

import re
import requests



names = []
response = requests.get("http://milenko.ml/api/botnames")
for i in response.json()["response"]["bot_names"]:
	names.append([re.escape(i["name"]).encode("unicode-escape").decode(), i["properties"]["times_seen"]])
names.sort()
for i in names:
	if i[1] > 10:
		print(i[0])
