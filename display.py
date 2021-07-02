#!/usr/bin/env python3

# Parses the GLaDOS namerules and displays the patterns as they should be read by a human.

import pprint
import requests



response = requests.get("https://milenko.ml/api/namerules")
vibecheck = response.json()

for rule in vibecheck["rules"]:
	for pattern in rule["triggers"]["username_text_match"]["patterns"]:
		print(pattern)
