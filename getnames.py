#!/usr/bin/env python3

# Quick script to print bot names from the API in various formats

import argparse
import copy
import re
import requests



parser = argparse.ArgumentParser()
parser.add_argument("-q", "--quiet", action="store_true", help="Don't print the number of times seen with names and certain other information.")
parser.add_argument("-s", "--sort-by-count", action="store_true")
parser.add_argument("-m", "--minimum-count", type=int, default=0)
parser.add_argument("-p", "--print", action="store_true", help="Print names or evades alongside their representation.")
parser.add_argument("-l", "--live", action="store_true", help="Only use names seen within about a minute.")
parser.add_argument("-e", "--evades", action="store_true", help="Find evading character sequences in use.")
parser.add_argument("-a", "--append-evades", action="store_true", help="Read evades from evade_blacklist.txt and print them alongside those found during this run for easy updating.")
parser.add_argument("-c", "--check", type=str, help="Check if a unicode escape is allowed.")
args = parser.parse_args()


if args.check:
	if not args.check.startswith("\\u"):
		args.check = f"\\u{args.check}"
	args.evades = True


botnames = []
response = requests.get("http://milenko.ml/api/botnames", headers={"User-Agent": "getnames.py/1.0 (https://github.com/incontestableness/GLaDOS)"})
for i in response.json()["response"]["bot_names"]:
	botnames.append([i["name"], i["properties"]["times_seen"], i["properties"]["last_seen"] == "0 minutes ago"])

if args.sort_by_count:
	botnames = sorted(botnames, key = lambda x: x[1])
else:
	botnames.sort()

evades = set()
x = re.compile(r"((\\x[a-z0-9]{2})+)")
u = re.compile(r"((\\u[a-z0-9]{4})+)")

for name, count, live in botnames:
	unicode_escaped = name.encode("unicode-escape").decode()
	re_escaped = re.escape(unicode_escaped)
	fixed = re_escaped.replace("\\\\", "\\")
	formatted = fixed.replace("\\ ", " ")

	if args.live and not live:
		continue
	if count < args.minimum_count:
		continue
	if args.evades:
		for i in ["x", "u"]:
			exec(f"matches = {i}.findall(unicode_escaped)")
			for group in matches:
				assert len(group) == 2
				s = group[0]
				found = False
				# Modified from https://stackoverflow.com/a/29481244
				for j in range(1, len(s) // 2 + 1):
					if not len(s) % len(s[:j]) and s[:j] * (len(s) // len(s[:j])) == s:
						evades.add(s[:j])
						found = True
						break
				if not found:
					evades.add(s)
	elif args.quiet:
		print(formatted)
	elif args.print:
		decoded = name.encode().decode("unicode-escape")
		spacing = " " * ((160 - len(fixed)) - len(decoded))
		print(f"{fixed}{spacing}{decoded}")
	else:
		print(formatted.ljust(80), count)

if args.append_evades:
	file = open("evade_blacklist.txt", "r")
	data = file.read()
	file.close()
	for i in data.split("\n")[:-1]:
		evades.add(i)

# We're going to go through the generated evades and check for certain common characters
evades_copy = copy.copy(evades)
for e in evades_copy:
	decoded = e.encode().decode("unicode-escape")
	latin_1_supplement = (u"\u0080", u"\u00FF")
	latin_extended_a = (u"\u0100", u"\u017F")
	latin_extended_b = (u"\u0180", u"\u024F")
	cryllic = (u"\u0400", u"\u04FF")
	arabic = (u"\u0600", u"\u06FF")
	tibetan = (u"\u0F00", u"\u0FFF")
	#thai = (u"\u0E00", u"\u0E7F")
	phonetic_extensions = (u"\u1D00", u"\u1D7F")
	latin_extended_additional = (u"\u1E00", u"\u1EFF")
	letterlike_symbols = (u"\u2100", u"\u214F")
	miscellaneous_symbols = (u"\u2600", u"\u26FF")
	dingbats = (u"\u2700", u"\u27BF")
	hiragana = (u"\u3040", u"\u309F")
	cjk_unified_ideographs = (u"\u4E00", u"\u9FFF")
	hangul_syllables = (u"\uAC00", u"\uD7AF")
	javanese = (u"\uA980", u"\uA9DF")
	whitelist_1 = (u"\uFFFD", u"\uFFFD")
	allowed = [latin_1_supplement, latin_extended_a, latin_extended_b, cryllic, arabic, tibetan, phonetic_extensions, latin_extended_additional, letterlike_symbols, miscellaneous_symbols, dingbats, hiragana, cjk_unified_ideographs, hangul_syllables, javanese, whitelist_1]
	blacklist = ["\xb2"]
	if args.check:
		decoded = args.check.encode().decode("unicode-escape")
		for index, unicode_range in enumerate(allowed):
			if unicode_range[0] <= decoded <= unicode_range[1] and args.check not in blacklist:
				print(f"{args.check} ({decoded}) is allowed by unicode range index {index}: {unicode_range}.")
				exit()
		print(f"{args.check} is NOT allowed.")
		exit(1)
	all_indexes = list(range(0, len(decoded)))
	good_indexes = set()
	for index, c in enumerate(decoded):
		if c in blacklist:
			break
		for unicode_range in allowed:
			if unicode_range[0] <= c <= unicode_range[1]:
				good_indexes.add(index)
	good_indexes = list(good_indexes)
	for i in all_indexes:
		if i not in good_indexes:
			if not args.quiet: print(f"Bad character ({decoded[i].encode('unicode-escape').decode()}): {decoded[i]}")
	if all_indexes == good_indexes:
		try:
			evades.remove(e)
			if not args.quiet: print(f"Removed {e}")
			continue
		except:
			pass

if args.evades:
	evades = sorted(evades)
	for evade_sequence in evades:
		if not args.print:
			print(evade_sequence)
		else:
			decoded = evade_sequence.encode().decode("unicode-escape")
			spacing = " " * ((160 - len(evade_sequence)) - len(decoded))
			print()
			print("^" * 190)
			print(f"{evade_sequence}{spacing}ABC{decoded}DEF")
			print("$" * 190)
