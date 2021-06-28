#!/usr/bin/env python3

from debug import matchify_debug
from string import ascii_letters, digits, punctuation
import re



allowed_chars = ascii_letters + digits + punctuation + " "
dupematch = re.compile("^(\([1-9]\d?\))")
b4pat = re.compile("\\\\u(?=[a-z0-9]{4})")


# Returns an ASCII-only string
def strip_name(name):
	return "".join(filter(lambda x: x in allowed_chars, name))


# Removes the leading (N) from names
def undupe(name):
	return re.sub(dupematch, "", name)


# Return a name suitable for printing
def unevade(name):
	return name.encode("unicode-escape").decode()


# Returns a name_blacklist.txt and ECMAScript regex-compatible version of the name
def matchify(name):
	matchify_debug(f"Name to be matchified: {repr(name)}")

	unicode_escaped = name.encode("unicode-escape").decode()
	matchify_debug(f"Unicode-escaped name: {unicode_escaped}")

	# Fuck you Microsoft, document your shit correctly
	padded = re.sub(b4pat, "\\\\u0000", unicode_escaped)
	matchify_debug(f"Unicode-escaped with padding: {padded}")

	regex_control_escaped = re.escape(padded)
	matchify_debug(f"Regex control escaped: {regex_control_escaped}")

	# Remove unnecessary escaping from re.escape()
	no_backslash_escaping = regex_control_escaped.replace("\\\\", "\\")
	matchify_debug(f"No backslash escaping: {no_backslash_escaping}")
	no_space_escaping = no_backslash_escaping.replace("\\ ", " ")
	matchify_debug(f"No space escaping: {no_space_escaping}")
	no_hyphen_escaping = no_space_escaping.replace("\\-", "-")
	matchify_debug(f"No hyphen escaping: {no_hyphen_escaping}")
	return no_hyphen_escaping
