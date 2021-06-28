#!/usr/bin/env python3

import configparser
import logging



config = configparser.ConfigParser()
config.read("settings.ini")
logging_settings = config["logging"]

logger = logging.getLogger()
print = logger.info


def logging_enabled(which):
	return logging_settings.getboolean(which)


def scanner_debug(what):
	if logging_enabled("scanner"):
		print(what)


def timeout_debug(what):
	if logging_enabled("timeout"):
		print(what)


def match_debug(what):
	if logging_enabled("match"):
		print(what)


def stripmatch_debug(what):
	if logging_enabled("stripmatch"):
		print(what)


def dupematch_debug(what):
	if logging_enabled("dupematch"):
		print(what)


def recur_debug(what):
	if logging_enabled("recur"):
		print(what)


def striprecur_debug(what):
	if logging_enabled("striprecur"):
		print(what)


def namesteal_debug(what):
	if logging_enabled("namesteal"):
		print(what)


def inject_debug(what):
	if logging_enabled("inject"):
		print(what)


def matchify_debug(what):
	if logging_enabled("matchify"):
		print(what)
