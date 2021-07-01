#!/usr/bin/env python3

import configparser
import logging



class LogController:
	def __init__(self):
		self.reload_settings()

	def reload_settings(self):
		config = configparser.ConfigParser()
		config.read("settings.ini")
		self.logging_settings = config["logging"]

	def enabled(self, which):
		return self.logging_settings.getboolean(which)


lc = LogController()
logger = logging.getLogger()
print = logger.info


def scanner_debug(what):
	if lc.enabled("scanner"):
		print(what)


def timeout_debug(what):
	if lc.enabled("timeout"):
		print(what)


def match_debug(what):
	if lc.enabled("match"):
		print(what)


def stripmatch_debug(what):
	if lc.enabled("stripmatch"):
		print(what)


def dupematch_debug(what):
	if lc.enabled("dupematch"):
		print(what)


def recur_debug(what):
	if lc.enabled("recur"):
		print(what)


def striprecur_debug(what):
	if lc.enabled("striprecur"):
		print(what)


def namesteal_debug(what):
	if lc.enabled("namesteal"):
		print(what)


def inject_debug(what):
	if lc.enabled("inject"):
		print(what)


def matchify_debug(what):
	if lc.enabled("matchify"):
		print(what)
