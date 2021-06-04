#!/usr/bin/env bash

whois -h whois.radb.net '!gas32590' | awk NR==2 | xargs -n 1 echo | sort -u
