#!/usr/bin/env python3

import os
import sys


print("Hello, world!")

# We need to chdir and update our python path when running as a WSGI application
if __name__ != "__main__":
	# Get full path to GLaDOS
	runtime = os.path.expanduser("~/GLaDOS")
	# GLaDOS uses relative paths for file operations
	os.chdir(runtime)
	# Python needs to know where to look for GLaDOS modules
	sys.path.insert(0, runtime)
	# and where to look for Python libraries installed via pip by the local user
	site_packages = os.path.expanduser(f"~/.local/lib/python3.{sys.version_info.minor}/site-packages/")
	sys.path.insert(0, site_packages)

# Now we can load GLaDOS
from GLaDOS import api as application

# If we're not being run as a WSGI application, start the GLaDOS API server in the main thread
if __name__ == "__main__":
	print("WARNING: Listening on all available interfaces!")
	application.run(host="0.0.0.0", port=8000)
