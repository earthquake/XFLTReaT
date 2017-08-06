import sys

if "__init__.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import os
import os.path
import inspect

import common

class Authentication():
	def __init__(self):

		return

	def load_auth_module(self, config):
		if not config.has_section("Authentication"):
			module_name = "noauth"
		else:
			if config.has_option("Authentication", "module"):
				module_name = config.get("Authentication", "module")
			else:
				module_name = "noauth"

		if not os.path.isfile("authentication/auth_"+module_name+".py"):
			common.internal_print("No such authentication module: auth_{0}.py".format(module_name), -1)
			sys.exit(-1)

		imports = __import__("authentication.auth_"+module_name, locals(), globals())
		module_reference = getattr(imports, "auth_"+module_name)
		module = module_reference.Authentication_module()

		return module