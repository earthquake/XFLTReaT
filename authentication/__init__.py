# MIT License

# Copyright (c) 2017 Balazs Bucsay

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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