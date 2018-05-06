# MIT License

# Copyright (c) 2018 Balazs Bucsay

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
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import os
import os.path
import inspect

import common

class Encryption():
	def __init__(self):

		return

	def load_encryption_module(self, config):
		if not config.has_section("Encryption"):
			module_name = "none"
		else:
			if config.has_option("Encryption", "module"):
				module_name = config.get("Encryption", "module")
			else:
				module_name = "none"

		if not os.path.isfile("encryption/enc_"+module_name+".py"):
			common.internal_print("No such encryption module: enc_{0}.py".format(module_name), -1)
			sys.exit(-1)

		imports = __import__("encryption.enc_"+module_name, locals(), globals())
		module_reference = getattr(imports, "enc_"+module_name)
		module = module_reference.Encryption_module()

		return module

class Encryption_details():
	def __init__(self):
		# by default it is false, it is set to true when key was agreed
		self.encrypted = False
		self.encryption_module = None

		# optional properties depends on the module
		self.shared_key = None
		self.public_key = None
		self.private_key = None

		return

	def set_encrypted(self, bool):
		self.encrypted = bool
		return

	def get_encrypted(self):
		return self.encrypted

	def set_module(self, module):
		self.encryption_module = module
		return

	def get_module(self):
		return self.encryption_module

	def set_shared_key(self, key):
		self.shared_key = key
		return

	def get_shared_key(self):
		return self.shared_key

	def set_public_key(self, key):
		self.public_key = key
		return

	def get_public_key(self):
		return self.public_key

	def set_private_key(self, key):
		self.private_key = key
		return

	def get_private_key(self):
		return self.private_key

