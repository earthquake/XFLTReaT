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

if "Generic_module.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)


import threading

#local files
import common
from packetselector import PacketSelector
from client import Client

class Generic_module(threading.Thread):
	module_name = "Generic module to inherit"
	module_configname = "NONE"
	module_description = """This is a generic module with all the methods to inherit.
	This saves us some bytes and fulfills the joy of oop. Wut?
	"""

	def __init_thread__(self, threadID, config, tunnel, packetselector, auth_module, verbosity):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.config = config
		self.tunnel = tunnel
		self.packetselector = packetselector
		self.auth_module = auth_module
		self.verbosity = verbosity
		self._stop = False

		if not self.os_check():
			common.internal_print("The module '{0}' does not support your operating system.".format(self.get_module_name()), -1)
			return False

		if not self.sanity_check():
			return False

		return True

	def __init__(self):
		self._stop = False
		self.os_type = common.get_os_type()

		return

	# default function to run the server module
	def run(self):
		self.serve()

		return

	# stop thread and exit as soon as possible
	def stop(self):
		self._stop = True

		return

	def os_check(self):
		if (self.module_os_support & self.os_type):
			return True
		else:
			return False

	def serve(self):

		return

	def connect(self):

		return

	def check(self):

		return

	def cleanup(self):

		return

	def get_module_name(self):

		return self.module_name

	def get_module_configname(self):

		return self.module_configname

	def get_module_description(self):

		return self.module_description

	def get_intermediate_hop(self, config):

		return ""