import sys

if "Generic_module.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)


import threading

#local files
from packetselector import PacketSelector
from client import Client

class Generic_module(threading.Thread):
	module_name = "Generic module to inherit"
	module_configname = "NONE"
	module_description = """This is a generic module with all the methods to inherit.
	This saves us some bytes and fulfill the joy of oop. Wut?
	"""

	def __init_thread__(self, threadID, config, tunnel, packetselector, verbosity):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.config = config
		self.tunnel = tunnel
		self.packetselector = packetselector
		self.verbosity = verbosity
		self._stop = False

		return

	def __init__(self):
		self._stop = False

		return

	# default function to run the server module
	def run(self):
		self.serve()

		return

	# stop thread and exit as soon as possible
	def stop(self):
		self._stop = True

		return

	def serve(self):

		return

	def client(self):

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