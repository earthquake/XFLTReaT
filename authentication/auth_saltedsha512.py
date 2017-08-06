import sys

if "auth_noauth.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import struct
import hashlib
import random

import common

class Authentication_module():
	def __init__(self):
		self.key = None
		return

	def sanity_check(self, config):
		if not config.has_option("Authentication", "key"):
			common.internal_print("Please define a 'key' option in the Authentication section", -1)

			return False

		self.key = config.get("Authentication", "key")
		if not len(self.key):
			common.internal_print("The 'key' option's value in the Authentication section is missing", -1)

			return False
		if len(self.key) < 10:
			common.internal_print("The 'key' option's value in the Authentication section is a bit short, it is recommended to make it longer", -1)

		return True

	def send_details(self, clientip):
		client_private_ip = clientip
		rnd = struct.pack("<I", random.randint(0, 4294967295))
		m = hashlib.sha512()
		m.update(rnd)
		m.update(self.key)
		ciphertext = m.digest()

		return socket.inet_aton(client_private_ip)+rnd+ciphertext

	def check_details(self, msg):
		rnd = msg[4:8]
		ciphertext = msg[8:72]
		m = hashlib.sha512()
		m.update(rnd)
		m.update(self.key)
		if ciphertext == m.digest():
			return True

		return False
