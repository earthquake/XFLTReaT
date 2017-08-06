import sys

if "auth_noauth.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import struct

import common

class Authentication_module():
	def __init__(self):
		return

	def sanity_check(self, config):

		return True

	def send_details(self, clientip, sd):
		client_private_ip = clientip

		return socket.inet_aton(client_private_ip)

	def check_details(self, msg):

		return True
