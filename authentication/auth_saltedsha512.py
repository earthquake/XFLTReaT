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

if "auth_saltedsha512.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import struct
import hashlib
import random

import common
from authentication import Generic_authentication_module

class Authentication_module(Generic_authentication_module.Generic_authentication_module):
	def __init__(self):
		super(Authentication_module, self).__init__()
		self.cmh_struct_authentication  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : [b"XFLT>AUTH!", 		self.authentication_step_1, 1, True, False, True],
			1  : [b"XFLT>AUTH_OK", 		self.authentication_step_2_ok, 0, True, False, False],
			2  : [b"XFLT>AUTH_NOTOK", 	self.authentication_step_2_not_ok, 0, True, False, False]
		}

		self.client_step_count = 1
		self.server_step_count = 1

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

	def send_details(self):
		rnd = struct.pack("<I", random.randint(0, 4294967295))
		m = hashlib.sha512()
		m.update(rnd)
		m.update(self.key.encode('ascii'))
		ciphertext = m.digest()

		return rnd+ciphertext

	def check_details(self, msg):
		rnd = msg[0:4]
		ciphertext = msg[4:68]
		m = hashlib.sha512()
		m.update(rnd)
		m.update(self.key.encode('ascii'))
		if ciphertext == m.digest():
			return True

		return False

	def authentication_init_msg(self):
		return self.cmh_struct_authentication[0][0]+self.send_details()

	# auth: authentication request received, authenticate client
	def authentication_step_1(self, module, message, additional_data, cm):
		if self.check_details(message[len(self.cmh_struct_authentication[0][0]):]):
			if module.post_authentication_server(message[len(self.cmh_struct_authentication[0][0]):], additional_data):
				module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_authentication[1][0], module.modify_additional_data(additional_data, 1))
			else:
				module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_authentication[2][0], module.modify_additional_data(additional_data, 1))
				return module.cmh_struct[cm][4+module.is_caller_stateless()]

			common.internal_print("Client authenticated", 1)

			return module.cmh_struct[cm][3]
		else:
			module.send(common.CONTROL_CHANNEL_BYTE, self.cmh_struct_authentication[2][0], module.modify_additional_data(additional_data, 1))
			common.internal_print("Client authentication failed", -1)

		return module.cmh_struct[cm][4+module.is_caller_stateless()]

	# auth_ok: auth succeded on server, client authenticated
	def authentication_step_2_ok(self, module, message, additional_data, cm):
		module.post_authentication_client(message[len(self.cmh_struct_authentication[1][0]):], additional_data)
		common.internal_print("Authentication succeed for: {0}".format(module.module_name), 1)

		return module.cmh_struct[cm][3]

	# auth_notok: auth failed on server, client exits
	def authentication_step_2_not_ok(self, module, message, additional_data, cm):
		common.internal_print("Authentication failed for: {0}".format(module.module_name), -1)
		module.remove_initiated_client(message, additional_data)

		return module.cmh_struct[cm][4+module.is_caller_stateless()]